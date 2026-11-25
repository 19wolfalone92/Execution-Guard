import { OAuthProvider, AuthorizationError, CimdFetchError, getOAuthApi } from "@cloudflare/workers-oauth-provider";
import publicWorker from "./worker.mjs";
import { HOST, RESOURCE, READ, WRITE, CLIENT, consentHtml, s256, gatewayRoute, configured } from "./security.mjs";
import { privateFetch } from "./private.mjs";
import { runBatch } from "./tasks.mjs";

const callbackUrl=HOST+"/callback";
const chatgptRedirect="https://chatgpt.com/connector_platform_oauth_redirect";
const registeredKey="eg:chatgpt:registered-client:v1";
// Public-client ID only. No credentials are stored here or returned to the browser.
async function registeredId(env) {
  return await env.OAUTH_KV.get(registeredKey);
}
async function approvedClient(env,id) {
  return id===CLIENT || (typeof id==="string" && id.length>0 && id===await registeredId(env));
}
// Provision once from the trusted scheduled handler, never from a public request.
async function provisionRegisteredClient(env,oauth) {
  const existing=await registeredId(env);
  if(existing) {
    const client=await oauth.lookupClient(existing);
    if(!client || client.tokenEndpointAuthMethod!=="none" || client.redirectUris?.length!==1 || client.redirectUris[0]!==chatgptRedirect) throw new Error("Registered OAuth client requires administrator review");
    return existing;
  }
  const client=await oauth.createClient({clientName:"ChatGPT (Execution Guard)",redirectUris:[chatgptRedirect],tokenEndpointAuthMethod:"none",grantTypes:["authorization_code","refresh_token"],responseTypes:["code"]});
  if(!client.clientId || client.clientSecret)throw new Error("Unexpected registered client");
  await env.OAUTH_KV.put(registeredKey,client.clientId);
  return client.clientId;
}
function metadataCategory(error) {
  const d=typeof error.detail==="string"?error.detail:"";
  const status=/^Failed to fetch client metadata: HTTP ([1-5][0-9]{2})\b/.exec(d);
  return status?"client_metadata_http_"+status[1]:"client_metadata";
}
// Match only fixed library messages (workers-oauth-provider 1.3.0).
// Never echo a raw exception, state, cookie, token or callback URL.
function authorizationCategory(error,stage) {
  if(stage!=="finish_github_sign_in"&&stage!=="approve_consent"&&stage!=="deny_consent")return "request_rejected";
  switch(error.description) {
    case "Missing state parameter": return "missing_state";
    case "Missing transaction handle": return "missing_handle";
    case "This authorization was not started in this browser; start again": return "browser_cookie_missing";
    case "This authorization belongs to a different browser session; start again": return "browser_session_mismatch";
    case "This authorization expired or was already used; start again": return "transaction_unavailable";
    default: return "request_rejected";
  }
}
const defaultHandler={async fetch(request,env) {
  const path=new URL(request.url).pathname;
  const oauth=env.OAUTH_PROVIDER;
  let stage="route";
  try {
    if(path==="/authorize"){
      if(request.method==="GET"){
        if(!await approvedClient(env,new URL(request.url).searchParams.get("client_id")))return new Response("Client forbidden",{status:403});
        stage="parse_request";
        const parsed=await oauth.parseAuthRequest(request);
        if(!await approvedClient(env,parsed.clientId))return new Response("Only the approved ChatGPT client is allowed",{status:403});
        stage="describe_consent";
        const details=await oauth.describeConsent(parsed);
        stage="begin_consent";
        const consent=await oauth.beginConsent(parsed);
        stage="render_consent";
        consent.headers.set("Content-Type","text/html; charset=utf-8");
        return new Response(consentHtml(details,consent.handle),{headers:consent.headers});
      }
      if(request.method!=="POST")return new Response(null,{status:405});
      stage="read_consent_form";
      const form=await request.formData(),handle=String(form.get("handle")||"");
      stage="deny_consent";
      if(form.get("decision")!=="approve"){const denied=await oauth.denyConsent(request,handle);return new Response(null,{status:302,headers:denied.headers});}
      stage="approve_consent";
      const approved=await oauth.approveConsent(request,handle);
      if(!await approvedClient(env,approved.request.clientId))return new Response("Client forbidden",{status:403});
      const verifier=crypto.randomUUID()+crypto.randomUUID();
      stage="begin_github_sign_in";
      const {state,headers}=await oauth.beginUpstream(approved.request,{data:{verifier},headers:approved.headers});
      const url=new URL("https://github.com/login/oauth/authorize");
      for(const [key,value] of Object.entries({client_id:env.GITHUB_CLIENT_ID,redirect_uri:callbackUrl,scope:"read:user",state,code_challenge:await s256(verifier),code_challenge_method:"S256"}))url.searchParams.set(key,value);
      headers.set("Location",url.toString());
      // Explicitly turn the consent POST into a top-level GET at GitHub.
      return new Response(null,{status:303,headers});
    }
    if(path==="/callback"&&request.method==="GET"){
      stage="finish_github_sign_in";
      const {request:original,data,headers}=await oauth.finishUpstream(request);
      const params=new URL(request.url).searchParams;
      const code=params.get("code");
      if(!await approvedClient(env,original.clientId))return new Response("Client forbidden",{status:403,headers});
      if(!code){
        const reason=params.get("error")==="access_denied"?"github_access_denied":params.has("error")?"github_rejected":"missing_code";
        headers.set("Content-Type","text/plain; charset=utf-8");
        return new Response("Authorization failed (github_callback / "+reason+")",{status:400,headers});
      }
      stage="github_token_exchange";
      const token=await fetch("https://github.com/login/oauth/access_token",{method:"POST",redirect:"error",headers:{Accept:"application/json","Content-Type":"application/json"},body:JSON.stringify({client_id:env.GITHUB_CLIENT_ID,client_secret:env.GITHUB_CLIENT_SECRET,code,code_verifier:data.verifier,redirect_uri:callbackUrl})});
      if(!token.ok)return new Response("Sign in failed",{status:403,headers});
      const {access_token}=await token.json();
      if(typeof access_token!=="string"||!access_token)return new Response("Sign in failed",{status:403,headers});
      stage="github_user_lookup";
      const response=await fetch("https://api.github.com/user",{redirect:"error",headers:{Authorization:"Bearer "+access_token,"User-Agent":"Execution-Guard",Accept:"application/vnd.github+json"}});
      if(!response.ok)return new Response("Sign in failed",{status:403,headers});
      const user=await response.json();
      if(String(user.id)!==env.EG_OWNER_GITHUB_ID)return new Response("Owner required",{status:403,headers});
      stage="complete_authorization";
      const {redirectTo}=await oauth.completeAuthorization({request:original,userId:String(user.id),metadata:{},scope:original.scope,props:{userId:String(user.id)}});
      headers.set("Location",redirectTo);
      return new Response(null,{status:302,headers});
    }
    return new Response("Not found",{status:404});
  }catch(error){
    // Fixed diagnostic categories only; never log URLs, OAuth state, codes, secrets or raw exceptions.
    const category=error instanceof CimdFetchError?metadataCategory(error):error instanceof AuthorizationError?authorizationCategory(error,stage):"internal";
    console.warn(JSON.stringify({event:"oauth_authorization_failed",stage,category}));
    if(error instanceof AuthorizationError && error.redirectTo)return Response.redirect(error.redirectTo,302);
    return new Response("Authorization failed ("+stage+" / "+category+")",{status:400,headers:{"Cache-Control":"no-store","Content-Type":"text/plain; charset=utf-8"}});
  }
}};
const providerOptions={apiRoute:"/mcp-private",apiHandler:{fetch:privateFetch},defaultHandler,authorizeEndpoint:"/authorize",tokenEndpoint:"/oauth/token",scopesSupported:[READ,WRITE],requiredScopes:[READ],resourceMetadata:{resource:RESOURCE,authorization_servers:[HOST]},clientIdMetadataDocumentEnabled:true};
const provider=new OAuthProvider(providerOptions);
const gateway=gatewayRoute(publicWorker,provider);
export default {...gateway,async fetch(request,env,ctx){
  const url=new URL(request.url);
  if(url.pathname==="/oauth/client-info"){
    if(url.origin!==HOST)return new Response("Unknown host",{status:404});
    if(request.method!=="GET")return new Response(null,{status:405});
    if(!configured(env))return new Response("Private access not configured",{status:503});
    const id=await registeredId(env);
    return new Response(JSON.stringify(id?{status:"ready",client_id:id,redirect_uri:chatgptRedirect,token_endpoint_auth_method:"none"}:{status:"pending"}),{status:id?200:503,headers:{"Content-Type":"application/json","Cache-Control":"no-store"}});
  }
  return gateway.fetch(request,env,ctx);
},async scheduled(_event,env,ctx){
  if(configured(env)){
    ctx.waitUntil(runBatch(env.DB,env.EG_OWNER_GITHUB_ID));
    ctx.waitUntil((async()=>{try{await provisionRegisteredClient(env,getOAuthApi(providerOptions,env));}catch{console.warn("oauth_registered_client_provision_failed");}})());
  }
}};
