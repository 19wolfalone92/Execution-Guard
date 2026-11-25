import { timingSafeEqual, createHash } from "node:crypto";
import { OAuthProvider, AuthorizationError, CimdFetchError, getOAuthApi } from "@cloudflare/workers-oauth-provider";
import publicWorker from "./worker.mjs";
import { HOST, RESOURCE, PREVIEW_HOST, authHost, READ, WRITE, CLIENT, consentHtml, s256, gatewayRoute, configured, previewStorageReady } from "./security.mjs";
import { privateFetch } from "./private.mjs";
import { runBatch } from "./tasks.mjs";

const callbackUrl=env=>authHost(env)+"/callback";
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
const githubTokenEndpoint="https://github.com/login/oauth/access_token";
const knownGithubErrors=new Set(["incorrect_client_credentials","redirect_uri_mismatch","bad_verification_code","unverified_user_email","invalid_grant","invalid_request","invalid_client","bad_code_verifier","access_denied"]);
async function exchangeGithubCode(env,code,verifier,fetcher=fetch) {
  if(typeof verifier!=="string"||!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier))return {error:"invalid_saved_verifier"};
  if(typeof env.GITHUB_CLIENT_ID!=="string"||!env.GITHUB_CLIENT_ID.trim()||typeof env.GITHUB_CLIENT_SECRET!=="string"||!env.GITHUB_CLIENT_SECRET.trim())return {error:"missing_client_configuration"};
  const body=new URLSearchParams({client_id:env.GITHUB_CLIENT_ID.trim(),client_secret:env.GITHUB_CLIENT_SECRET.trim(),code,code_verifier:verifier,redirect_uri:callbackUrl(env)});
  let response;
  try {
    response=await fetcher(githubTokenEndpoint,{method:"POST",redirect:"manual",headers:{Accept:"application/json","Content-Type":"application/x-www-form-urlencoded","User-Agent":"Execution-Guard"},body:body.toString(),signal:AbortSignal.timeout(15000)});
  } catch(error) {
    return {error:error?.name==="TimeoutError"||error?.name==="AbortError"?"network_timeout":"network_failure"};
  }
  if(response.status>=300&&response.status<400)return {error:"unexpected_redirect"};
  let payload;
  try {payload=await response.json();} catch {return {error:"non_json_http_"+response.status};}
  if(typeof payload?.error==="string")return {error:knownGithubErrors.has(payload.error)?payload.error:"github_rejected_http_"+response.status};
  if(!response.ok)return {error:"http_"+response.status};
  if(typeof payload?.access_token!=="string"||!payload.access_token||typeof payload.token_type!=="string"||payload.token_type.toLowerCase()!=="bearer")return {error:"invalid_token_response"};
  return {accessToken:payload.access_token};
}
// Fetch only GitHub's fixed identity endpoint. Never forward a bearer token on redirect.
async function lookupGithubOwner(accessToken,ownerId,fetcher=fetch) {
  if(typeof accessToken!=="string"||!accessToken||/[\r\n]/.test(accessToken))return {error:"invalid_token"};
  if(typeof ownerId!=="string"||!/^\d+$/.test(ownerId))return {error:"invalid_owner_configuration"};
  let response;
  try {
    response=await fetcher("https://api.github.com/user",{method:"GET",redirect:"manual",headers:{Authorization:"Bearer "+accessToken,"User-Agent":"Execution-Guard",Accept:"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28"},signal:AbortSignal.timeout(15000)});
  } catch(error) {
    return {error:error?.name==="TimeoutError"||error?.name==="AbortError"?"network_timeout":"network_failure"};
  }
  if(response.status>=300&&response.status<400)return {error:"unexpected_redirect"};
  if(!response.ok)return {error:"http_"+response.status};
  let user;
  try {user=await response.json();} catch {return {error:"invalid_json"};}
  if(!user||!Number.isSafeInteger(user.id)||user.id<=0)return {error:"invalid_identity_response"};
  if(String(user.id)!==ownerId)return {error:"owner_required"};
  return {userId:String(user.id)};
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
      for(const [key,value] of Object.entries({client_id:env.GITHUB_CLIENT_ID,redirect_uri:callbackUrl(env),scope:"read:user",state,code_challenge:await s256(verifier),code_challenge_method:"S256"}))url.searchParams.set(key,value);
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
      const exchange=await exchangeGithubCode(env,code,data?.verifier);
      if(exchange.error){
        console.warn(JSON.stringify({event:"oauth_authorization_failed",stage,category:exchange.error}));
        headers.set("Content-Type","text/plain; charset=utf-8");
        return new Response("Authorization failed ("+stage+" / "+exchange.error+")",{status:502,headers});
      }
      const access_token=exchange.accessToken;
      stage="github_user_lookup";
      const identity=await lookupGithubOwner(access_token,env.EG_OWNER_GITHUB_ID);
      if(identity.error){
        console.warn(JSON.stringify({event:"oauth_authorization_failed",stage,category:identity.error}));
        headers.set("Content-Type","text/plain; charset=utf-8");
        return new Response("Authorization failed ("+stage+" / "+identity.error+")",{status:identity.error==="owner_required"?403:502,headers});
      }
      stage="complete_authorization";
      const {redirectTo}=await oauth.completeAuthorization({request:original,userId:identity.userId,metadata:{},scope:original.scope,props:{userId:identity.userId}});
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
const previewOptions={...providerOptions,resourceMetadata:{resource:PREVIEW_HOST+"/mcp-private",authorization_servers:[PREVIEW_HOST]}};
const previewProvider=new OAuthProvider(previewOptions);
const gateway=gatewayRoute(publicWorker,provider);
const previewGateway=gatewayRoute(publicWorker,previewProvider);
export default {...gateway,async fetch(request,env,ctx){
  const url=new URL(request.url);
  // Previews have no platform Cron. A bounded test-only tick is guarded by
  // exact stable preview origin, explicit environment opt-in and a separate secret.
  if(url.pathname==="/qualification/tick"){
    if(env.EG_ENVIRONMENT!=="preview"||url.origin!==PREVIEW_HOST||!configured(env))return new Response("Not found",{status:404});
    if(request.method!=="POST")return new Response(null,{status:405});
    const secret=env.EG_PREVIEW_TICK_SECRET,provided=request.headers.get("Authorization")||"";
    if(typeof secret!=="string"||secret.length<32||provided.length>512||!timingSafeEqual(createHash("sha256").update(provided).digest(),createHash("sha256").update("Bearer "+secret).digest()))return new Response("Forbidden",{status:403});
    if(!await previewStorageReady(env))return new Response("Preview storage not qualified",{status:503});
    await provisionRegisteredClient(env,getOAuthApi(previewOptions,env));
    await runBatch(env.DB,env.EG_OWNER_GITHUB_ID);
    return Response.json({status:"tick_completed",environment:"preview"},{headers:{"Cache-Control":"no-store"}});
  }
  if(url.pathname==="/oauth/client-info"){
    if(url.origin!==authHost(env))return new Response("Unknown host",{status:404});
    if(request.method!=="GET")return new Response(null,{status:405});
    if(!configured(env)||(env.EG_ENVIRONMENT==="preview"&&!await previewStorageReady(env)))return new Response("Private access not configured",{status:503});
    const id=await registeredId(env);
    return new Response(JSON.stringify(id?{status:"ready",client_id:id,redirect_uri:chatgptRedirect,token_endpoint_auth_method:"none"}:{status:"pending"}),{status:id?200:503,headers:{"Content-Type":"application/json","Cache-Control":"no-store"}});
  }
  return (env.EG_ENVIRONMENT==="preview"?previewGateway:gateway).fetch(request,env,ctx);
},async scheduled(_event,env,ctx){
  if(env.EG_ENVIRONMENT!=="preview"&&configured(env)){
    ctx.waitUntil(runBatch(env.DB,env.EG_OWNER_GITHUB_ID));
    ctx.waitUntil((async()=>{try{await provisionRegisteredClient(env,getOAuthApi(providerOptions,env));}catch{console.warn("oauth_registered_client_provision_failed");}})());
  }
}};
