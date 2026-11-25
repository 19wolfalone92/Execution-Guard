import { OAuthProvider, AuthorizationError, CimdFetchError } from "@cloudflare/workers-oauth-provider";
import publicWorker from "./worker.mjs";
import { HOST, RESOURCE, READ, WRITE, CLIENT, consentHtml, s256, gatewayRoute, configured } from "./security.mjs";
import { privateFetch } from "./private.mjs";
import { runBatch } from "./tasks.mjs";

const callbackUrl=HOST+"/callback";
const defaultHandler={async fetch(request,env) {
  const path=new URL(request.url).pathname;
  const oauth=env.OAUTH_PROVIDER;
  let stage="route";
  try {
    if(path==="/authorize"){
      if(request.method==="GET"){
        if(new URL(request.url).searchParams.get("client_id")!==CLIENT)return new Response("Client forbidden",{status:403});
        stage="parse_request";
        const parsed=await oauth.parseAuthRequest(request);
        if(parsed.clientId!==CLIENT)return new Response("Only the approved ChatGPT client is allowed",{status:403});
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
      if(approved.request.clientId!==CLIENT)return new Response("Client forbidden",{status:403});
      const verifier=crypto.randomUUID()+crypto.randomUUID();
      stage="begin_github_sign_in";
      const {state,headers}=await oauth.beginUpstream(approved.request,{data:{verifier},headers:approved.headers});
      const url=new URL("https://github.com/login/oauth/authorize");
      for(const [key,value] of Object.entries({client_id:env.GITHUB_CLIENT_ID,redirect_uri:callbackUrl,scope:"read:user",state,code_challenge:await s256(verifier),code_challenge_method:"S256"}))url.searchParams.set(key,value);
      headers.set("Location",url.toString());
      return new Response(null,{status:302,headers});
    }
    if(path==="/callback"&&request.method==="GET"){
      stage="finish_github_sign_in";
      const {request:original,data,headers}=await oauth.finishUpstream(request);
      const code=new URL(request.url).searchParams.get("code");
      if(!code||original.clientId!==CLIENT)return new Response("Sign in not completed",{status:400,headers});
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
    const category=error instanceof CimdFetchError?"client_metadata":error instanceof AuthorizationError?"request_rejected":"internal";
    console.warn(JSON.stringify({event:"oauth_authorization_failed",stage,category}));
    if(error instanceof AuthorizationError && error.redirectTo)return Response.redirect(error.redirectTo,302);
    return new Response("Authorization failed ("+stage+" / "+category+")",{status:400,headers:{"Cache-Control":"no-store","Content-Type":"text/plain; charset=utf-8"}});
  }
}};
const provider=new OAuthProvider({apiRoute:"/mcp-private",apiHandler:{fetch:privateFetch},defaultHandler,authorizeEndpoint:"/authorize",tokenEndpoint:"/oauth/token",scopesSupported:[READ,WRITE],requiredScopes:[READ],resourceMetadata:{resource:RESOURCE,authorization_servers:[HOST]},clientIdMetadataDocumentEnabled:true});
const gateway=gatewayRoute(publicWorker,provider);
export default {...gateway,async scheduled(_event,env,ctx){
  if(configured(env))ctx.waitUntil(runBatch(env.DB,env.EG_OWNER_GITHUB_ID));
}};
