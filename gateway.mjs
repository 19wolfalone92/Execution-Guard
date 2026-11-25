import { OAuthProvider, AuthorizationError } from "@cloudflare/workers-oauth-provider";
import publicWorker from "./worker.mjs";
import { HOST, RESOURCE, READ, WRITE, CLIENT, consentHtml, s256, gatewayRoute } from "./security.mjs";
import { privateFetch } from "./private.mjs";

const callbackUrl=HOST+"/callback";
const defaultHandler={async fetch(request,env) {
  const path=new URL(request.url).pathname;
  const oauth=env.OAUTH_PROVIDER;
  try {
    if(path==="/authorize"){
      if(request.method==="GET"){
        const parsed=await oauth.parseAuthRequest(request);
        if(parsed.clientId!==CLIENT)return new Response("Only the approved ChatGPT client is allowed",{status:403});
        const details=await oauth.describeConsent(parsed);
        const consent=await oauth.beginConsent(parsed);
        consent.headers.set("Content-Type","text/html; charset=utf-8");
        return new Response(consentHtml(details,consent.handle),{headers:consent.headers});
      }
      if(request.method!=="POST")return new Response(null,{status:405});
      const form=await request.formData(),handle=String(form.get("handle")||"");
      if(form.get("decision")!=="approve"){const denied=await oauth.denyConsent(request,handle);return new Response(null,{status:302,headers:denied.headers});}
      const approved=await oauth.approveConsent(request,handle);
      if(approved.request.clientId!==CLIENT)return new Response("Client forbidden",{status:403});
      const verifier=crypto.randomUUID()+crypto.randomUUID();
      const {state,headers}=await oauth.beginUpstream(approved.request,{data:{verifier},headers:approved.headers});
      const url=new URL("https://github.com/login/oauth/authorize");
      for(const [key,value] of Object.entries({client_id:env.GITHUB_CLIENT_ID,redirect_uri:callbackUrl,scope:"read:user",state,code_challenge:await s256(verifier),code_challenge_method:"S256"}))url.searchParams.set(key,value);
      headers.set("Location",url.toString());
      return new Response(null,{status:302,headers});
    }
    if(path==="/callback"&&request.method==="GET"){
      const {request:original,data,headers}=await oauth.finishUpstream(request);
      const code=new URL(request.url).searchParams.get("code");
      if(!code||original.clientId!==CLIENT)return new Response("Sign in not completed",{status:400,headers});
      const token=await fetch("https://github.com/login/oauth/access_token",{method:"POST",redirect:"error",headers:{Accept:"application/json","Content-Type":"application/json"},body:JSON.stringify({client_id:env.GITHUB_CLIENT_ID,client_secret:env.GITHUB_CLIENT_SECRET,code,code_verifier:data.verifier,redirect_uri:callbackUrl})});
      if(!token.ok)return new Response("Sign in failed",{status:403,headers});
      const {access_token}=await token.json();
      if(typeof access_token!=="string"||!access_token)return new Response("Sign in failed",{status:403,headers});
      const response=await fetch("https://api.github.com/user",{redirect:"error",headers:{Authorization:"Bearer "+access_token,"User-Agent":"Execution-Guard",Accept:"application/vnd.github+json"}});
      if(!response.ok)return new Response("Sign in failed",{status:403,headers});
      const user=await response.json();
      if(String(user.id)!==env.EG_OWNER_GITHUB_ID)return new Response("Owner required",{status:403,headers});
      const {redirectTo}=await oauth.completeAuthorization({request:original,userId:String(user.id),metadata:{},scope:original.scope,props:{userId:String(user.id)}});
      headers.set("Location",redirectTo);
      return new Response(null,{status:302,headers});
    }
    return new Response("Not found",{status:404});
  }catch(error){
    if(error instanceof AuthorizationError && error.redirectTo)return Response.redirect(error.redirectTo,302);
    return new Response("Authorization failed",{status:400,headers:{"Cache-Control":"no-store"}});
  }
}};
const provider=new OAuthProvider({apiRoute:"/mcp-private",apiHandler:{fetch:privateFetch},defaultHandler,authorizeEndpoint:"/authorize",tokenEndpoint:"/oauth/token",scopesSupported:[READ,WRITE],requiredScopes:[READ],resourceMetadata:{resource:RESOURCE,authorization_servers:[HOST]},clientIdMetadataDocumentEnabled:true});
export default gatewayRoute(publicWorker,provider);
