export const HOST = "https://execution-guard.19wolf-alone92.workers.dev";
export const RESOURCE = HOST + "/mcp-private";
export const PREVIEW_HOST = "https://audit-oauth-e2e-20261125-execution-guard.19wolf-alone92.workers.dev";
// Never derive an OAuth issuer from Host/forwarded headers.
export function authHost(env) {
  return env?.EG_ENVIRONMENT === "preview" ? PREVIEW_HOST : HOST;
}
export const READ = "eg:read";
export const WRITE = "eg:write";
export const CLIENT = "https://chatgpt.com/oauth/client.json";
export function configured(env) {
  return (!env?.EG_ENVIRONMENT || env.EG_ENVIRONMENT==="production" || (env.EG_ENVIRONMENT==="preview" && env.EG_PREVIEW_READY==="true")) && env?.EG_AUTH_ENABLED === "true" && /^\d+$/.test(env.EG_OWNER_GITHUB_ID || "") &&
    Boolean(env.OAUTH_KV && env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET && env.DB);
}
// A configuration flag alone cannot establish storage isolation. Separate
// test resources must carry both markers before any private Preview operation.
export async function previewStorageReady(env) {
  if(env?.EG_ENVIRONMENT!=="preview"||!configured(env))return false;
  try {
    const [d,k]=await Promise.all([env.DB.prepare("SELECT value FROM eg_preview_identity WHERE id=1").first(),env.OAUTH_KV.get("eg:preview:identity")]);
    return d?.value==="execution-guard-preview-v1"&&k==="execution-guard-preview-v1";
  } catch {return false;}
}
export function isOwner(env, ctx) {
  return configured(env) && typeof ctx?.props?.userId === "string" &&
    ctx.props.userId === env.EG_OWNER_GITHUB_ID && Array.isArray(ctx?.auth?.scope);
}
export function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}
export function consentHtml(details, handle) {
  const e = escapeHtml;
  return '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Execution Guard consent</title><h1>Execution Guard</h1><p>Client: '+e(details.clientName)+'</p><p>Verified domain: '+e(details.clientDomain || 'not verified')+'</p><p>Redirect host: '+e(details.redirectHost)+'</p><p>Scopes: '+e(details.scope.join(', '))+'</p><p>Sign in with the configured GitHub owner. Read and write project checkpoints and bounded diagnostic tasks; no repository access is requested.</p><form method="post"><input type="hidden" name="handle" value="'+e(handle)+'"><button name="decision" value="approve">Continue to GitHub</button><button name="decision" value="deny">Deny</button></form></html>';
}
export async function s256(value) {
  const digest = await crypto.subtle.digest("SHA-256",new TextEncoder().encode(value));
  return btoa(String.fromCharCode(...new Uint8Array(digest))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}
export async function oauthDiagnostics(env, provider, ctx) {
  if (!configured(env)) return {configuration:env?.EG_AUTH_ENABLED==="true"?"incomplete":"disabled",discovery:"not_ready"};
  try {
    const host=authHost(env),resourceUrl=host+"/mcp-private";
    const paths=["/.well-known/oauth-protected-resource/mcp-private","/.well-known/oauth-authorization-server"];
    const [resource,issuer]=await Promise.all(paths.map(p=>provider.fetch(new Request(host+p),env,ctx)));
    const result={configuration:"ready",resource_http:resource.status,issuer_http:issuer.status,discovery:"invalid"};
    if(resource.ok&&issuer.ok){
      const [r,a]=await Promise.all([resource.json(),issuer.json()]);
      result.discovery=r.resource===resourceUrl&&r.authorization_servers?.includes(a.issuer)&&a.issuer===host&&a.authorization_endpoint===host+"/authorize"&&a.token_endpoint===host+"/oauth/token"&&a.code_challenge_methods_supported?.includes("S256")&&a.client_id_metadata_document_supported===true?"verified":"invalid_metadata";
    }
    return result;
  } catch {return {configuration:"ready",discovery:"provider_error"};}
}
export function gatewayRoute(publicWorker, provider) {
  return {async fetch(request,env,ctx) {
    const url = new URL(request.url);
    if (["/","/health","/mcp"].includes(url.pathname)) {
      const production=url.origin===HOST&&env?.EG_ENVIRONMENT!=="preview";
      const isolated=url.origin===PREVIEW_HOST&&await previewStorageReady(env);
      if(production||isolated)return publicWorker.fetch(request,env,ctx,()=>oauthDiagnostics(env,provider,ctx));
      // Cloudflare can supply unexpected bindings from Previews Base. Do not
      // read them, even for health. Report their presence, not their contents.
      const safe={EG_AUTH_ENABLED:"false",EG_STORAGE_GUARD:{state:"blocked",d1_binding_present:Boolean(env?.DB),kv_binding_present:Boolean(env?.OAUTH_KV)}};
      return publicWorker.fetch(request,safe,ctx,()=>oauthDiagnostics(safe,provider,ctx));
    }
    if (url.pathname === "/mcp-private" || url.pathname === "/authorize" || url.pathname === "/callback" || url.pathname === "/oauth/token" || url.pathname.startsWith("/.well-known/")) {
      if (url.origin !== authHost(env)) return new Response("Unknown host",{status:404});
      if (!configured(env)||(env.EG_ENVIRONMENT==="preview"&&!await previewStorageReady(env))) return new Response("Private access not configured",{status:503,headers:{"Cache-Control":"no-store"}});
      return provider.fetch(request,env,ctx);
    }
    return new Response("Not found",{status:404});
  }};
}
