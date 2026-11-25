export const HOST = "https://execution-guard.19wolf-alone92.workers.dev";
export const RESOURCE = HOST + "/mcp-private";
export const READ = "eg:read";
export const WRITE = "eg:write";
export const CLIENT = "https://chatgpt.com/oauth/client.json";
export function configured(env) {
  return env?.EG_AUTH_ENABLED === "true" && /^\d+$/.test(env.EG_OWNER_GITHUB_ID || "") &&
    Boolean(env.OAUTH_KV && env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET && env.DB);
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
  return '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Execution Guard consent</title><h1>Execution Guard</h1><p>Client: '+e(details.clientName)+'</p><p>Verified domain: '+e(details.clientDomain || 'not verified')+'</p><p>Redirect host: '+e(details.redirectHost)+'</p><p>Scopes: '+e(details.scope.join(', '))+'</p><p>Sign in with the configured GitHub owner. Read and write project checkpoints only; no repository access is requested.</p><form method="post"><input type="hidden" name="handle" value="'+e(handle)+'"><button name="decision" value="approve">Continue to GitHub</button><button name="decision" value="deny">Deny</button></form></html>';
}
export async function s256(value) {
  const digest = await crypto.subtle.digest("SHA-256",new TextEncoder().encode(value));
  return btoa(String.fromCharCode(...new Uint8Array(digest))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}
export function gatewayRoute(publicWorker, provider) {
  return {async fetch(request,env,ctx) {
    const url = new URL(request.url);
    if (["/","/health","/mcp"].includes(url.pathname)) return publicWorker.fetch(request,env,ctx);
    if (url.pathname === "/mcp-private" || url.pathname === "/authorize" || url.pathname === "/callback" || url.pathname === "/oauth/token" || url.pathname.startsWith("/.well-known/")) {
      if (url.origin !== HOST) return new Response("Unknown host",{status:404});
      if (!configured(env)) return new Response("Private access not configured",{status:503,headers:{"Cache-Control":"no-store"}});
      return provider.fetch(request,env,ctx);
    }
    return new Response("Not found",{status:404});
  }};
}
