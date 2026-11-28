const VERSION = "0.6.0";
async function status(env, diagnose) {
  let database = "not_verified";
  let persistence_probe = "not_verified";
  if (env?.DB) {
    try {
      const row = await env.DB.prepare("SELECT 1 AS ok").first();
      if (row?.ok === 1) {
        database = "online";
        try {
          const probe = await env.DB.prepare("SELECT value FROM eg_probe WHERE id = 1").first();
          if (probe?.value === "execution-guard-v030") persistence_probe = "verified";
        } catch { /* Schema or probe unavailable. */ }
      }
    } catch { /* Do not expose internal database errors. */ }
  }
  return {
    service: "Execution Guard",
    version: VERSION,
    status: "online",
    database,
    persistence_probe,
    oauth_storage: typeof env?.OAUTH_KV?.get === "function" ? "bound" : "not_bound",
    ...(env?.EG_STORAGE_GUARD ? {storage_guard:env.EG_STORAGE_GUARD} : {}),
    ...(diagnose ? {oauth:await diagnose()} : {}),
    timestamp: new Date().toISOString()
  };
}
export default {
  async fetch(request, env, ctx, diagnose) {
    const url = new URL(request.url);
    if (url.pathname === "/" || url.pathname === "/health") return Response.json(await status(env, diagnose));
    if (url.pathname !== "/mcp") return new Response("Not found", { status: 404 });
    const origin = request.headers.get("Origin");
    if (origin && ![url.origin, "https://chatgpt.com", "https://www.chatgpt.com"].includes(origin)) return new Response("Forbidden", { status: 403 });
    if (request.method !== "POST") return new Response("Use MCP POST", {status:405,headers:{Allow:"POST"}});
    let msg;
    try { msg = await request.json(); }
    catch { return Response.json({jsonrpc:"2.0",id:null,error:{code:-32700,message:"Parse error"}}, {status:400}); }
    if (!msg || Array.isArray(msg) || msg.jsonrpc !== "2.0" || typeof msg.method !== "string") return Response.json({jsonrpc:"2.0",id:null,error:{code:-32600,message:"Invalid request"}}, {status:400});
    if (!("id" in msg)) return new Response(null, { status: 202 });
    const reply = result => Response.json({jsonrpc:"2.0",id:msg.id,result});
    const error = (code,message) => Response.json({jsonrpc:"2.0",id:msg.id,error:{code,message}});
    switch (msg.method) {
      case "initialize": {
        const versions = ["2025-03-26", "2025-06-18", "2025-11-25", "2026-07-28"];
        const v = msg.params?.protocolVersion;
        return reply({protocolVersion:versions.includes(v)?v:"2026-07-28",capabilities:{tools:{}},serverInfo:{name:"execution-guard",version:VERSION}});
      }
      case "ping": return reply({});
      case "tools/list": return reply({tools:[{
        name:"server_status",
        description:"Read the current public Execution Guard server status and fresh UTC timestamp.",
        inputSchema:{type:"object",properties:{},additionalProperties:false},
        annotations:{readOnlyHint:true,destructiveHint:false,idempotentHint:true,openWorldHint:false}
      }]});
      case "tools/call": {
        if (msg.params?.name !== "server_status") return error(-32602,"Unknown tool");
        const args = msg.params?.arguments ?? {};
        if (!args || typeof args !== "object" || Array.isArray(args) || Object.keys(args).length) return error(-32602,"No arguments expected");
        return reply({content:[{type:"text",text:JSON.stringify(await status(env, diagnose))}]});
      }
      default: return error(-32601,"Method not found");
    }
  }
};