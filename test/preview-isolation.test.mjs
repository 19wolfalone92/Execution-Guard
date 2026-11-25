import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {gatewayRoute} from "../security.mjs";
import worker from "../worker.mjs";

test("initial Cloudflare preview is explicitly storage-isolated and OAuth disabled",()=>{
  const config=JSON.parse(readFileSync(new URL("../wrangler.jsonc",import.meta.url),"utf8"));
  assert.equal(config.previews.vars.EG_AUTH_ENABLED,"false");
  assert.deepEqual(config.previews.d1_databases,[]);
  assert.deepEqual(config.previews.kv_namespaces,[]);
  assert.equal(config.previews.triggers,undefined);
  assert.equal(config.d1_databases.length,1);
  assert.equal(config.kv_namespaces.length,1);
  assert.ok(config.triggers.crons.includes("*/5 * * * *"));
});
test("storage-free preview reports unverified data and rejects private requests",async()=>{
  const gateway=gatewayRoute(worker,{fetch(){throw Error("private provider must not be reached");}});
  const host="https://qualification-preview.example.com";
  const env={EG_AUTH_ENABLED:"false"};
  const health=await gateway.fetch(new Request(host+"/health"),env,{});
  assert.equal(health.status,200);
  const state=await health.json();
  assert.equal(state.version,"0.6.0");
  assert.equal(state.database,"not_verified");
  assert.equal(state.persistence_probe,"not_verified");
  assert.equal(state.oauth_storage,"not_bound");
  assert.equal(state.oauth.configuration,"disabled");
  const denied=await gateway.fetch(new Request(host+"/mcp-private",{method:"POST",body:"{}"}),env,{});
  assert.equal(denied.status,404);
  const rpc=await gateway.fetch(new Request(host+"/mcp",{method:"POST",body:JSON.stringify({jsonrpc:"2.0",id:1,method:"tools/list"})}),env,{});
  assert.deepEqual((await rpc.json()).result.tools.map(t=>t.name),["server_status"]);
});
