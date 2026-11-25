import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {gatewayRoute,PREVIEW_HOST,HOST} from "../security.mjs";
import worker from "../worker.mjs";

test("Cloudflare Preview bindings are either absent or explicitly separate from production",()=>{
  const config=JSON.parse(readFileSync(new URL("../wrangler.jsonc",import.meta.url),"utf8"));
  assert.equal(config.previews.vars.EG_ENVIRONMENT,"preview");
  const enabled=config.previews.vars.EG_AUTH_ENABLED==="true";
  assert.equal(config.previews.vars.EG_PREVIEW_READY,enabled?"true":"false");
  const d=config.previews.d1_databases,k=config.previews.kv_namespaces;
  assert.equal(d.length,k.length);
  if(enabled)assert.equal(d.length,1);
  assert.ok(d.length===0||d.length===1);
  if(d.length){
    assert.equal(d[0].binding,"DB");assert.equal(k[0].binding,"OAUTH_KV");
    assert.match(d[0].database_id,/^[a-f0-9-]{36}$/);assert.match(k[0].id,/^[a-f0-9]{32}$/);
    assert.ok(config.d1_databases.every(x=>x.database_id!==d[0].database_id));
    assert.ok(config.kv_namespaces.every(x=>x.id!==k[0].id));
  }
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

test("unexpected preview bindings are reported but never accessed",async()=>{
  const fail=()=>{throw Error("unexpected storage access")};
  const gateway=gatewayRoute(worker,{fetch:fail});
  const host="https://audit-oauth-e2e-20261125-execution-guard.19wolf-alone92.workers.dev";
  const env={EG_ENVIRONMENT:"preview",EG_PREVIEW_READY:"false",EG_AUTH_ENABLED:"false",DB:{prepare:fail},OAUTH_KV:{get:fail}};
  const h=await (await gateway.fetch(new Request(host+"/health"),env,{})).json();
  assert.equal(h.database,"not_verified");
  assert.deepEqual(h.storage_guard,{state:"blocked",d1_binding_present:true,kv_binding_present:true});
  assert.equal((await gateway.fetch(new Request(host+"/mcp-private",{method:"POST",body:"{}"}),env,{})).status,503);
});

test("Preview readiness diagnoses missing secrets without reading stores or exposing values",async()=>{
  const fail=()=>{throw Error("must not access storage")};
  const gw=gatewayRoute(worker,{fetch:fail});
  const env={EG_ENVIRONMENT:"preview",EG_AUTH_ENABLED:"true",EG_PREVIEW_READY:"true",EG_OWNER_GITHUB_ID:"123",GITHUB_CLIENT_ID:"example-client",DB:{prepare:fail},OAUTH_KV:{get:fail}};
  const res=await gw.fetch(new Request(PREVIEW_HOST+"/qualification/readiness"),env,{});
  const d=await res.json();assert.equal(res.status,200);
  assert.equal(d.checks.github_client_secret_present,false);assert.equal(d.d1_marker,"not_checked");assert.equal(d.kv_marker,"not_checked");assert.equal(d.ready,false);
  assert.ok(!JSON.stringify(d).includes("example-client"));
  assert.equal((await gw.fetch(new Request(HOST+"/qualification/readiness"),env,{})).status,404);
});
test("Preview readiness distinguishes marker failures and independently verifies both",async()=>{
  const gw=gatewayRoute(worker,{fetch(){throw Error("provider must not be reached")}});
  const env={EG_ENVIRONMENT:"preview",EG_AUTH_ENABLED:"true",EG_PREVIEW_READY:"true",EG_OWNER_GITHUB_ID:"123",GITHUB_CLIENT_ID:"client",GITHUB_CLIENT_SECRET:"test-only",EG_PREVIEW_TICK_SECRET:"x".repeat(32),DB:{prepare(){return {first:async()=>({value:"execution-guard-preview-v1"})}}},OAUTH_KV:{get:async()=>null}};
  const read=async e=>(await gw.fetch(new Request(PREVIEW_HOST+"/qualification/readiness"),e,{})).json();
  let d=await read(env);assert.equal(d.d1_marker,"verified");assert.equal(d.kv_marker,"missing_or_mismatch");assert.equal(d.ready,false);
  d=await read({...env,OAUTH_KV:{get:async()=>{throw Error("do not disclose raw details")}}});assert.equal(d.kv_marker,"read_failed");assert.equal(d.ready,false);assert.ok(!JSON.stringify(d).includes("raw details"));
  d=await read({...env,OAUTH_KV:{get:async()=>"execution-guard-preview-v1"}});assert.equal(d.ready,true);assert.equal(d.kv_marker,"verified");
});
