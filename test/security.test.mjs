import {test} from "node:test";
import assert from "node:assert/strict";
import {DatabaseSync} from "node:sqlite";
import {configured,isOwner,consentHtml,s256,gatewayRoute,oauthDiagnostics,RESOURCE,HOST,READ,WRITE} from "../security.mjs";
import {privateFetch} from "../private.mjs";
const env={EG_AUTH_ENABLED:"true",EG_OWNER_GITHUB_ID:"7",GITHUB_CLIENT_ID:"test",GITHUB_CLIENT_SECRET:"fake",OAUTH_KV:{},DB:{}};
const ctx=(scope=[READ,WRITE],id="7")=>({props:{userId:id},auth:{scope}});
const req=(name,args={})=>new Request(HOST+"/mcp-private",{method:"POST",body:JSON.stringify({jsonrpc:"2.0",id:1,method:"tools/call",params:{name,arguments:args}})});
const read=async(response)=>{const j=await response.json();return {j,value:JSON.parse(j.result.content[0].text)}};
test("auth is disabled when missing configuration",()=>{assert.equal(configured({}),false);assert.equal(configured({...env,EG_AUTH_ENABLED:"false"}),false);assert.equal(configured(env),true);assert.equal(isOwner(env,ctx([],"8")),false);assert.equal(isOwner(env,ctx()),true)});
test("private route fails closed and public route stays available",async()=>{const gw=gatewayRoute({fetch:()=>new Response("public")},{fetch:()=>new Response("oauth")});assert.equal(await (await gw.fetch(new Request(HOST+"/mcp"),{})).text(),"public");assert.equal((await gw.fetch(new Request(HOST+"/mcp-private"),{})).status,503);assert.equal((await gw.fetch(new Request("https://other.example/mcp-private"),env)).status,404);assert.equal(await (await gw.fetch(new Request(HOST+"/mcp-private"),env)).text(),"oauth")});
test("consent escapes HTML and uses S256",async()=>{const h=consentHtml({clientName:"<script>",clientDomain:"<b>",redirectHost:"x",scope:[READ]},'"><script>');assert.ok(!h.includes("<script>"));assert.ok(h.includes("&lt;script&gt;"));assert.equal(await s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")});
test("no unauthenticated, wrong owner or missing read scope access",async()=>{for(const c of [undefined,ctx([READ],"8"),ctx([])])assert.equal((await privateFetch(req("whoami"),env,c)).status,403)});
test("read only token cannot write",async()=>{const r=await privateFetch(req("checkpoint_put",{project:"p",expected_revision:0,value:"a"}),env,ctx([READ]));assert.equal((await r.json()).result.isError,true)});
test("unknown tool and invalid project rejected",async()=>{for(const r of [req("sql"),req("checkpoint_get",{project:"../x"}),req("checkpoint_put",{project:"p",expected_revision:-1,value:"x"})])assert.equal((await (await privateFetch(r,env,ctx())).json()).error.code,-32602)});
test("body limit and origin validation",async()=>{const r=new Request(HOST+"/mcp-private",{method:"POST",body:"x".repeat(17000)});assert.equal((await privateFetch(r,env,ctx())).status,413);const o=new Request(HOST+"/mcp-private",{method:"POST",headers:{Origin:"https://evil.example"},body:"{}"});assert.equal((await privateFetch(o,env,ctx())).status,403)});
test("checkpoint SQLite create/read/CAS/isolation",async()=>{const db=new DatabaseSync(":memory:");const adapter={prepare(sql){const stmt=db.prepare(sql);const wrap=(a)=>({bind:(...v)=>wrap(v),first:async()=>stmt.get(...a),run:async()=>({meta:{changes:Number(stmt.run(...a).changes)}})});return wrap([])}};
const e={...env,DB:adapter};const call=async(n,a,c=ctx())=>(await read(await privateFetch(req(n,a),e,c))).value;
try{assert.equal((await call("checkpoint_get",{project:"p"})).found,false);assert.equal((await call("checkpoint_put",{project:"p",expected_revision:0,value:"first"})).revision,1);assert.equal((await call("checkpoint_put",{project:"p",expected_revision:0,value:"bad"})).status,"conflict");assert.equal((await call("checkpoint_put",{project:"p",expected_revision:1,value:"second"})).revision,2);assert.equal((await call("checkpoint_get",{project:"p"})).value,"second");assert.equal((await call("checkpoint_get",{project:"other"})).found,false);assert.equal((await call("checkpoint_put",{project:"p",expected_revision:1,value:"stale"})).status,"conflict");assert.equal((await call("checkpoint_get",{project:"p"})).revision,2);assert.equal((await privateFetch(req("checkpoint_get",{project:"p"}),{...e,EG_OWNER_GITHUB_ID:"8"},ctx([READ],"8")).then(read)).value.found,false);}finally{db.close()}});

test("discovery diagnostic is fail closed and reports only metadata validation",async()=>{
const valid={fetch:async req=>Response.json(new URL(req.url).pathname.includes("protected-resource")?{resource:RESOURCE,authorization_servers:[HOST]}:{issuer:HOST,authorization_endpoint:HOST+"/authorize",token_endpoint:HOST+"/oauth/token",code_challenge_methods_supported:["S256"],client_id_metadata_document_supported:true})};
assert.deepEqual(await oauthDiagnostics({},valid),{configuration:"disabled",discovery:"not_ready"});
assert.deepEqual(await oauthDiagnostics({...env,GITHUB_CLIENT_SECRET:""},valid),{configuration:"incomplete",discovery:"not_ready"});
assert.deepEqual(await oauthDiagnostics(env,valid),{configuration:"ready",resource_http:200,issuer_http:200,discovery:"verified"});
assert.equal((await oauthDiagnostics(env,{fetch:async()=>Response.json({})})).discovery,"invalid_metadata");
assert.equal((await oauthDiagnostics(env,{fetch:async()=>new Response(null,{status:404})})).resource_http,404);
assert.deepEqual(await oauthDiagnostics(env,{fetch:async()=>{throw Error("secret")}}),{configuration:"ready",discovery:"provider_error"});
});
