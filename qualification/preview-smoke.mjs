import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
const config=JSON.parse(readFileSync("wrangler.jsonc","utf8"));
const enabled=config.previews.vars.EG_AUTH_ENABLED==="true";
const repo="19wolfalone92/Execution-Guard",sha=process.env.GITHUB_SHA;
assert.match(sha||"",/^[a-f0-9]{40}$/);
const api=async p=>{const r=await fetch("https://api.github.com/repos/"+repo+p,{headers:{Authorization:"Bearer "+process.env.GITHUB_TOKEN,Accept:"application/vnd.github+json","User-Agent":"eg-preview-qualification"},signal:AbortSignal.timeout(15000)});assert.equal(r.status,200);return r.json();};
let deployment,build;
for(let i=0;i<60;i++){
  const checks=await api("/commits/"+sha+"/check-runs");build=checks.check_runs.find(x=>x.name==="Workers Builds: execution-guard");
  if(build?.status==="completed"&&build.conclusion!=="success")assert.fail("Cloudflare build failed: "+build.details_url);
  const comments=await api("/issues/5/comments?per_page=100");
  for(const c of comments.filter(x=>["cloudflare-workers-and-pages[bot]","cloudflare-workers-and-pages"].includes(x.user?.login))){
    for(const row of c.body.match(/<tr>[\s\S]*?<\/tr>/g)||[]){
      if(row.includes("<td>"+sha.slice(0,7)+"</td>")&&row.includes("Deployment:</b> Success")){
        deployment=row.match(/https:\/\/[a-f0-9]{8}-execution-guard\.19wolf-alone92\.workers\.dev/)?.[0];
      }
    }
  }
  if(i%6===0)console.log("Preview discovery: "+JSON.stringify({sha,attempt:i+1,build:build?.status??"missing",conclusion:build?.conclusion??null,matchingDeployment:Boolean(deployment)}));
  if(deployment&&build?.conclusion==="success")break;
  await new Promise(r=>setTimeout(r,10000));
}
assert.ok(deployment&&build?.conclusion==="success","Exact SHA deployment missing");
const request=(p,opts={})=>fetch(deployment+p,{...opts,redirect:"manual",signal:AbortSignal.timeout(15000)});
const health=await request("/health");assert.equal(health.status,200);
const h=await health.json();console.log("PREVIEW EVIDENCE "+JSON.stringify({sha,deployment,build:build.details_url,health:h}));
assert.equal(h.version,"0.6.0");assert.equal(h.status,"online");
assert.equal(h.database,"not_verified");assert.equal(h.persistence_probe,"not_verified");
assert.equal(h.oauth_storage,"not_bound");assert.equal(h.oauth.configuration,"disabled");assert.equal(h.storage_guard?.state,"blocked");
const post=(p,method,params={})=>request(p,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({jsonrpc:"2.0",id:1,method,params})});
const init=await post("/mcp","initialize",{protocolVersion:"2025-11-25"});assert.equal(init.status,200);assert.equal((await init.json()).result.serverInfo.version,"0.6.0");
const list=await post("/mcp","tools/list");assert.equal(list.status,200);assert.deepEqual((await list.json()).result.tools.map(t=>t.name),["server_status"]);
assert.equal((await post("/mcp-private","tools/list")).status,404);
assert.equal((await request("/.well-known/oauth-authorization-server")).status,404);
assert.equal((await post("/qualification/tick","ping")).status,404);
console.log("LIVE PREVIEW HTTP GUARD PASS: "+deployment+" "+sha+"; binding identity still requires account verification.");
// Keep resource isolation a separate explicit gate. A guard is not proof
// that a binding is absent or points to a separate database.
assert.equal(h.storage_guard.d1_binding_present,config.previews.d1_databases.length===1,"Unexpected D1 binding; inspect Previews Base");
assert.equal(h.storage_guard.kv_binding_present,config.previews.kv_namespaces.length===1,"Unexpected KV binding; inspect Previews Base");
if(!enabled){
  const stable="https://audit-oauth-e2e-20261125-execution-guard.19wolf-alone92.workers.dev";
  const r=await fetch(stable+"/health",{redirect:"manual",signal:AbortSignal.timeout(15000)});
  assert.equal(r.status,200);const state=await r.json();
  assert.equal(state.version,"0.6.0");assert.equal(state.storage_guard?.state,"blocked");assert.equal(state.database,"not_verified");assert.equal(state.oauth.configuration,"disabled");
  console.log("LIVE PREVIEW STAGED BINDING PRESENCE AND DISABLED AUTH PASS; resource identity and markers require account confirmation");
}
else{
  const stable="https://audit-oauth-e2e-20261125-execution-guard.19wolf-alone92.workers.dev";
  const readiness=await fetch(stable+"/qualification/readiness",{redirect:"manual",signal:AbortSignal.timeout(15000)});
  assert.equal(readiness.status,200);const report=await readiness.json();
  console.log("PREVIEW READINESS "+JSON.stringify(report));
  const r=await fetch(stable+"/health",{redirect:"manual",signal:AbortSignal.timeout(15000)});
  assert.equal(r.status,200);const state=await r.json();
  console.log("STABLE PREVIEW HEALTH "+JSON.stringify(state));
  assert.equal(report.ready,true,"Preview readiness: inspect fixed diagnostic codes above");
  assert.equal(report.checks.tick_secret_configured,true,"Preview tick secret missing or too short");
  assert.equal(state.version,"0.6.0");assert.equal(state.database,"online");assert.equal(state.persistence_probe,"verified");assert.equal(state.oauth_storage,"bound");assert.equal(state.oauth.discovery,"verified");
  const unauthorized=await fetch(stable+"/mcp-private",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({jsonrpc:"2.0",id:1,method:"tools/list"}),redirect:"manual",signal:AbortSignal.timeout(15000)});
  assert.equal(unauthorized.status,401);assert.match(unauthorized.headers.get("WWW-Authenticate")||"",/resource_metadata=/);
  console.log("LIVE PREVIEW MARKERS AND PUBLIC OAUTH DISCOVERY PASS; owner login and refresh require authenticated qualification.");
}
