import assert from "node:assert/strict";
const account=process.env.CLOUDFLARE_ACCOUNT_ID,token=process.env.CLOUDFLARE_API_TOKEN;
assert.equal(account,"04b45c9393f4e12159c6b8118ec54791");assert.equal(process.env.GITHUB_REF,"refs/heads/audit/oauth-e2e-20261125");
const owner="336868992",keys=["eg-qualification-browser-11fc6efe-2182-4c8d-99ef-d7448ee2ba73-p","eg-qualification-browser-5aa7da9c-d3af-4d7e-8fd6-2f4737621b44-p"];
async function query(sql,params=[]){const r=await fetch("https://api.cloudflare.com/client/v4/accounts/"+account+"/d1/database/657131f8-b0f4-47f3-ab3d-91840843f2db/query",{method:"POST",headers:{Authorization:"Bearer "+token,"Content-Type":"application/json"},body:JSON.stringify({sql,params}),redirect:"error",signal:AbortSignal.timeout(20000)});const j=await r.json();assert.ok(r.ok&&j.success);return j.result[0].results;}
const inventory=await query("SELECT name FROM sqlite_master WHERE type='table'");const names=new Set(inventory.map(x=>x.name));
const out={checked_at:new Date().toISOString(),sessions:[]};
for(const key of keys){const rows=await query("SELECT revision,value,updated_at FROM eg_checkpoints WHERE owner=? AND project=?",[owner,key]);if(!rows.length)continue;
const p=JSON.parse(rows[0].value),project=key.slice(0,-2),matrix=Object.fromEntries(Object.entries(p.tools||{}).filter(([n])=>/^[a-z_]{1,60}$/.test(n)).map(([n,m])=>[n,Object.fromEntries(["valid","schema","invalid","missing_required","unauthenticated","scope"].map(k=>[k,typeof m[k]==="boolean"?m[k]:null]))]));
const session={key,revision:rows[0].revision,sha:p.sha,state:p.state,stage:p.failure_stage,matrix,project_revision_conflict:p.project_revision_conflict===true,project_history_verified:p.project_history_verified===true,project_isolation:p.project_isolation===true,commit_status:p.commit_status||null,cancel_task:p.cancel_task||null};
if(names.has("eg_tasks"))session.tasks=await query("SELECT id,kind,state,attempts,error_code FROM eg_tasks WHERE owner=? AND project=?",[owner,project]);
if(names.has("eg_projects"))session.projects=await query("SELECT revision,created_at,updated_at FROM eg_projects WHERE owner=? AND project=?",[owner,project]);
if(names.has("eg_workflows"))session.workflows=await query("SELECT id,state,error_code FROM eg_workflows WHERE owner=? AND project=?",[owner,project]);
if(names.has("eg_execution_audit"))session.audit=await query("SELECT event,created_at FROM eg_execution_audit WHERE owner=? AND project=? ORDER BY created_at",[owner,project]);
out.sessions.push(session);}
console.log("MCP_DIAG "+JSON.stringify(out));
