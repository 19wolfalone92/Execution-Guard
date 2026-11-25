import assert from "node:assert/strict";
const host="https://audit-oauth-e2e-20261125-execution-guard.19wolf-alone92.workers.dev",account=process.env.CLOUDFLARE_ACCOUNT_ID,token=process.env.CLOUDFLARE_API_TOKEN,tick=process.env.EG_PREVIEW_TICK_SECRET;
assert.equal(account,"04b45c9393f4e12159c6b8118ec54791");assert.equal(process.env.GITHUB_REF,"refs/heads/audit/oauth-e2e-20261125");assert.ok(token&&tick?.length>=32);
const req=(p,opts={})=>fetch(host+p,{...opts,redirect:"error",signal:AbortSignal.timeout(30000)});
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
async function query(sql,params=[]){const r=await fetch("https://api.cloudflare.com/client/v4/accounts/"+account+"/d1/database/657131f8-b0f4-47f3-ab3d-91840843f2db/query",{method:"POST",headers:{Authorization:"Bearer "+token,"Content-Type":"application/json"},body:JSON.stringify({sql,params}),redirect:"error",signal:AbortSignal.timeout(20000)});const x=await r.json();assert.ok(r.ok&&x.success);return x.result[0].results;}
const started=Date.now(),sha=process.env.GITHUB_SHA;let report;
for(let i=0;i<60;i++){
 try{
   const v=await (await req("/qualification/version")).json();
   if(v.sha===sha){
    const table=await query("SELECT name FROM sqlite_master WHERE type='table' AND name='eg_checkpoints'");
    if(table.length){
     const rows=await query("SELECT project,revision,value FROM eg_checkpoints WHERE owner=? AND project LIKE 'eg-qualification-browser-%-p' ORDER BY updated_at DESC LIMIT 10",["336868992"]);
     for(const row of rows){const p=JSON.parse(row.value);if(p.sha===sha&&p.state==="QUEUED"&&/^[a-f0-9-]{36}$/.test(p.workflow_id||"")&&p.proof_project===row.project){report={project:p.project,proof_project:row.project,workflow_id:p.workflow_id,control_id:p.control_id};break;}}
    }
   }
 }catch{}
 if(report)break;
 if(i%10===0)console.log("Preview qualification: awaiting owner OAuth and queued test workflow");
 await sleep(10000);
}
if(!report){console.log("PREVIEW_RUNNER "+JSON.stringify({status:"BLOCKED",reason:"owner_authorization_not_observed",sha}));process.exit(1);}
const out={sha,...report,ticks:0};
for(let i=0;i<20;i++){
 const r=await req("/qualification/tick",{method:"POST",headers:{Authorization:"Bearer "+tick}});assert.equal(r.status,200);out.ticks++;
 const rows=await query("SELECT id,state FROM eg_workflows WHERE owner=? AND project=? AND id IN (?,?)",["336868992",report.project,report.workflow_id,report.control_id]);
 out.states=rows;
 if(rows.some(x=>x.id===report.workflow_id&&["SUCCEEDED","FAILED"].includes(x.state))&&rows.some(x=>x.id===report.control_id&&["FAILED","CANCELLED","NEEDS_APPROVAL"].includes(x.state)))break;
 await sleep(10000);
}
out.steps=await query("SELECT id,step_key,state,attempts,created_at,updated_at FROM eg_workflow_steps WHERE owner=? AND project=? AND workflow_id=? ORDER BY created_at,step_key",["336868992",report.project,report.workflow_id]);
out.status=out.states?.some(x=>x.id===report.workflow_id&&x.state==="SUCCEEDED")&&out.steps.length===7&&out.steps.every(x=>x.state==="SUCCEEDED")?"PASS":"FAIL";
console.log("PREVIEW_RUNNER "+JSON.stringify(out));if(out.status!=="PASS")process.exitCode=1;
