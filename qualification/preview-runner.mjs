import assert from "node:assert/strict";
import {createHash} from "node:crypto";
const host="https://audit-oauth-e2e-20261125-execution-guard.19wolf-alone92.workers.dev",account=process.env.CLOUDFLARE_ACCOUNT_ID,token=process.env.CLOUDFLARE_API_TOKEN,tick=process.env.EG_PREVIEW_TICK_SECRET;
assert.equal(account,"04b45c9393f4e12159c6b8118ec54791");assert.equal(process.env.GITHUB_REF,"refs/heads/audit/oauth-e2e-20261125");assert.ok(token&&tick?.length>=32);
const req=(p,opts={})=>fetch(host+p,{...opts,redirect:"error",signal:AbortSignal.timeout(45000)});
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
async function query(sql,params=[]){const r=await fetch("https://api.cloudflare.com/client/v4/accounts/"+account+"/d1/database/657131f8-b0f4-47f3-ab3d-91840843f2db/query",{method:"POST",headers:{Authorization:"Bearer "+token,"Content-Type":"application/json"},body:JSON.stringify({sql,params}),redirect:"error",signal:AbortSignal.timeout(20000)});const x=await r.json();assert.ok(r.ok&&x.success);return x.result[0].results;}
const sha=process.env.GITHUB_SHA,owner="336868992",out={sha,ticks:0,checked_at:new Date().toISOString()};
const hash=x=>createHash("sha256").update(x,"utf8").digest("hex");
const terminal=new Set(["SUCCEEDED","FAILED","CANCELLED","NEEDS_APPROVAL"]);
let phase="read_live_state";
try{
 const [v,r]=await Promise.all([req("/qualification/version").then(x=>x.json()),req("/qualification/readiness").then(x=>x.json())]);out.live_sha=v.sha;out.version_id=v.version_id;out.ready=r.ready===true;assert.ok(out.ready);
 const table=await query("SELECT name FROM sqlite_master WHERE type='table' AND name='eg_checkpoints'");
 const rows=table.length?await query("SELECT project,revision,value,updated_at FROM eg_checkpoints WHERE owner=? AND project LIKE 'eg-qualification-browser-%-p' ORDER BY updated_at DESC LIMIT 20",[owner]):[];
 const reports=rows.flatMap(row=>{try{const p=JSON.parse(row.value);return p.proof_project===row.project&&p.project===row.project.slice(0,-2)&&/^[a-f0-9]{40}$/.test(p.sha||"")?[{row,p}]:[];}catch{return [];}});
 out.sessions=reports.map(({row,p})=>({project:row.project,revision:row.revision,sha:p.sha,state:p.state,owner_verified:p.owner_verified===true,refresh:p.refresh===true,stage:p.failure_stage||null,updated_at:row.updated_at}));
 const match=reports.find(({p})=>p.sha===v.sha&&p.owner_verified===true&&p.refresh===true);
 if(!match){out.status="BLOCKED";out.reason="owner_authorization_not_observed";process.exitCode=1;}
 else{
  let {row,p}=match;out.project=p.project;out.proof_project=row.project;out.revision=row.revision;out.oauth={owner_verified:p.owner_verified,refresh:p.refresh,pkce:p.pkce,state:p.state===undefined?false:true,rotation:p.refresh_rotation_observed,read_only:p.read_only};
  if(v.sha!==sha){out.status="BLOCKED";out.reason="workflow_sha_not_live";process.exitCode=1;}
  else if(!/^[a-f0-9-]{36}$/.test(p.workflow_id||"")||! /^[a-f0-9-]{36}$/.test(p.control_id||"")){out.status="BLOCKED";out.reason="authorized_but_workflow_not_created";process.exitCode=1;}
  else{
   phase="resume_persisted_workflow";out.workflow_id=p.workflow_id;out.control_id=p.control_id;
   const state=()=>query("SELECT id,state,created_at,updated_at,finished_at,error_code FROM eg_workflows WHERE owner=? AND project=? AND id IN (?,?)",[owner,p.project,p.workflow_id,p.control_id]);
   for(let i=0;i<16;i++){
    out.states=await state();
    if(out.states.length===2&&out.states.every(s=>terminal.has(s.state)))break;
    const res=await req("/qualification/tick",{method:"POST",headers:{Authorization:"Bearer "+tick}});assert.equal(res.status,200);out.ticks++;
    await sleep(5000);
   }
   out.states=await state();const steps=await query("SELECT id,step_key,operation,depends_on,state,attempts,created_at,updated_at,result,evidence,error_code FROM eg_workflow_steps WHERE owner=? AND project=? AND workflow_id=? ORDER BY created_at,step_key",[owner,p.project,p.workflow_id]);
   out.steps=steps.map(s=>{const e=JSON.parse(s.evidence||"null");return {id:s.id,key:s.step_key,operation:s.operation,depends_on:JSON.parse(s.depends_on),state:s.state,attempts:s.attempts,created_at:s.created_at,updated_at:s.updated_at,hash_verified:!!e&&e.verified===true&&hash(s.result||"")===e.result_sha256,sha256:e?.result_sha256,error_code:s.error_code};});
   const save=steps.find(s=>s.operation==="qualification_checkpoint");
   if(save?.state==="SUCCEEDED"){
    const s=JSON.parse(save.result),cp=await query("SELECT revision,value FROM eg_checkpoints WHERE owner=? AND project=?",[owner,"eg-qualification-"+p.workflow_id]);
    if(cp.length===1){const saved=JSON.parse(cp[0].value);out.checkpoint={project:"eg-qualification-"+p.workflow_id,revision:cp[0].revision,sha256:saved.sha256,verified:cp[0].revision===1&&s.sha256===saved.sha256&&hash(JSON.stringify(saved.snapshot))===saved.sha256&&saved.snapshot.sha===sha&&saved.snapshot.workflow_id===p.workflow_id,ci:saved.snapshot.ci};}
   }
   const current=await query("SELECT revision,value FROM eg_checkpoints WHERE owner=? AND project=?",[owner,row.project]);if(current.length){p=JSON.parse(current[0].value);out.revision=current[0].revision;out.tools=p.tools;out.all_tools_valid=p.all_tools_valid===true;out.browser_state=p.state;}
   out.dag_verified=out.states.some(x=>x.id===out.workflow_id&&x.state==="SUCCEEDED")&&out.steps.length===7&&out.steps.every(x=>x.state==="SUCCEEDED"&&x.hash_verified)&&out.checkpoint?.verified===true;
   out.status=out.dag_verified&&out.all_tools_valid?"PASS":"PARTIAL";if(out.status!=="PASS")process.exitCode=1;
  }
 }
}catch(e){out.status="BLOCKED";out.reason="failed_"+phase;process.exitCode=1;}
console.log("PREVIEW_RUNNER "+JSON.stringify(out));
