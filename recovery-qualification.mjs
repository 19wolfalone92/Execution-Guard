// Engine-only fixtures use reserved, non-GitHub identities; never an OAuth bypass.
// All network faults are controlled simulations on the real isolated Preview D1.
import {createHash} from "node:crypto";
import {projectCreate,projectGet,projectUpdate,projectHistory,projectResume,workflowCreate,workflowStart,workflowStatus,workflowCancel,runWorkflowBatch,executionFinalize} from "./orchestrator.mjs";
import {taskSubmit,taskStatus} from "./tasks.mjs";
const cases=new Set(["lease","concurrent","429","503","timeout","backoff","exhaust","dependency","cancel_running","cancel_queued","tamper","memory","stale","missing_step"]);
const hash=s=>createHash("sha256").update(s).digest("hex");
const target={owner:"octo",repo:"repo"};
const okFetch=async()=>Response.json({id:7,full_name:"octo/repo",default_branch:"main",private:false,archived:false});
export async function recoveryQualification(db,params){
 const scenario=params.get("case"),phase=params.get("phase"),id=params.get("id");
 if(!cases.has(scenario)||!["setup","advance","observe","tamper","duplicate"].includes(phase)||! /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(id||""))return {status:"INVALID_REQUEST"};
 const owner="eg-recovery-fixture-"+id,project="eg-recovery-"+id,ref={project};
 const result={scenario,phase,id,project,environment:"preview",synthetic_identity:true,external_faults:"simulated",checked_at:new Date().toISOString(),checks:{}};
 const check=(k,v)=>{result.checks[k]=Boolean(v);};
 const external=["429","503","timeout","backoff","exhaust","cancel_running","stale"].includes(scenario);
 const step=external?{key:"repo",operation:"github_repository_status",input:target,max_attempts:scenario==="exhaust"?2:3,timeout_ms:1000}:{key:"hash",operation:"sha256_verify",input:{text:"abc",expected_sha256:scenario==="dependency"?"0".repeat(64):hash("abc")},max_attempts:3};
 const steps=[step];if(scenario==="missing_step")steps.push({...step,key:"second"});if(scenario==="dependency")steps.push({key:"dependent",operation:"health_probe",input:{},depends_on:["hash"]});
 const args={project,name:"Recovery "+scenario,idempotency_key:"recovery-"+id,steps};
 if(phase==="setup"){
  const p=await projectCreate(db,owner,{project,record:{goal:"Isolated recovery "+scenario,repository:target,stage:"created",rules:["Fixture only"]}});
  check("project_created",p.status==="created");if(!result.checks.project_created)return {...result,status:"FAIL"};
  const w=await workflowCreate(db,owner,args);check("workflow_created",w.status==="created");if(!w.workflow_id)return {...result,status:"FAIL"};
  ref.workflow_id=w.workflow_id;result.workflow_id=w.workflow_id;check("started",(await workflowStart(db,owner,ref)).status==="started");
  if(scenario==="lease"){await db.prepare("UPDATE eg_workflow_steps SET state='RUNNING',attempts=1,lease_id='expired-fixture',lease_until=? WHERE owner=? AND project=? AND workflow_id=?").bind(Date.now()-1,owner,project,w.workflow_id).run();await db.prepare("UPDATE eg_workflows SET state='RUNNING' WHERE owner=? AND project=? AND id=?").bind(owner,project,w.workflow_id).run();}
  if(scenario==="missing_step")await db.prepare("DELETE FROM eg_workflow_steps WHERE owner=? AND project=? AND workflow_id=? AND step_key='second'").bind(owner,project,w.workflow_id).run();
  if(scenario==="cancel_queued")check("cancelled",(await workflowCancel(db,owner,ref)).status==="cancelled");
  if(scenario==="memory"){
   check("revision_two",(await projectUpdate(db,owner,{project,expected_revision:1,patch:{stage:"saved",evidence:[{workflow_id:w.workflow_id}]}})).revision===2);
   check("stale_rejected",(await projectUpdate(db,owner,{project,expected_revision:1,patch:{stage:"stale"}})).error==="revision_conflict");
   await db.prepare("INSERT INTO eg_checkpoints(owner,project,revision,value,updated_at) VALUES(?,?,1,?,?)").bind(owner,project,JSON.stringify({workflow_id:w.workflow_id,scenario}),new Date().toISOString()).run();
   const t=await taskSubmit(db,owner,{project,idempotency_key:"task-"+id,kind:"health_probe",payload:{}});check("task_created",typeof t.task_id==="string");result.task_id=t.task_id;
  }
 }else{
  const w=await db.prepare("SELECT id FROM eg_workflows WHERE owner=? AND project=? AND name=?").bind(owner,project,args.name).first();
  if(!w)return {...result,status:"BLOCKED",reason:"fixture_missing"};ref.workflow_id=w.id;result.workflow_id=w.id;
  if(phase==="duplicate"){
   const duplicate=await workflowCreate(db,owner,args);check("duplicate_same_id",duplicate.deduplicated&&duplicate.workflow_id===w.id);
   check("idempotency_conflict",(await workflowCreate(db,owner,{...args,name:"different"})).error==="idempotency_conflict");
  }
  if(phase==="advance"){
   const before=await db.prepare("SELECT state,attempts,available_at FROM eg_workflow_steps WHERE owner=? AND project=? AND workflow_id=? AND step_key=?").bind(owner,project,w.id,step.key).first();
   const now=Date.now(),attempt=before.attempts;
   const fetcher=async(_url,options)=>{
    if(scenario==="cancel_running"){await workflowCancel(db,owner,ref);return okFetch();}
    if(scenario==="stale"&&attempt===0){
      const recovered=await runWorkflowBatch(db,owner,1,okFetch,now+32000);
      check("replacement_lease_executed",recovered.executed===1);
      // Old claimant returns a different payload after replacement commits.
      return Response.json({id:99,full_name:"octo/repo",default_branch:"stale",private:false});
    }
    if(scenario==="timeout"&&attempt===0){if(!options.signal)throw Error("missing_abort_signal");await new Promise((resolve,reject)=>{if(options.signal.aborted)reject(options.signal.reason);else options.signal.addEventListener("abort",()=>reject(options.signal.reason),{once:true});});}
    if(scenario==="exhaust"||(scenario==="backoff"&&attempt<2)||((scenario==="429"||scenario==="503")&&attempt===0))return new Response("{}",{status:scenario==="429"?429:503,headers:scenario==="429"||scenario==="503"?{"Retry-After":"3"}:{}});
    return okFetch();
   };
   const early=params.get("early")==="1";
   const at=early?Math.min(now,before.available_at-1):before.state==="RETRYING"?Math.max(now,before.available_at):now;
   result.scheduler_clock=at;result.before_attempt=attempt;
   const run=await runWorkflowBatch(db,owner,1,fetcher,at);result.executed=run.executed;
   if(early)check("early_retry_not_claimed",run.executed===0);
  }
  if(phase==="tamper"){
   if(scenario!=="tamper")return {...result,status:"INVALID_REQUEST"};
   check("original_verified",(await executionFinalize(db,owner,ref)).verified===true);
   const wrong=JSON.stringify({verified:true,sha256:hash("wrong"),expected_sha256:hash("wrong")}),ev=JSON.stringify({verified:true,operation:"sha256_verify",result_sha256:hash(wrong)});
   await db.prepare("UPDATE eg_workflow_steps SET result=?,evidence=? WHERE owner=? AND project=? AND workflow_id=?").bind(wrong,ev,owner,project,w.id).run();
   check("semantic_tamper_rejected",(await executionFinalize(db,owner,ref)).verified===false);
  }
  if(phase==="observe"&&scenario==="memory"){
   const p=await projectGet(db,owner,{project}),h=await projectHistory(db,owner,{project,limit:10}),resume=await projectResume(db,owner,{project});
   const cp=await db.prepare("SELECT revision,value FROM eg_checkpoints WHERE owner=? AND project=?").bind(owner,project).first();
   const task=await db.prepare("SELECT id FROM eg_tasks WHERE owner=? AND project=?").bind(owner,project).first(),other="eg-recovery-fixture-other-"+id;
   check("memory_revision",p.revision===2&&p.record.stage==="saved"&&p.record.evidence[0].workflow_id===w.id);
   check("history",h.history?.length===2&&h.history[0].revision===2);check("resume",resume.resume_ready&&resume.reconcile_required);
   check("checkpoint",cp?.revision===1&&JSON.parse(cp.value).workflow_id===w.id);
   check("other_owner_project",(await projectGet(db,other,{project})).found===false);
   check("other_owner_workflow",(await workflowStatus(db,other,ref)).found===false);
   check("other_owner_task",task&&(await taskStatus(db,other,{project,task_id:task.id})).found===false);
   check("other_project_task",task&&(await taskStatus(db,owner,{project:project+"x",task_id:task.id})).found===false);
   check("other_owner_checkpoint",!await db.prepare("SELECT revision FROM eg_checkpoints WHERE owner=? AND project=?").bind(other,project).first());
   check("sql_injection_rejected",(await projectGet(db,owner,{project:"x' OR 1=1--"})).error==="invalid_arguments");
   result.memory_hash=hash(JSON.stringify({p,h,cp}));result.task_id=task?.id||null;
  }
 }
 const w=await workflowStatus(db,owner,ref);
 const leases=(await db.prepare("SELECT step_key,available_at,lease_id,lease_until FROM eg_workflow_steps WHERE owner=? AND project=? AND workflow_id=?").bind(owner,project,ref.workflow_id).all()).results||[];
 result.workflow_state=w.workflow?.state;result.workflow_error=w.workflow?.error_code;result.steps=(w.steps||[]).map(s=>({id:s.id,key:s.key,state:s.state,attempts:s.attempts,error_code:s.error_code,updated_at:s.updated_at,verified:s.evidence?.verified===true,available_at:leases.find(l=>l.step_key===s.key)?.available_at,lease_released:!leases.find(l=>l.step_key===s.key)?.lease_id}));
 if(scenario==="stale"&&phase==="advance")check("stale_result_rejected",w.steps[0]?.result?.repository?.default_branch==="main"&&w.steps[0]?.attempts===2&&w.workflow?.state==="SUCCEEDED");
 result.status=Object.values(result.checks).every(Boolean)?"OBSERVED":"FAIL";return result;
}
