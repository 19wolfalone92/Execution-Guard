import {test} from "node:test";
import assert from "node:assert/strict";
import {DatabaseSync} from "node:sqlite";
import {projectCreate,workflowCreate,workflowStart,runWorkflowBatch,workflowStatus} from "../orchestrator.mjs";

function fixture(){
  const raw=new DatabaseSync(":memory:");
  const statement=(sql,params=[])=>({sql,params,bind(...v){return statement(sql,v)},async first(){return raw.prepare(sql).get(...params)},async all(){return {results:raw.prepare(sql).all(...params)}},async run(){const r=raw.prepare(sql).run(...params);return {meta:{changes:Number(r.changes)}}}});
  return {raw,db:{prepare(sql){return statement(sql)},async batch(items){raw.exec("BEGIN");try{const out=items.map(s=>({meta:{changes:Number(raw.prepare(s.sql).run(...s.params).changes)}}));raw.exec("COMMIT");return out;}catch(e){raw.exec("ROLLBACK");throw e;}}},close(){raw.close()}};
}

test("D1 lease claim enforces the four-running-steps per-owner limit",async()=>{
  const f=fixture();
  try{
    await projectCreate(f.db,"owner",{project:"cap",record:{goal:"Concurrency qualification"}});
    const steps=Array.from({length:5},(_,i)=>({key:"step"+i,operation:"health_probe",input:{}}));
    const wf=await workflowCreate(f.db,"owner",{project:"cap",name:"owner-cap",steps});
    await workflowStart(f.db,"owner",{project:"cap",workflow_id:wf.workflow_id});
    f.raw.prepare("UPDATE eg_workflow_steps SET state='RUNNING',attempts=1,lease_id='held',lease_until=? WHERE workflow_id=? AND step_key IN ('step0','step1','step2','step3')").run(Date.now()+60000,wf.workflow_id);
    const result=await runWorkflowBatch(f.db,"owner",4,fetch,Date.now());
    assert.equal(result.executed,0);
    const status=await workflowStatus(f.db,"owner",{project:"cap",workflow_id:wf.workflow_id});
    assert.equal(status.steps.filter(s=>s.state==="RUNNING").length,4);
    assert.equal(status.steps.filter(s=>s.state==="QUEUED").length,1);
  }finally{f.close()}
});
