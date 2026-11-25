import {test} from "node:test";
import assert from "node:assert/strict";
import {DatabaseSync} from "node:sqlite";
import {
  projectCreate,projectGet,projectUpdate,projectHistory,projectResume,
  workflowCreate,workflowStart,workflowStatus,workflowPause,workflowResume,
  workflowCancel,workflowRetry,workflowDependenciesGet,taskEvidenceGet,
  executionAudit,executionFinalize,systemHealth,githubRepositoryStatus,
  githubCommitStatus,githubWorkflowStatus,runWorkflowBatch
} from "../orchestrator.mjs";

function dbFixture(){
  const raw=new DatabaseSync(":memory:");
  const statement=(sql,params=[])=>({
    sql,params,
    bind(...values){return statement(sql,values)},
    async first(){return raw.prepare(sql).get(...params)},
    async all(){return {results:raw.prepare(sql).all(...params)}},
    async run(){const r=raw.prepare(sql).run(...params);return {meta:{changes:Number(r.changes)}}}
  });
  const db={
    prepare(sql){return statement(sql)},
    async batch(items){
      raw.exec("BEGIN");
      try{
        const results=items.map(item=>{const r=raw.prepare(item.sql).run(...item.params);return {meta:{changes:Number(r.changes)}}});
        raw.exec("COMMIT");return results;
      }catch(error){raw.exec("ROLLBACK");throw error;}
    }
  };
  return {db,raw,close(){raw.close()}};
}
const owner="123456";
async function seedProject(db,project="williams"){
  return projectCreate(db,owner,{project,record:{goal:"Qualification project",rules:["Keep repositories isolated"],repository:{owner:"19wolfalone92",repo:"Execution-Guard"},stage:"audit"}});
}
async function seedProbe(raw){
  raw.exec("CREATE TABLE eg_probe(id INTEGER PRIMARY KEY,value TEXT NOT NULL);INSERT INTO eg_probe VALUES(1,'execution-guard-v030')");
}

test("structured project memory preserves history and rejects stale revisions",async()=>{
  const f=dbFixture();
  try{
    const created=await seedProject(f.db);
    assert.equal(created.status,"created");
    assert.equal((await projectGet(f.db,owner,{project:"williams"})).revision,1);
    const update=await projectUpdate(f.db,owner,{project:"williams",expected_revision:1,patch:{stage:"qualification",next_action:"Run the independent checks"}});
    assert.equal(update.revision,2);
    const stale=await projectUpdate(f.db,owner,{project:"williams",expected_revision:1,patch:{stage:"stale"}});
    assert.equal(stale.error,"revision_conflict");
    const history=await projectHistory(f.db,owner,{project:"williams",limit:10});
    assert.deepEqual(history.history.map(x=>x.revision),[2,1]);
    assert.equal((await projectResume(f.db,owner,{project:"williams"})).reconcile_required,true);
    assert.equal((await projectCreate(f.db,owner,{project:"bad",record:{goal:"x",api_token:"do-not-store"}})).error,"invalid_project_record");
    assert.equal((await projectGet(f.db,"999",{project:"williams"})).found,false);
  }finally{f.close()}
});

test("workflow DAG executes independent steps, respects dependencies and stores verifiable evidence",async()=>{
  const f=dbFixture();
  try{
    seedProbe(f.raw);
    await seedProject(f.db);
    const workflow=await workflowCreate(f.db,owner,{project:"williams",name:"qualification",idempotency_key:"qualification-idem",steps:[
      {key:"hash",operation:"sha256_verify",input:{text:"abc",expected_sha256:"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}},
      {key:"health",operation:"health_probe",input:{},depends_on:["hash"]}
    ]});
    assert.equal(workflow.state,"CREATED");
    assert.equal((await workflowStart(f.db,owner,{project:"williams",workflow_id:workflow.workflow_id})).state,"QUEUED");
    const graph=await workflowDependenciesGet(f.db,owner,{project:"williams",workflow_id:workflow.workflow_id});
    assert.deepEqual(graph.dependencies.find(x=>x.key==="hash").dependents,["health"]);
    const run=await runWorkflowBatch(f.db,owner,4,fetch,Date.now());
    assert.equal(run.executed,2);
    const status=await workflowStatus(f.db,owner,{project:"williams",workflow_id:workflow.workflow_id});
    assert.equal(status.workflow.state,"SUCCEEDED");
    assert.ok(status.steps.every(x=>x.state==="SUCCEEDED"&&x.evidence?.verified===true));
    const evidence=await taskEvidenceGet(f.db,owner,{project:"williams",workflow_id:workflow.workflow_id,step_key:"hash"});
    assert.equal(evidence.evidence.verified,true);
    assert.equal((await executionFinalize(f.db,owner,{project:"williams",workflow_id:workflow.workflow_id})).verified,true);
    assert.ok((await executionAudit(f.db,owner,{project:"williams",limit:20})).events.length>=3);
    assert.equal((await systemHealth(f.db,owner)).database,"online");
  }finally{f.close()}
});

test("workflow validation rejects cycles, unknown operations and cross-project access",async()=>{
  const f=dbFixture();
  try{
    await seedProject(f.db);
    const cyclic=await workflowCreate(f.db,owner,{project:"williams",name:"cycle",idempotency_key:"cycle-idem",steps:[
      {key:"a",operation:"health_probe",input:{},depends_on:["b"]},
      {key:"b",operation:"health_probe",input:{},depends_on:["a"]}
    ]});
    assert.equal(cyclic.error,"invalid_workflow_definition");
    const unsupported=await workflowCreate(f.db,owner,{project:"williams",name:"unsafe",idempotency_key:"unsafe-idem",steps:[{key:"shell",operation:"shell",input:{command:"id"}}]});
    assert.equal(unsupported.error,"invalid_workflow_definition");
    const other=await workflowCreate(f.db,owner,{project:"missing",name:"missing",idempotency_key:"missing-idem",steps:[{key:"a",operation:"health_probe",input:{}}]});
    assert.equal(other.error,"project_not_found");
  }finally{f.close()}
});

test("pause, resume and cancellation enforce workflow state transitions",async()=>{
  const f=dbFixture();
  try{
    await seedProject(f.db);
    const workflow=await workflowCreate(f.db,owner,{project:"williams",name:"lifecycle",idempotency_key:"lifecycle-idem",steps:[{key:"health",operation:"health_probe",input:{}}]});
    await workflowStart(f.db,owner,{project:"williams",workflow_id:workflow.workflow_id});
    assert.equal((await workflowPause(f.db,owner,{project:"williams",workflow_id:workflow.workflow_id})).status,"paused");
    assert.equal((await workflowStatus(f.db,owner,{project:"williams",workflow_id:workflow.workflow_id})).workflow.state,"PAUSED");
    assert.equal((await workflowResume(f.db,owner,{project:"williams",workflow_id:workflow.workflow_id})).status,"resumed");
    assert.equal((await workflowCancel(f.db,owner,{project:"williams",workflow_id:workflow.workflow_id})).status,"cancelled");
    assert.equal((await workflowStatus(f.db,owner,{project:"williams",workflow_id:workflow.workflow_id})).workflow.state,"CANCELLED");
    assert.equal((await runWorkflowBatch(f.db,owner,4,fetch,Date.now())).executed,0);
  }finally{f.close()}
});

test("failed verification is not success and retry exhaustion requires explicit approval",async()=>{
  const f=dbFixture();
  try{
    await seedProject(f.db);
    const workflow=await workflowCreate(f.db,owner,{project:"williams",name:"bad-hash",idempotency_key:"bad-hash-idem",steps:[{key:"hash",operation:"sha256_verify",input:{text:"abc",expected_sha256:"0".repeat(64)},max_attempts:1}]});
    await workflowStart(f.db,owner,{project:"williams",workflow_id:workflow.workflow_id});
    await runWorkflowBatch(f.db,owner,1,fetch,Date.now());
    assert.equal((await workflowStatus(f.db,owner,{project:"williams",workflow_id:workflow.workflow_id})).workflow.state,"FAILED");
    assert.equal((await workflowRetry(f.db,owner,{project:"williams",workflow_id:workflow.workflow_id})).status,"needs_approval");
    assert.equal((await workflowStatus(f.db,owner,{project:"williams",workflow_id:workflow.workflow_id})).workflow.state,"NEEDS_APPROVAL");
    assert.equal((await workflowRetry(f.db,owner,{project:"williams",workflow_id:workflow.workflow_id})).status,"retrying");
  }finally{f.close()}
});

test("GitHub read adapter is host-pinned, read-only and classifies rate limits",async()=>{
  const fetcher=async url=>new Response(JSON.stringify({id:1,full_name:"octo/repo",private:false,archived:false,default_branch:"main",updated_at:"2026-11-25T00:00:00Z",state:"success",total_count:1,status:"completed",conclusion:"success",run_number:7,head_sha:"a".repeat(40),html_url:"https://github.com/octo/repo/actions/runs/7"}),{status:200,headers:{"Content-Type":"application/json"}});
  const repo=await githubRepositoryStatus({owner:"octo",repo:"repo"},fetcher);
  assert.equal(repo.verified,true);
  const commit=await githubCommitStatus({owner:"octo",repo:"repo",sha:"a".repeat(40)},fetcher);
  assert.equal(commit.verified,true);
  const run=await githubWorkflowStatus({owner:"octo",repo:"repo",run_id:7},fetcher);
  assert.equal(run.verified,true);
  const limited=await githubRepositoryStatus({owner:"octo",repo:"repo"},async()=>new Response("{}",{status:429,headers:{"Retry-After":"2"}}));
  assert.equal(limited.retryable,true);
  assert.equal(limited.error,"github_rate_limited");
});


test("workflow creation is idempotent and rejects key reuse with a different definition",async()=>{
  const f=dbFixture();
  try{
    await seedProject(f.db);
    const definition={project:"williams",name:"idempotent",idempotency_key:"workflow-idem-1",steps:[{key:"health",operation:"health_probe",input:{}}]};
    const first=await workflowCreate(f.db,owner,definition);
    const repeated=await workflowCreate(f.db,owner,definition);
    assert.equal(first.status,"created");
    assert.equal(repeated.status,"existing");
    assert.equal(repeated.deduplicated,true);
    assert.equal(repeated.workflow_id,first.workflow_id);
    const conflict=await workflowCreate(f.db,owner,{...definition,name:"different-definition"});
    assert.equal(conflict.error,"idempotency_conflict");
  }finally{f.close()}
});


test("expired execution lease is recovered and retried without losing the workflow",async()=>{
  const f=dbFixture();
  try{
    await seedProbe(f.raw);
    await seedProject(f.db);
    const wf=await workflowCreate(f.db,owner,{project:"williams",name:"lease-recovery",idempotency_key:"lease-recovery-1",steps:[{key:"health",operation:"health_probe",input:{},max_attempts:3}]});
    await workflowStart(f.db,owner,{project:"williams",workflow_id:wf.workflow_id});
    const now=Date.now();
    f.raw.prepare("UPDATE eg_workflows SET state='RUNNING' WHERE id=?").run(wf.workflow_id);
    f.raw.prepare("UPDATE eg_workflow_steps SET state='RUNNING',attempts=1,lease_id='expired-lease',lease_until=? WHERE workflow_id=? AND step_key='health'").run(now-1,wf.workflow_id);
    await runWorkflowBatch(f.db,owner,2,fetch,now);
    const status=await workflowStatus(f.db,owner,{project:"williams",workflow_id:wf.workflow_id});
    assert.equal(status.workflow.state,"SUCCEEDED");
    assert.equal(status.steps[0].attempts,2);
  }finally{f.close()}
});

test("transient GitHub 503 honors Retry-After and retries within the configured budget",async()=>{
  const f=dbFixture();
  try{
    await seedProject(f.db);
    const wf=await workflowCreate(f.db,owner,{project:"williams",name:"retry-after",idempotency_key:"retry-after-1",steps:[{key:"repo",operation:"github_repository_status",input:{owner:"octo",repo:"repo"},max_attempts:2}]});
    await workflowStart(f.db,owner,{project:"williams",workflow_id:wf.workflow_id});
    const now=Date.now();
    await runWorkflowBatch(f.db,owner,1,async()=>new Response("{}",{status:503,headers:{"Retry-After":"2"}}),now);
    const waiting=f.raw.prepare("SELECT state,attempts,available_at FROM eg_workflow_steps WHERE workflow_id=?").get(wf.workflow_id);
    assert.equal(waiting.state,"RETRYING");
    assert.equal(waiting.attempts,1);
    assert.ok(waiting.available_at>=now+2000);
    await runWorkflowBatch(f.db,owner,1,async()=>new Response(JSON.stringify({id:7,full_name:"octo/repo",default_branch:"main",private:false,archived:false}),{status:200}),now+5000);
    const status=await workflowStatus(f.db,owner,{project:"williams",workflow_id:wf.workflow_id});
    assert.equal(status.workflow.state,"SUCCEEDED");
    assert.equal(status.steps[0].attempts,2);
  }finally{f.close()}
});

test("cancelling during an in-flight GitHub read prevents the step from becoming successful",async()=>{
  const f=dbFixture();
  try{
    await seedProject(f.db);
    const wf=await workflowCreate(f.db,owner,{project:"williams",name:"cancel-in-flight",idempotency_key:"cancel-in-flight-1",steps:[{key:"repo",operation:"github_repository_status",input:{owner:"octo",repo:"repo"}}]});
    await workflowStart(f.db,owner,{project:"williams",workflow_id:wf.workflow_id});
    const fetcher=async()=>{await workflowCancel(f.db,owner,{project:"williams",workflow_id:wf.workflow_id});return new Response(JSON.stringify({id:7,full_name:"octo/repo",default_branch:"main"}),{status:200});};
    await runWorkflowBatch(f.db,owner,1,fetcher,Date.now());
    const status=await workflowStatus(f.db,owner,{project:"williams",workflow_id:wf.workflow_id});
    assert.equal(status.workflow.state,"CANCELLED");
    assert.equal(status.steps[0].state,"CANCELLED");
    assert.equal((await executionFinalize(f.db,owner,{project:"williams",workflow_id:wf.workflow_id})).verified,false);
  }finally{f.close()}
});

test("finalization detects a modified persisted result",async()=>{
  const f=dbFixture();
  try{
    await seedProject(f.db);
    const wf=await workflowCreate(f.db,owner,{project:"williams",name:"tamper-check",idempotency_key:"tamper-check-1",steps:[{key:"hash",operation:"sha256_verify",input:{text:"abc",expected_sha256:"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}}]});
    await workflowStart(f.db,owner,{project:"williams",workflow_id:wf.workflow_id});
    await runWorkflowBatch(f.db,owner,1,fetch,Date.now());
    f.raw.prepare("UPDATE eg_workflow_steps SET result=? WHERE workflow_id=? AND step_key='hash'").run(JSON.stringify({verified:true,sha256:"tampered"}),wf.workflow_id);
    const final=await executionFinalize(f.db,owner,{project:"williams",workflow_id:wf.workflow_id});
    assert.equal(final.verified,false);
  }finally{f.close()}
});

test("exhausted lease reconciles a stranded workflow without another runnable step",async()=>{
  const f=dbFixture();
  try{
    await seedProject(f.db);
    const w=await workflowCreate(f.db,owner,{project:"williams",name:"exhausted",idempotency_key:"exhausted-lease-1",steps:[{key:"health",operation:"health_probe",input:{},max_attempts:1}]});
    await workflowStart(f.db,owner,{project:"williams",workflow_id:w.workflow_id});
    const now=Date.now();
    f.raw.prepare("UPDATE eg_workflow_steps SET state='RUNNING',attempts=1,lease_id='dead',lease_until=? WHERE workflow_id=?").run(now-1,w.workflow_id);
    assert.equal((await runWorkflowBatch(f.db,owner,1,fetch,now)).executed,0);
    const s=await workflowStatus(f.db,owner,{project:"williams",workflow_id:w.workflow_id});
    assert.equal(s.workflow.state,"FAILED");
    assert.equal(s.steps[0].state,"FAILED");
    assert.equal(s.steps[0].attempts,1);
    assert.equal((await workflowRetry(f.db,owner,{project:"williams",workflow_id:w.workflow_id})).status,"needs_approval");
  }finally{f.close()}
});
test("crash after final step commit reconciles parent on next Cron",async()=>{
  const f=dbFixture();
  try{
    await seedProbe(f.raw);await seedProject(f.db);
    const w=await workflowCreate(f.db,owner,{project:"williams",name:"parent-recovery",idempotency_key:"parent-recovery-1",steps:[{key:"health",operation:"health_probe",input:{}}]});
    await workflowStart(f.db,owner,{project:"williams",workflow_id:w.workflow_id});
    await runWorkflowBatch(f.db,owner,1,fetch,Date.now());
    f.raw.prepare("UPDATE eg_workflows SET state='RUNNING',finished_at=NULL WHERE id=?").run(w.workflow_id);
    assert.equal((await runWorkflowBatch(f.db,owner,1,fetch,Date.now())).executed,0);
    const s=await workflowStatus(f.db,owner,{project:"williams",workflow_id:w.workflow_id});
    assert.equal(s.workflow.state,"SUCCEEDED");
    assert.equal(s.steps[0].attempts,1);
    assert.equal((await executionFinalize(f.db,owner,{project:"williams",workflow_id:w.workflow_id})).verified,true);
  }finally{f.close()}
});
test("expired cancelled lease never requeues a step",async()=>{
  const f=dbFixture();
  try{
    await seedProject(f.db);
    const w=await workflowCreate(f.db,owner,{project:"williams",name:"cancel-crash",idempotency_key:"cancel-crash-1",steps:[{key:"health",operation:"health_probe",input:{}}]});
    await workflowStart(f.db,owner,{project:"williams",workflow_id:w.workflow_id});
    const now=Date.now();
    f.raw.prepare("UPDATE eg_workflow_steps SET state='RUNNING',attempts=1,lease_id='dead',lease_until=? WHERE workflow_id=?").run(now-1,w.workflow_id);
    await workflowCancel(f.db,owner,{project:"williams",workflow_id:w.workflow_id});
    await runWorkflowBatch(f.db,owner,1,fetch,now);
    const s=await workflowStatus(f.db,owner,{project:"williams",workflow_id:w.workflow_id});
    assert.equal(s.workflow.state,"CANCELLED");assert.equal(s.steps[0].state,"CANCELLED");assert.equal(s.steps[0].attempts,1);
  }finally{f.close()}
});
test("resume settles already completed last step instead of remaining queued",async()=>{
  const f=dbFixture();
  try{
    await seedProject(f.db);
    const w=await workflowCreate(f.db,owner,{project:"williams",name:"pause-final",idempotency_key:"pause-final-1",steps:[{key:"repo",operation:"github_repository_status",input:{owner:"octo",repo:"repo"}}]});
    const args={project:"williams",workflow_id:w.workflow_id};
    await workflowStart(f.db,owner,args);
    const fetcher=async()=>{await workflowPause(f.db,owner,args);return new Response(JSON.stringify({id:7,full_name:"octo/repo",default_branch:"main"}),{status:200})};
    await runWorkflowBatch(f.db,owner,1,fetcher,Date.now());
    assert.equal((await workflowStatus(f.db,owner,args)).workflow.state,"PAUSED");
    assert.equal((await workflowResume(f.db,owner,args)).state,"SUCCEEDED");
    assert.equal((await executionFinalize(f.db,owner,args)).verified,true);
  }finally{f.close()}
});

test("fixed qualification DAG resolves branch SHA, checks exact Actions runs, verifies snapshot and writes one dedicated checkpoint",async()=>{
  const f=dbFixture();const project="eg-qualification-test",sha="a".repeat(40);
  try{
    seedProbe(f.raw);await seedProject(f.db,project);
    const steps=[
      {key:"health",operation:"health_probe",input:{}},
      {key:"repo",operation:"github_repository_status",input:{owner:"19wolfalone92",repo:"Execution-Guard"}},
      {key:"head",operation:"github_branch_head",input:{owner:"19wolfalone92",repo:"Execution-Guard",branch:"audit/oauth-e2e-20261125"},depends_on:["repo"]},
      {key:"ci",operation:"github_actions_for_branch",input:{branch_step:"head"},depends_on:["head"]},
      {key:"collect",operation:"qualification_collect",depends_on:["health","repo","head","ci"]},
      {key:"verify",operation:"qualification_verify",depends_on:["collect"]},
      {key:"save",operation:"qualification_checkpoint",depends_on:["verify"]}
    ];
    const def={project,name:"release proof",idempotency_key:"release-proof-test",steps};
    const w=await workflowCreate(f.db,owner,def);assert.equal(w.status,"created");
    assert.equal((await workflowCreate(f.db,owner,def)).workflow_id,w.workflow_id);
    assert.equal((await workflowCreate(f.db,owner,{...def,idempotency_key:"wrong-dependency",steps:steps.map(s=>s.key==="save"?{...s,depends_on:["collect"]}:s)})).error,"invalid_workflow_definition");
    const calls=[];
    const fetcher=async url=>{calls.push(url);const data=url.includes("/git/ref/")?{ref:"refs/heads/audit/oauth-e2e-20261125",object:{type:"commit",sha}}:url.includes("/actions/runs?")?{total_count:3,workflow_runs:["Qualification","OAuth and MCP runtime qualification","Exact Preview HTTP and isolation qualification"].map((name,i)=>({id:i+1,name,head_sha:sha,status:"completed",conclusion:"success"}))}:{id:7,full_name:"19wolfalone92/Execution-Guard",default_branch:"main",private:false};return new Response(JSON.stringify(data),{status:200})};
    await workflowStart(f.db,owner,{project,workflow_id:w.workflow_id});
    await runWorkflowBatch(f.db,owner,8,fetcher,Date.now());
    const result=await workflowStatus(f.db,owner,{project,workflow_id:w.workflow_id});
    assert.equal(result.workflow.state,"SUCCEEDED");
    assert.equal(result.steps.length,7);assert.ok(result.steps.every(s=>s.attempts===1&&s.evidence.verified));
    assert.ok(calls.some(x=>x.includes("head_sha="+sha)));
    const saved=result.steps.find(s=>s.key==="save").result;
    const row=f.raw.prepare("SELECT revision,value FROM eg_checkpoints WHERE owner=? AND project=?").get(owner,saved.checkpoint);
    assert.equal(row.revision,1);assert.equal(JSON.parse(row.value).snapshot.sha,sha);
    assert.equal(JSON.parse(row.value).sha256,saved.sha256);
    assert.equal((await executionFinalize(f.db,owner,{project,workflow_id:w.workflow_id})).verified,true);
    await runWorkflowBatch(f.db,owner,8,fetcher,Date.now());
    assert.equal(f.raw.prepare("SELECT COUNT(*) AS n FROM eg_checkpoints").get().n,1);
    f.raw.prepare("UPDATE eg_checkpoints SET value='tampered' WHERE project=?").run(saved.checkpoint);
    assert.equal((await executionFinalize(f.db,owner,{project,workflow_id:w.workflow_id})).verified,false);
  }finally{f.close()}
});
