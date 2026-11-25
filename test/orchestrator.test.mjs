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
