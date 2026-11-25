import { createHash } from "node:crypto";

const projectPattern = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const workflowIdPattern = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const stepKeyPattern = /^[a-z0-9][a-z0-9_-]{0,31}$/;
const idempotencyPattern = /^[A-Za-z0-9_-]{8,64}$/;
const repoPartPattern = /^(?!\.{1,2}$)[A-Za-z0-9_.-]{1,100}$/;
const shaPattern = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/;
const secretKeyPattern = /(?:token|secret|password|credential|private.?key|authorization|cookie)/i;
const projectFields = new Set(["goal","rules","repository","branch","commit","pull_request","stage","completed","pending","errors","tests","limitations","next_action","evidence"]);
const operations = new Set(["health_probe","sha256_verify","github_repository_status","github_commit_status","github_workflow_status","github_branch_head","github_actions_for_branch","qualification_collect","qualification_verify","qualification_checkpoint"]);
const nowIso = () => new Date().toISOString();
const bytes = value => new TextEncoder().encode(value).length;
const isObject = value => value !== null && typeof value === "object" && !Array.isArray(value);
const allKeys = (value, keys) => isObject(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value,key));
const schemaReady = new WeakSet();

async function ensureSchema(db) {
  if (schemaReady.has(db)) return;
  const statements = [
    "CREATE TABLE IF NOT EXISTS eg_projects (owner TEXT NOT NULL, project TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision > 0), value TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY(owner,project))",
    "CREATE TABLE IF NOT EXISTS eg_project_history (owner TEXT NOT NULL, project TEXT NOT NULL, revision INTEGER NOT NULL, value TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY(owner,project,revision))",
    "CREATE TABLE IF NOT EXISTS eg_workflows (id TEXT PRIMARY KEY, owner TEXT NOT NULL, project TEXT NOT NULL, name TEXT NOT NULL, idempotency_key TEXT NOT NULL, definition_hash TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('CREATED','QUEUED','BLOCKED','RUNNING','RETRYING','VERIFYING','SUCCEEDED','FAILED','CANCELLED','PAUSED','NEEDS_APPROVAL')), created_at TEXT NOT NULL, updated_at TEXT NOT NULL, finished_at TEXT, error_code TEXT, UNIQUE(owner,project,idempotency_key))",
    "CREATE INDEX IF NOT EXISTS eg_workflows_owner_project ON eg_workflows(owner,project,created_at)",
    "CREATE TABLE IF NOT EXISTS eg_workflow_steps (id TEXT PRIMARY KEY, workflow_id TEXT NOT NULL, owner TEXT NOT NULL, project TEXT NOT NULL, step_key TEXT NOT NULL, operation TEXT NOT NULL, input TEXT NOT NULL, depends_on TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('CREATED','QUEUED','BLOCKED','RUNNING','RETRYING','VERIFYING','SUCCEEDED','FAILED','CANCELLED','PAUSED','NEEDS_APPROVAL')), attempts INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL, timeout_ms INTEGER NOT NULL, available_at INTEGER NOT NULL, lease_id TEXT, lease_until INTEGER, result TEXT, evidence TEXT, error_code TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(workflow_id,step_key))",
    "CREATE INDEX IF NOT EXISTS eg_workflow_steps_dispatch ON eg_workflow_steps(state,available_at,lease_until)",
    "CREATE TABLE IF NOT EXISTS eg_execution_audit (id TEXT PRIMARY KEY, owner TEXT NOT NULL, project TEXT NOT NULL, workflow_id TEXT, event TEXT NOT NULL, details TEXT NOT NULL, created_at TEXT NOT NULL)",
    "CREATE INDEX IF NOT EXISTS eg_execution_audit_project ON eg_execution_audit(owner,project,created_at)"
  ];
  for (const sql of statements) await db.prepare(sql).run();
  schemaReady.add(db);
}

function scanForSecrets(value, depth = 0) {
  if (depth > 8) return false;
  if (Array.isArray(value)) return value.every(item => scanForSecrets(item,depth+1));
  if (typeof value === "string") return !/(?:gh[pousr]_[A-Za-z0-9_]{20,}|Bearer\s+[A-Za-z0-9._~-]{20,}|sk-[A-Za-z0-9]{20,})/.test(value);
  if (!isObject(value)) return true;
  for (const [key,item] of Object.entries(value)) {
    if (secretKeyPattern.test(key) || !scanForSecrets(item,depth+1)) return false;
  }
  return true;
}

function validateRecord(record) {
  if (!isObject(record) || Object.keys(record).some(key => !projectFields.has(key))) return null;
  if (!scanForSecrets(record)) return null;
  const textField = (key,max) => record[key] === undefined || (typeof record[key] === "string" && bytes(record[key]) <= max);
  const stringArray = (key,maxItems,maxBytes) => record[key] === undefined || (Array.isArray(record[key]) && record[key].length <= maxItems && record[key].every(item => typeof item === "string" && bytes(item) <= maxBytes));
  if (!textField("goal",2000) || !textField("branch",255) || !textField("commit",64) || !textField("stage",200) || !textField("next_action",2000)) return null;
  if (record.pull_request !== undefined && (!Number.isSafeInteger(record.pull_request) || record.pull_request < 1)) return null;
  if (!stringArray("rules",50,1000) || !stringArray("completed",100,500) || !stringArray("pending",100,500) || !stringArray("errors",100,1000) || !stringArray("limitations",100,1000)) return null;
  if (record.repository !== undefined && (!isObject(record.repository) || !allKeys(record.repository,["owner","repo"]) || !repoPartPattern.test(record.repository.owner) || !repoPartPattern.test(record.repository.repo))) return null;
  if (record.tests !== undefined && !isObject(record.tests)) return null;
  if (record.evidence !== undefined && (!Array.isArray(record.evidence) || record.evidence.length > 100 || record.evidence.some(item => !isObject(item)))) return null;
  let serialized;
  try { serialized = JSON.stringify(record); } catch { return null; }
  if (bytes(serialized) > 8192) return null;
  return serialized;
}

async function audit(db, owner, project, event, details = {}, workflowId = null) {
  const serialized = JSON.stringify(details);
  if (bytes(serialized) > 2048 || !scanForSecrets(details)) return;
  await db.prepare("INSERT INTO eg_execution_audit(id,owner,project,workflow_id,event,details,created_at) VALUES(?,?,?,?,?,?,?)")
    .bind(crypto.randomUUID(),owner,project,workflowId,event,serialized,nowIso()).run();
  await db.prepare("DELETE FROM eg_execution_audit WHERE owner=? AND id IN (SELECT id FROM eg_execution_audit WHERE owner=? ORDER BY created_at DESC LIMIT -1 OFFSET 10000)").bind(owner,owner).run();
}

function parseJson(value, fallback = null) {
  try { return JSON.parse(value); } catch { return fallback; }
}

export async function projectCreate(db, owner, args) {
  if (!allKeys(args,["project","record"]) || !projectPattern.test(args.project)) return {error:"invalid_arguments"};
  const value = validateRecord(args.record);
  if (value === null) return {error:"invalid_project_record"};
  await ensureSchema(db);
  const now = nowIso();
  const result = await db.batch([
    db.prepare("INSERT INTO eg_projects(owner,project,revision,value,created_at,updated_at) VALUES(?,?,1,?,?,?) ON CONFLICT(owner,project) DO NOTHING").bind(owner,args.project,value,now,now),
    db.prepare("INSERT INTO eg_project_history(owner,project,revision,value,updated_at) SELECT owner,project,revision,value,updated_at FROM eg_projects WHERE owner=? AND project=? AND revision=1 AND changes()=1").bind(owner,args.project),
    db.prepare("INSERT INTO eg_execution_audit(id,owner,project,event,details,created_at) SELECT ?,?,?,?, '{}',? WHERE changes()=1").bind(crypto.randomUUID(),owner,args.project,"project_created",now)
  ]);
  if (result[0]?.meta?.changes !== 1) return {error:"project_exists"};
  return {status:"created",project:args.project,revision:1,created_at:now};
}

export async function projectGet(db, owner, args) {
  if (!allKeys(args,["project"]) || !projectPattern.test(args.project)) return {error:"invalid_arguments"};
  await ensureSchema(db);
  const row = await db.prepare("SELECT revision,value,created_at,updated_at FROM eg_projects WHERE owner=? AND project=?").bind(owner,args.project).first();
  return row ? {project:args.project,found:true,revision:row.revision,record:parseJson(row.value,{}),created_at:row.created_at,updated_at:row.updated_at} : {project:args.project,found:false};
}

export async function projectUpdate(db, owner, args) {
  if (!allKeys(args,["project","expected_revision","patch"]) || !projectPattern.test(args.project) || !Number.isSafeInteger(args.expected_revision) || args.expected_revision < 1 || args.expected_revision > 2147483646 || !isObject(args.patch) || !Object.keys(args.patch).length) return {error:"invalid_arguments"};
  if (Object.keys(args.patch).some(key => !projectFields.has(key))) return {error:"invalid_project_record"};
  await ensureSchema(db);
  const current = await db.prepare("SELECT revision,value FROM eg_projects WHERE owner=? AND project=?").bind(owner,args.project).first();
  if (!current) return {error:"project_not_found"};
  if (current.revision !== args.expected_revision) return {error:"revision_conflict",current_revision:current.revision};
  const merged = {...parseJson(current.value,{}),...args.patch};
  const value = validateRecord(merged);
  if (value === null) return {error:"invalid_project_record"};
  const now = nowIso();
  const result = await db.batch([
    db.prepare("UPDATE eg_projects SET revision=revision+1,value=?,updated_at=? WHERE owner=? AND project=? AND revision=?").bind(value,now,owner,args.project,args.expected_revision),
    db.prepare("INSERT INTO eg_project_history(owner,project,revision,value,updated_at) SELECT owner,project,revision,value,updated_at FROM eg_projects WHERE owner=? AND project=? AND revision=? AND changes()=1").bind(owner,args.project,args.expected_revision+1),
    db.prepare("INSERT INTO eg_execution_audit(id,owner,project,event,details,created_at) SELECT ?,?,?,?, '{}',? WHERE changes()=1").bind(crypto.randomUUID(),owner,args.project,"project_updated",now),
    db.prepare("DELETE FROM eg_project_history WHERE owner=? AND project=? AND revision <= (SELECT MAX(revision)-100 FROM eg_project_history WHERE owner=? AND project=?) AND changes()=1").bind(owner,args.project,owner,args.project)
  ]);
  if (result[0]?.meta?.changes !== 1) {
    const latest = await db.prepare("SELECT revision FROM eg_projects WHERE owner=? AND project=?").bind(owner,args.project).first();
    return {error:"revision_conflict",current_revision:latest?.revision ?? null};
  }
  return {status:"saved",project:args.project,revision:args.expected_revision+1,updated_at:now};
}

export async function projectHistory(db, owner, args) {
  if (!allKeys(args,["project","limit"]) || !projectPattern.test(args.project) || !Number.isInteger(args.limit) || args.limit < 1 || args.limit > 50) return {error:"invalid_arguments"};
  await ensureSchema(db);
  const rows = await db.prepare("SELECT revision,value,updated_at FROM eg_project_history WHERE owner=? AND project=? ORDER BY revision DESC LIMIT ?").bind(owner,args.project,args.limit).all();
  return {project:args.project,history:(rows.results||[]).map(row=>({revision:row.revision,record:parseJson(row.value,{}),updated_at:row.updated_at}))};
}

export async function projectResume(db, owner, args) {
  const current = await projectGet(db,owner,args);
  if (!current.found) return current;
  return {...current,reconcile_required:Boolean(current.record.repository),resume_ready:true};
}

function validateGithubInput(operation, input) {
  if (!isObject(input)) return false;
  if (operation === "health_probe") return Object.keys(input).length === 0;
  if (operation === "sha256_verify") return allKeys(input,["text","expected_sha256"]) && typeof input.text === "string" && bytes(input.text) <= 4096 && scanForSecrets(input.text) && /^[a-f0-9]{64}$/.test(input.expected_sha256);
  if (operation === "github_repository_status") return allKeys(input,["owner","repo"]) && repoPartPattern.test(input.owner) && repoPartPattern.test(input.repo);
  if (operation === "github_commit_status") return allKeys(input,["owner","repo","sha"]) && repoPartPattern.test(input.owner) && repoPartPattern.test(input.repo) && shaPattern.test(input.sha);
  if (operation === "github_workflow_status") return allKeys(input,["owner","repo","run_id"]) && repoPartPattern.test(input.owner) && repoPartPattern.test(input.repo) && Number.isSafeInteger(input.run_id) && input.run_id > 0;
  if (operation==="github_branch_head") return allKeys(input,["owner","repo","branch"])&&repoPartPattern.test(input.owner)&&repoPartPattern.test(input.repo)&&typeof input.branch==="string"&&/^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/.test(input.branch)&&!input.branch.includes("..");
  if (operation==="github_actions_for_branch") return allKeys(input,["branch_step"])&&typeof input.branch_step==="string"&&stepKeyPattern.test(input.branch_step);
  if (["qualification_collect","qualification_verify","qualification_checkpoint"].includes(operation)) return Object.keys(input).length===0;
  return false;
}

const qualificationOps=new Set(["github_branch_head","github_actions_for_branch","qualification_collect","qualification_verify","qualification_checkpoint"]);
const requiredCI=["Qualification","OAuth and MCP runtime qualification","Exact Preview HTTP and isolation qualification"];
function validateQualification(steps,project){
  if(!steps.some(s=>qualificationOps.has(s.operation)))return true;
  // This release acceptance workflow is deliberately fixed and scoped to a
  // dedicated project. It is not a general-purpose write or expression engine.
  if(!project.startsWith("eg-qualification-")||steps.length!==7)return false;
  const m=new Map(steps.map(s=>[s.operation,s]));
  if(m.size!==7||!["health_probe","github_repository_status",...qualificationOps].every(x=>m.has(x)))return false;
  const health=m.get("health_probe"),repo=m.get("github_repository_status"),head=m.get("github_branch_head"),ci=m.get("github_actions_for_branch"),collect=m.get("qualification_collect"),verify=m.get("qualification_verify"),save=m.get("qualification_checkpoint");
  const deps=(s,keys)=>s.depends_on.length===keys.length&&keys.every(k=>s.depends_on.includes(k));
  const target=x=>x.owner==="19wolfalone92"&&x.repo==="Execution-Guard";
  return target(repo.input)&&target(head.input)&&head.input.branch==="audit/oauth-e2e-20261125"&&ci.input.branch_step===head.key&&
    deps(health,[])&&deps(repo,[])&&deps(head,[repo.key])&&deps(ci,[head.key])&&deps(collect,[health.key,repo.key,head.key,ci.key])&&deps(verify,[collect.key])&&deps(save,[verify.key]);
}

function validateSteps(steps) {
  if (!Array.isArray(steps) || steps.length < 1 || steps.length > 32) return null;
  const keys = new Set();
  const normalized = [];
  for (const step of steps) {
    if (!isObject(step) || Object.keys(step).some(key => !["key","operation","input","depends_on","max_attempts","timeout_ms"].includes(key))) return null;
    if (typeof step.key !== "string" || !stepKeyPattern.test(step.key) || keys.has(step.key) || !operations.has(step.operation)) return null;
    const input = step.input ?? {};
    if (!validateGithubInput(step.operation,input)) return null;
    const depends = step.depends_on ?? [];
    const maxAttempts = step.max_attempts ?? 3;
    const timeoutMs = step.timeout_ms ?? 15000;
    if (!Array.isArray(depends) || depends.some(x=>typeof x!=="string"||!stepKeyPattern.test(x)) || new Set(depends).size !== depends.length) return null;
    if (!Number.isInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > 5 || !Number.isInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 30000) return null;
    keys.add(step.key);
    normalized.push({key:step.key,operation:step.operation,input,depends_on:depends,max_attempts:maxAttempts,timeout_ms:timeoutMs});
  }
  const byKey = new Map(normalized.map(step=>[step.key,step]));
  for (const step of normalized) if (step.depends_on.some(dep=>!byKey.has(dep) || dep===step.key)) return null;
  const visiting = new Set(), visited = new Set();
  function visit(key) {
    if (visiting.has(key)) return false;
    if (visited.has(key)) return true;
    visiting.add(key);
    for (const dep of byKey.get(key).depends_on) if (!visit(dep)) return false;
    visiting.delete(key); visited.add(key); return true;
  }
  for (const key of keys) if (!visit(key)) return null;
  return normalized;
}

export async function workflowCreate(db, owner, args) {
  if (!allKeys(args,["project","name","idempotency_key","steps"]) || !projectPattern.test(args.project) || typeof args.name!=="string" || !args.name.trim() || bytes(args.name)>160 || typeof args.idempotency_key!=="string" || !idempotencyPattern.test(args.idempotency_key)) return {error:"invalid_arguments"};
  const steps = validateSteps(args.steps);
  if (!steps||!validateQualification(steps,args.project)) return {error:"invalid_workflow_definition"};
  await ensureSchema(db);
  const project = await db.prepare("SELECT project FROM eg_projects WHERE owner=? AND project=?").bind(owner,args.project).first();
  if (!project) return {error:"project_not_found"};
  const id = crypto.randomUUID(), now = nowIso(), name=args.name.trim();
  const definition=JSON.stringify({name,steps});
  const definitionHash=createHash("sha256").update(definition,"utf8").digest("hex");
  const statements = [
    db.prepare("INSERT INTO eg_workflows(id,owner,project,name,idempotency_key,definition_hash,state,created_at,updated_at) SELECT ?,?,?,?,?,?,'CREATED',?,? WHERE (SELECT COUNT(*) FROM eg_workflows WHERE owner=?)<5000 AND (SELECT COUNT(*) FROM eg_workflows WHERE owner=? AND state NOT IN ('SUCCEEDED','FAILED','CANCELLED'))<100 ON CONFLICT(owner,project,idempotency_key) DO NOTHING")
      .bind(id,owner,args.project,name,args.idempotency_key,definitionHash,now,now,owner,owner)
  ];
  for (const step of steps) statements.push(db.prepare("INSERT INTO eg_workflow_steps(id,workflow_id,owner,project,step_key,operation,input,depends_on,state,attempts,max_attempts,timeout_ms,available_at,created_at,updated_at) SELECT ?,?,?,?,?,?,?,?,'CREATED',0,?,?,0,?,? WHERE EXISTS(SELECT 1 FROM eg_workflows WHERE id=? AND definition_hash=?)")
    .bind(crypto.randomUUID(),id,owner,args.project,step.key,step.operation,JSON.stringify(step.input),JSON.stringify(step.depends_on),step.max_attempts,step.timeout_ms,now,now,id,definitionHash));
  statements.push(db.prepare("INSERT INTO eg_execution_audit(id,owner,project,workflow_id,event,details,created_at) SELECT ?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM eg_workflows WHERE id=?)")
    .bind(crypto.randomUUID(),owner,args.project,id,"workflow_created",JSON.stringify({steps:steps.length}),now,id));
  await db.batch(statements);
  const existing=await db.prepare("SELECT id,state,definition_hash FROM eg_workflows WHERE owner=? AND project=? AND idempotency_key=?").bind(owner,args.project,args.idempotency_key).first();
  if(!existing)return {error:"workflow_capacity"};
  if(existing.definition_hash!==definitionHash)return {error:"idempotency_conflict"};
  if(existing.id!==id)return {status:"existing",workflow_id:existing.id,project:args.project,state:existing.state,deduplicated:true};
  return {status:"created",workflow_id:id,project:args.project,state:"CREATED",steps:steps.length,created_at:now,deduplicated:false};
}

async function loadWorkflow(db, owner, project, id) {
  return db.prepare("SELECT * FROM eg_workflows WHERE owner=? AND project=? AND id=?").bind(owner,project,id).first();
}
async function loadSteps(db, owner, project, id) {
  const rows = await db.prepare("SELECT * FROM eg_workflow_steps WHERE owner=? AND project=? AND workflow_id=? ORDER BY created_at,step_key").bind(owner,project,id).all();
  return rows.results || [];
}

export async function workflowStart(db, owner, args) {
  if (!allKeys(args,["project","workflow_id"]) || !projectPattern.test(args.project) || !workflowIdPattern.test(args.workflow_id)) return {error:"invalid_arguments"};
  await ensureSchema(db);
  const now=nowIso();
  const result=await db.batch([
    db.prepare("UPDATE eg_workflows SET state='QUEUED',updated_at=? WHERE owner=? AND project=? AND id=? AND state='CREATED'").bind(now,owner,args.project,args.workflow_id),
    db.prepare("UPDATE eg_workflow_steps SET state=CASE WHEN depends_on='[]' THEN 'QUEUED' ELSE 'BLOCKED' END,updated_at=? WHERE owner=? AND project=? AND workflow_id=? AND state='CREATED' AND EXISTS(SELECT 1 FROM eg_workflows WHERE id=? AND state='QUEUED')").bind(now,owner,args.project,args.workflow_id,args.workflow_id)
  ]);
  if(result[0]?.meta?.changes!==1)return {error:"invalid_state_transition"};
  await audit(db,owner,args.project,"workflow_started",{},args.workflow_id);
  return {status:"started",workflow_id:args.workflow_id,state:"QUEUED"};
}

export async function workflowStatus(db, owner, args) {
  if (!allKeys(args,["project","workflow_id"]) || !projectPattern.test(args.project) || !workflowIdPattern.test(args.workflow_id)) return {error:"invalid_arguments"};
  await ensureSchema(db);
  const workflow=await loadWorkflow(db,owner,args.project,args.workflow_id);
  if(!workflow)return {found:false};
  const steps=await loadSteps(db,owner,args.project,args.workflow_id);
  return {found:true,workflow:{id:workflow.id,project:workflow.project,name:workflow.name,state:workflow.state,created_at:workflow.created_at,updated_at:workflow.updated_at,finished_at:workflow.finished_at,error_code:workflow.error_code},steps:steps.map(step=>({id:step.id,key:step.step_key,operation:step.operation,depends_on:parseJson(step.depends_on,[]),state:step.state,attempts:step.attempts,max_attempts:step.max_attempts,created_at:step.created_at,updated_at:step.updated_at,result:parseJson(step.result),evidence:parseJson(step.evidence),error_code:step.error_code}))};
}

export async function workflowDependenciesGet(db, owner, args) {
  const status=await workflowStatus(db,owner,args);
  if(!status.found)return status;
  const dependents={};
  for(const step of status.steps)dependents[step.key]=[];
  for(const step of status.steps)for(const dep of step.depends_on)dependents[dep]?.push(step.key);
  return {workflow_id:args.workflow_id,dependencies:status.steps.map(step=>({key:step.key,depends_on:step.depends_on,dependents:dependents[step.key]}))};
}

export async function workflowPause(db, owner, args) {
  if (!allKeys(args,["project","workflow_id"]) || !projectPattern.test(args.project) || !workflowIdPattern.test(args.workflow_id)) return {error:"invalid_arguments"};
  await ensureSchema(db);
  const now=nowIso();
  const result=await db.batch([
    db.prepare("UPDATE eg_workflows SET state='PAUSED',updated_at=? WHERE owner=? AND project=? AND id=? AND state IN ('QUEUED','RUNNING','RETRYING','BLOCKED')").bind(now,owner,args.project,args.workflow_id),
    db.prepare("UPDATE eg_workflow_steps SET state='PAUSED',updated_at=? WHERE owner=? AND project=? AND workflow_id=? AND state IN ('QUEUED','BLOCKED','RETRYING') AND EXISTS(SELECT 1 FROM eg_workflows WHERE id=? AND state='PAUSED')").bind(now,owner,args.project,args.workflow_id,args.workflow_id)
  ]);
  if(result[0]?.meta?.changes!==1)return {error:"invalid_state_transition"};
  await audit(db,owner,args.project,"workflow_paused",{},args.workflow_id);
  return {status:"paused",workflow_id:args.workflow_id};
}

export async function workflowResume(db, owner, args) {
  if (!allKeys(args,["project","workflow_id"]) || !projectPattern.test(args.project) || !workflowIdPattern.test(args.workflow_id)) return {error:"invalid_arguments"};
  await ensureSchema(db);
  const workflow=await loadWorkflow(db,owner,args.project,args.workflow_id);
  if(!workflow || workflow.state!=="PAUSED")return {error:"invalid_state_transition"};
  const steps=await loadSteps(db,owner,args.project,args.workflow_id);
  const byKey=new Map(steps.map(step=>[step.step_key,step]));
  for(const step of steps)if(step.state==="PAUSED"&&step.depends_on!=="[]"){
    const deps=parseJson(step.depends_on,[]);
    if(deps.some(dep=>byKey.get(dep)?.state==="FAILED"||byKey.get(dep)?.state==="CANCELLED"))return {error:"dependency_failed"};
  }
  const now=nowIso(), statements=[db.prepare("UPDATE eg_workflows SET state='QUEUED',updated_at=? WHERE owner=? AND project=? AND id=? AND state='PAUSED'").bind(now,owner,args.project,args.workflow_id)];
  for(const step of steps)if(step.state==="PAUSED"){
    const deps=parseJson(step.depends_on,[]);
    const ready=deps.every(dep=>byKey.get(dep)?.state==="SUCCEEDED");
    statements.push(db.prepare("UPDATE eg_workflow_steps SET state=?,error_code=NULL,updated_at=? WHERE owner=? AND project=? AND workflow_id=? AND step_key=? AND state='PAUSED' AND EXISTS(SELECT 1 FROM eg_workflows WHERE id=? AND state='QUEUED')").bind(ready?"QUEUED":"BLOCKED",now,owner,args.project,args.workflow_id,step.step_key,args.workflow_id));
  }
  const result=await db.batch(statements);
  if(result[0]?.meta?.changes!==1)return {error:"invalid_state_transition"};
  await audit(db,owner,args.project,"workflow_resumed",{},args.workflow_id);
  await refreshWorkflowState(db,owner,args.project,args.workflow_id);
  const resumed=await loadWorkflow(db,owner,args.project,args.workflow_id);
  return {status:"resumed",workflow_id:args.workflow_id,state:resumed.state};
}

export async function workflowCancel(db, owner, args) {
  if (!allKeys(args,["project","workflow_id"]) || !projectPattern.test(args.project) || !workflowIdPattern.test(args.workflow_id)) return {error:"invalid_arguments"};
  await ensureSchema(db);
  const now=nowIso();
  const result=await db.batch([
    db.prepare("UPDATE eg_workflows SET state='CANCELLED',updated_at=?,finished_at=? WHERE owner=? AND project=? AND id=? AND state NOT IN ('SUCCEEDED','FAILED','CANCELLED')").bind(now,now,owner,args.project,args.workflow_id),
    db.prepare("UPDATE eg_workflow_steps SET state='CANCELLED',lease_id=NULL,lease_until=NULL,updated_at=? WHERE owner=? AND project=? AND workflow_id=? AND state IN ('CREATED','QUEUED','BLOCKED','RETRYING','VERIFYING','PAUSED') AND EXISTS(SELECT 1 FROM eg_workflows WHERE id=? AND state='CANCELLED')").bind(now,owner,args.project,args.workflow_id,args.workflow_id)
  ]);
  if(result[0]?.meta?.changes!==1)return {error:"invalid_state_transition"};
  await audit(db,owner,args.project,"workflow_cancelled",{},args.workflow_id);
  return {status:"cancelled",workflow_id:args.workflow_id};
}

export async function workflowRetry(db, owner, args) {
  if (!allKeys(args,["project","workflow_id"]) || !projectPattern.test(args.project) || !workflowIdPattern.test(args.workflow_id)) return {error:"invalid_arguments"};
  await ensureSchema(db);
  const workflow=await loadWorkflow(db,owner,args.project,args.workflow_id);
  if(!workflow || !["FAILED","NEEDS_APPROVAL"].includes(workflow.state))return {error:"invalid_state_transition"};
  const steps=await loadSteps(db,owner,args.project,args.workflow_id);
  const failed=steps.filter(step=>step.state==="FAILED");
  if(!failed.length)return {error:"no_failed_steps"};
  if(workflow.state==="FAILED"&&failed.some(step=>step.attempts>=step.max_attempts)){
    await db.prepare("UPDATE eg_workflows SET state='NEEDS_APPROVAL',updated_at=? WHERE owner=? AND project=? AND id=? AND state='FAILED'").bind(nowIso(),owner,args.project,args.workflow_id).run();
    await audit(db,owner,args.project,"workflow_needs_approval",{failed_steps:failed.map(x=>x.step_key)},args.workflow_id);
    return {status:"needs_approval",workflow_id:args.workflow_id,reason:"attempt_limit_reached"};
  }
  const now=nowIso(),statements=[db.prepare("UPDATE eg_workflows SET state='QUEUED',updated_at=?,finished_at=NULL,error_code=NULL WHERE owner=? AND project=? AND id=? AND state IN ('FAILED','NEEDS_APPROVAL')").bind(now,owner,args.project,args.workflow_id)];
  for(const step of failed)statements.push(db.prepare("UPDATE eg_workflow_steps SET state='QUEUED',attempts=CASE WHEN ?=1 THEN 0 ELSE attempts END,available_at=0,lease_id=NULL,lease_until=NULL,error_code=NULL,updated_at=? WHERE owner=? AND project=? AND workflow_id=? AND step_key=? AND state='FAILED' AND EXISTS(SELECT 1 FROM eg_workflows WHERE id=? AND state='QUEUED')").bind(workflow.state==="NEEDS_APPROVAL"?1:0,now,owner,args.project,args.workflow_id,step.step_key,args.workflow_id));
  const result=await db.batch(statements);
  if(result[0]?.meta?.changes!==1)return {error:"invalid_state_transition"};
  await audit(db,owner,args.project,"workflow_retry_approved",{steps:failed.map(x=>x.step_key)},args.workflow_id);
  return {status:"retrying",workflow_id:args.workflow_id,state:"QUEUED",steps:failed.map(x=>x.step_key)};
}

export async function taskEvidenceGet(db, owner, args) {
  if (!allKeys(args,["project","workflow_id","step_key"]) || !projectPattern.test(args.project) || !workflowIdPattern.test(args.workflow_id) || !stepKeyPattern.test(args.step_key)) return {error:"invalid_arguments"};
  await ensureSchema(db);
  const row=await db.prepare("SELECT operation,result,evidence,state,error_code FROM eg_workflow_steps WHERE owner=? AND project=? AND workflow_id=? AND step_key=?").bind(owner,args.project,args.workflow_id,args.step_key).first();
  return row?{found:true,workflow_id:args.workflow_id,step_key:args.step_key,operation:row.operation,state:row.state,result:parseJson(row.result),evidence:parseJson(row.evidence),error_code:row.error_code}:{found:false};
}

export async function executionAudit(db, owner, args) {
  if(!allKeys(args,["project","limit"])||!projectPattern.test(args.project)||!Number.isInteger(args.limit)||args.limit<1||args.limit>100)return {error:"invalid_arguments"};
  await ensureSchema(db);
  const rows=await db.prepare("SELECT event,workflow_id,details,created_at FROM eg_execution_audit WHERE owner=? AND project=? ORDER BY created_at DESC LIMIT ?").bind(owner,args.project,args.limit).all();
  return {project:args.project,events:(rows.results||[]).map(row=>({event:row.event,workflow_id:row.workflow_id,details:parseJson(row.details,{}),created_at:row.created_at}))};
}

export async function systemHealth(db, owner, args = {}) {
  if (!isObject(args) || Object.keys(args).length) return {error:"invalid_arguments"};
  try {
    await ensureSchema(db);
    const probe=await db.prepare("SELECT value FROM eg_probe WHERE id=1").first();
    const tasks=await db.prepare("SELECT COUNT(*) AS count FROM eg_tasks WHERE owner=?").bind(owner).first().catch(()=>({count:0}));
    const projects=await db.prepare("SELECT COUNT(*) AS count FROM eg_projects WHERE owner=?").bind(owner).first();
    const workflows=await db.prepare("SELECT COUNT(*) AS count FROM eg_workflows WHERE owner=?").bind(owner).first();
    return {status:probe?.value==="execution-guard-v030"?"online":"degraded",database:"online",persistence_probe:probe?.value==="execution-guard-v030"?"verified":"not_verified",projects:projects?.count??0,workflows:workflows?.count??0,tasks:tasks?.count??0};
  } catch { return {status:"degraded",database:"not_verified"}; }
}

class RetryableError extends Error {
  constructor(code, delayMs = 0) { super(code); this.code=code; this.delayMs=delayMs; }
}
function retryDelay(response) {
  const header=response?.headers?.get("Retry-After");
  if(!header)return 0;
  const seconds=Number(header);
  if(Number.isFinite(seconds)&&seconds>=0)return Math.min(seconds*1000,3600000);
  const date=Date.parse(header);
  return Number.isFinite(date)?Math.max(0,Math.min(date-Date.now(),3600000)):0;
}
async function githubJson(path, timeoutMs=15000, fetcher=fetch) {
  const url="https://api.github.com"+path;
  let response;
  try {
    response=await fetcher(url,{method:"GET",redirect:"manual",headers:{Accept:"application/vnd.github+json","User-Agent":"Execution-Guard","X-GitHub-Api-Version":"2022-11-28"},signal:AbortSignal.timeout(timeoutMs)});
  } catch(error) {
    throw new RetryableError(error?.name==="TimeoutError"?"github_timeout":"github_network_error");
  }
  if(response.status===429 || (response.status===403 && response.headers.get("X-RateLimit-Remaining")==="0"))throw new RetryableError("github_rate_limited",retryDelay(response));
  if(response.status>=500)throw new RetryableError("github_http_"+response.status,retryDelay(response));
  if(response.status>=300&&response.status<400)throw new Error("github_redirect_blocked");
  if(response.status===404)throw new Error("github_not_found_or_private");
  if(!response.ok)throw new Error("github_http_"+response.status);
  try{return await response.json();}catch{throw new Error("github_invalid_json");}
}

export async function githubRepositoryStatus(args, fetcher=fetch) {
  if(!allKeys(args,["owner","repo"])||!repoPartPattern.test(args.owner)||!repoPartPattern.test(args.repo))return {error:"invalid_arguments"};
  try {
    const data=await githubJson("/repos/"+encodeURIComponent(args.owner)+"/"+encodeURIComponent(args.repo),15000,fetcher);
    return {verified:typeof data.full_name==="string"&&data.full_name.toLowerCase()===(args.owner+"/"+args.repo).toLowerCase()&&typeof data.default_branch==="string",repository:{id:data.id,full_name:data.full_name,private:Boolean(data.private),archived:Boolean(data.archived),default_branch:data.default_branch,updated_at:data.updated_at},checked_at:nowIso(),source:"GitHub public REST API"};
  } catch(error) {return {error:error.code||error.message,retryable:error instanceof RetryableError};}
}

export async function githubCommitStatus(args, fetcher=fetch) {
  if(!allKeys(args,["owner","repo","sha"])||!repoPartPattern.test(args.owner)||!repoPartPattern.test(args.repo)||!shaPattern.test(args.sha))return {error:"invalid_arguments"};
  try {
    const data=await githubJson("/repos/"+encodeURIComponent(args.owner)+"/"+encodeURIComponent(args.repo)+"/commits/"+args.sha+"/status",15000,fetcher);
    return {verified:data.state==="success",state:data.state,total_count:data.total_count,statuses:(data.statuses||[]).slice(0,20).map(x=>({context:x.context,state:x.state,description:x.description,updated_at:x.updated_at})),sha:args.sha,checked_at:nowIso(),source:"GitHub public REST API"};
  } catch(error) {return {error:error.code||error.message,retryable:error instanceof RetryableError};}
}

export async function githubWorkflowStatus(args, fetcher=fetch) {
  if(!allKeys(args,["owner","repo","run_id"])||!repoPartPattern.test(args.owner)||!repoPartPattern.test(args.repo)||!Number.isSafeInteger(args.run_id)||args.run_id<1)return {error:"invalid_arguments"};
  try {
    const data=await githubJson("/repos/"+encodeURIComponent(args.owner)+"/"+encodeURIComponent(args.repo)+"/actions/runs/"+args.run_id,15000,fetcher);
    return {verified:data.status==="completed"&&data.conclusion==="success",status:data.status,conclusion:data.conclusion,run_id:data.id,run_number:data.run_number,head_sha:data.head_sha,html_url:data.html_url,updated_at:data.updated_at,checked_at:nowIso(),source:"GitHub public REST API"};
  } catch(error) {return {error:error.code||error.message,retryable:error instanceof RetryableError};}
}

const digestOf=text=>createHash("sha256").update(text,"utf8").digest("hex");
function checkedResult(row){
  if(row?.state!=="SUCCEEDED"||typeof row.result!=="string")throw new Error("dependency_not_verified");
  const result=parseJson(row.result),evidence=parseJson(row.evidence);
  if(result?.verified!==true||evidence?.verified!==true||digestOf(row.result)!==evidence.result_sha256)throw new Error("dependency_integrity_failed");
  return result;
}
function qualificationSnapshot(rows,workflowId){
  const get=op=>checkedResult(rows.find(r=>r.operation===op));
  const health=get("health_probe"),repo=get("github_repository_status"),head=get("github_branch_head"),ci=get("github_actions_for_branch");
  if(health.persistence_probe!=="verified"||repo.repository?.full_name?.toLowerCase()!=="19wolfalone92/execution-guard"||head.repository!=="19wolfalone92/Execution-Guard"||head.branch!=="audit/oauth-e2e-20261125"||ci.sha!==head.sha||ci.repository!==head.repository||!requiredCI.every(n=>ci.runs.some(r=>r.name===n&&r.status==="completed"&&r.conclusion==="success"))||ci.runs.some(r=>r.head_sha!==head.sha||r.status!=="completed"||r.conclusion!=="success"))throw new Error("qualification_semantic_mismatch");
  return {workflow_id:workflowId,health,repository:repo.repository,branch:head.branch,sha:head.sha,ci:ci.runs,observed_at:head.checked_at};
}
async function executeOperation(db, operation, input, timeoutMs, fetcher, context) {
  if(operation==="health_probe"){
    const row=await db.prepare("SELECT value FROM eg_probe WHERE id=1").first();
    return {verified:row?.value==="execution-guard-v030",database:"online",persistence_probe:row?.value==="execution-guard-v030"?"verified":"not_verified",checked_at:nowIso()};
  }
  if(operation==="sha256_verify"){
    const actual=createHash("sha256").update(input.text,"utf8").digest("hex");
    return {verified:actual===input.expected_sha256,sha256:actual,expected_sha256:input.expected_sha256,checked_at:nowIso()};
  }
  if(operation==="github_repository_status"){
    const data=await githubJson("/repos/"+encodeURIComponent(input.owner)+"/"+encodeURIComponent(input.repo),timeoutMs,fetcher);
    return {verified:typeof data.full_name==="string"&&data.full_name.toLowerCase()===(input.owner+"/"+input.repo).toLowerCase()&&typeof data.default_branch==="string",repository:{id:data.id,full_name:data.full_name,private:Boolean(data.private),archived:Boolean(data.archived),default_branch:data.default_branch,updated_at:data.updated_at},checked_at:nowIso()};
  }
  if(operation==="github_commit_status"){
    const data=await githubJson("/repos/"+encodeURIComponent(input.owner)+"/"+encodeURIComponent(input.repo)+"/commits/"+input.sha+"/status",timeoutMs,fetcher);
    return {verified:data.state==="success",state:data.state,total_count:data.total_count,sha:input.sha,checked_at:nowIso()};
  }
  if(operation==="github_workflow_status"){
    const data=await githubJson("/repos/"+encodeURIComponent(input.owner)+"/"+encodeURIComponent(input.repo)+"/actions/runs/"+input.run_id,timeoutMs,fetcher);
    if(data.status!=="completed")throw new RetryableError("github_workflow_in_progress",30000);
    return {verified:data.id===input.run_id&&data.conclusion==="success",status:data.status,conclusion:data.conclusion,run_id:data.id,head_sha:data.head_sha,html_url:data.html_url,checked_at:nowIso()};
  }
  if(operation==="github_branch_head"){
    const repository=input.owner+"/"+input.repo;
    const data=await githubJson("/repos/"+encodeURIComponent(input.owner)+"/"+encodeURIComponent(input.repo)+"/git/ref/heads/"+input.branch.split("/").map(encodeURIComponent).join("/"),timeoutMs,fetcher);
    return {verified:data.ref==="refs/heads/"+input.branch&&data.object?.type==="commit"&&/^[a-f0-9]{40}$/.test(data.object?.sha||""),repository,branch:input.branch,sha:data.object?.sha,checked_at:nowIso()};
  }
  if(qualificationOps.has(operation)){
    const {owner,project,claimed,lease}=context;
    const rows=await loadSteps(db,owner,project,claimed.workflow_id);
    const source=op=>checkedResult(rows.find(r=>r.operation===op));
    if(operation==="github_actions_for_branch"){
      const head=checkedResult(rows.find(r=>r.step_key===input.branch_step&&r.operation==="github_branch_head"));
      const data=await githubJson("/repos/"+head.repository+"/actions/runs?head_sha="+head.sha+"&per_page=100",timeoutMs,fetcher);
      if(!Array.isArray(data.workflow_runs)||!Number.isSafeInteger(data.total_count)||data.total_count>100)throw new Error("github_actions_incomplete");
      const runs=data.workflow_runs.filter(x=>requiredCI.includes(x.name)).map(x=>({id:x.id,name:x.name,head_sha:x.head_sha,status:x.status,conclusion:x.conclusion}));
      if(!requiredCI.every(n=>runs.some(x=>x.name===n))||runs.some(x=>x.status!=="completed"))throw new RetryableError("github_workflow_in_progress",30000);
      return {verified:runs.every(x=>Number.isSafeInteger(x.id)&&x.head_sha===head.sha&&x.conclusion==="success"),repository:head.repository,sha:head.sha,runs,checked_at:nowIso()};
    }
    if(operation==="qualification_collect"){
      const snapshot=qualificationSnapshot(rows,claimed.workflow_id),serialized=JSON.stringify(snapshot);
      if(bytes(serialized)>6000||!scanForSecrets(snapshot))throw new Error("qualification_result_invalid");
      return {verified:true,snapshot,sha256:digestOf(serialized),checked_at:nowIso()};
    }
    if(operation==="qualification_verify"){
      const collected=source("qualification_collect"),independent=qualificationSnapshot(rows,claimed.workflow_id);
      const serialized=JSON.stringify(independent),actual=digestOf(serialized);
      return {verified:JSON.stringify(collected.snapshot)===serialized&&collected.sha256===actual,sha256:actual,checked_at:nowIso()};
    }
    if(operation==="qualification_checkpoint"){
      const verified=source("qualification_verify"),collected=source("qualification_collect");
      const serialized=JSON.stringify({snapshot:collected.snapshot,sha256:verified.sha256});
      if(verified.sha256!==collected.sha256||digestOf(JSON.stringify(collected.snapshot))!==verified.sha256||bytes(serialized)>8192||!scanForSecrets(collected.snapshot))throw new Error("qualification_result_invalid");
      const key="eg-qualification-"+claimed.workflow_id;
      await db.prepare("CREATE TABLE IF NOT EXISTS eg_checkpoints (owner TEXT NOT NULL, project TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision > 0), value TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY(owner,project))").run();
      await db.prepare("INSERT INTO eg_checkpoints(owner,project,revision,value,updated_at) SELECT ?,?,1,?,? WHERE EXISTS(SELECT 1 FROM eg_workflow_steps s JOIN eg_workflows w ON w.id=s.workflow_id WHERE s.id=? AND s.owner=? AND s.project=? AND s.lease_id=? AND s.state='RUNNING' AND w.state IN ('QUEUED','RUNNING','RETRYING','BLOCKED')) ON CONFLICT(owner,project) DO NOTHING").bind(owner,key,serialized,nowIso(),claimed.id,owner,project,lease).run();
      const saved=await db.prepare("SELECT revision,value FROM eg_checkpoints WHERE owner=? AND project=?").bind(owner,key).first();
      return {verified:saved?.revision===1&&saved.value===serialized,checkpoint:key,revision:saved?.revision??null,sha256:verified.sha256,checked_at:nowIso()};
    }
  }
  throw new Error("unsupported_operation");
}

async function refreshWorkflowState(db, owner, project, workflowId) {
  const workflow=await loadWorkflow(db,owner,project,workflowId);
  if(!workflow || ["PAUSED","CANCELLED","SUCCEEDED"].includes(workflow.state))return;
  const steps=await loadSteps(db,owner,project,workflowId);
  let state=workflow.state,errorCode=null,finishedAt=null;
  if(steps.some(step=>step.state==="FAILED")){state="FAILED";errorCode="step_failed";finishedAt=nowIso();}
  else if(steps.length&&steps.every(step=>step.state==="SUCCEEDED"&&parseJson(step.evidence,{verified:false}).verified===true)){state="SUCCEEDED";finishedAt=nowIso();}
  else if(steps.some(step=>step.state==="RETRYING"))state="RETRYING";
  else if(steps.some(step=>step.state==="RUNNING"||step.state==="VERIFYING"))state="RUNNING";
  else if(steps.some(step=>step.state==="QUEUED"))state="QUEUED";
  else if(steps.some(step=>step.state==="BLOCKED"))state="BLOCKED";
  await db.prepare("UPDATE eg_workflows SET state=?,updated_at=?,finished_at=?,error_code=? WHERE owner=? AND project=? AND id=? AND state NOT IN ('PAUSED','CANCELLED')").bind(state,nowIso(),finishedAt,errorCode,owner,project,workflowId).run();
}

export async function runWorkflowBatch(db, owner, limit=4, fetcher=fetch, now=Date.now()) {
  await ensureSchema(db);
  await db.prepare("UPDATE eg_workflow_steps SET state=CASE WHEN EXISTS(SELECT 1 FROM eg_workflows w WHERE w.id=eg_workflow_steps.workflow_id AND w.state='CANCELLED') THEN 'CANCELLED' WHEN attempts>=max_attempts THEN 'FAILED' WHEN EXISTS(SELECT 1 FROM eg_workflows w WHERE w.id=eg_workflow_steps.workflow_id AND w.state='PAUSED') THEN 'PAUSED' ELSE 'RETRYING' END,lease_id=NULL,lease_until=NULL,error_code='lease_expired',available_at=?,updated_at=? WHERE owner=? AND state IN ('RUNNING','VERIFYING') AND lease_until<=?")
    .bind(now,nowIso(),owner,now).run();
  // Reconcile terminal child states even when there is no claimable step:
  // a Worker can stop after the last child is persisted, before parent refresh.
  const stamp=nowIso();
  await db.prepare("UPDATE eg_workflows SET state='FAILED',error_code='step_failed',updated_at=?,finished_at=? WHERE owner=? AND state IN ('QUEUED','RUNNING','RETRYING','BLOCKED') AND EXISTS(SELECT 1 FROM eg_workflow_steps s WHERE s.workflow_id=eg_workflows.id AND s.state='FAILED')").bind(stamp,stamp,owner).run();
  await db.prepare("UPDATE eg_workflows SET state='SUCCEEDED',error_code=NULL,updated_at=?,finished_at=? WHERE owner=? AND state IN ('QUEUED','RUNNING','RETRYING','BLOCKED') AND EXISTS(SELECT 1 FROM eg_workflow_steps s WHERE s.workflow_id=eg_workflows.id) AND NOT EXISTS(SELECT 1 FROM eg_workflow_steps s WHERE s.workflow_id=eg_workflows.id AND (s.state<>'SUCCEEDED' OR COALESCE(CASE WHEN json_valid(s.evidence) THEN json_extract(s.evidence,'$.verified') END,0)<>1))").bind(stamp,stamp,owner).run();
  let executed=0;
  for(let count=0;count<Math.min(limit,8);count++){
    const workflows=await db.prepare("SELECT id,project FROM eg_workflows WHERE owner=? AND state IN ('QUEUED','RUNNING','RETRYING','BLOCKED') ORDER BY created_at LIMIT 50").bind(owner).all();
    let candidate=null;
    for(const workflow of workflows.results||[]){
      const steps=await loadSteps(db,owner,workflow.project,workflow.id);
      const byKey=new Map(steps.map(step=>[step.step_key,step]));
      for(const step of steps){
        if(step.state!=="BLOCKED")continue;
        const deps=parseJson(step.depends_on,[]);
        if(deps.some(dep=>["FAILED","CANCELLED"].includes(byKey.get(dep)?.state))){
          await db.prepare("UPDATE eg_workflow_steps SET error_code='dependency_failed',updated_at=? WHERE id=? AND state='BLOCKED'").bind(nowIso(),step.id).run();
          continue;
        }
        if(deps.every(dep=>byKey.get(dep)?.state==="SUCCEEDED")){
          await db.prepare("UPDATE eg_workflow_steps SET state='QUEUED',updated_at=? WHERE id=? AND state='BLOCKED'").bind(nowIso(),step.id).run();
        }
      }
      const refreshed=await loadSteps(db,owner,workflow.project,workflow.id);
      const map=new Map(refreshed.map(step=>[step.step_key,step]));
      for(const step of refreshed){
        if(!["QUEUED","RETRYING"].includes(step.state)||step.available_at>now)continue;
        if(!parseJson(step.depends_on,[]).every(dep=>map.get(dep)?.state==="SUCCEEDED"))continue;
        candidate={workflow,step};break;
      }
      if(candidate)break;
    }
    if(!candidate)break;
    const lease=crypto.randomUUID(),started=nowIso();
    const claimed=await db.prepare("UPDATE eg_workflow_steps SET state='RUNNING',attempts=attempts+1,lease_id=?,lease_until=?,updated_at=?,error_code=NULL WHERE id=? AND owner=? AND state IN ('QUEUED','RETRYING') AND available_at<=? AND attempts<max_attempts AND EXISTS(SELECT 1 FROM eg_workflows w WHERE w.id=eg_workflow_steps.workflow_id AND w.owner=eg_workflow_steps.owner AND w.project=eg_workflow_steps.project AND w.state IN ('QUEUED','RUNNING','RETRYING','BLOCKED')) AND (SELECT COUNT(*) FROM eg_workflow_steps WHERE state IN ('RUNNING','VERIFYING') AND lease_until>?)<16 AND (SELECT COUNT(*) FROM eg_workflow_steps WHERE owner=? AND state IN ('RUNNING','VERIFYING') AND lease_until>?)<4 RETURNING id,workflow_id,project,step_key,operation,input,depends_on,attempts,max_attempts,timeout_ms")
      .bind(lease,now+candidate.step.timeout_ms+30000,started,candidate.step.id,owner,now,now,owner,now).first();
    if(!claimed)continue;
    await db.prepare("UPDATE eg_workflows SET state='RUNNING',updated_at=? WHERE id=? AND owner=? AND state IN ('QUEUED','RETRYING','BLOCKED','RUNNING')").bind(started,claimed.workflow_id,owner).run();
    let result=null,transient=false,errorCode=null,delay=0;
    try { result=await executeOperation(db,claimed.operation,parseJson(claimed.input,{}),claimed.timeout_ms,fetcher,{owner,project:claimed.project,claimed,lease}); }
    catch(error) { transient=error instanceof RetryableError;errorCode=error.code||error.message||"execution_error";delay=error.delayMs||0; }
    const workflowAfterExecution=await loadWorkflow(db,owner,claimed.project,claimed.workflow_id);
    if(workflowAfterExecution?.state==="CANCELLED"){
      await db.prepare("UPDATE eg_workflow_steps SET state='CANCELLED',result=?,lease_id=NULL,lease_until=NULL,updated_at=? WHERE id=? AND owner=? AND lease_id=? AND state='RUNNING'")
        .bind(result?JSON.stringify(result):null,nowIso(),claimed.id,owner,lease).run();
      executed++;
      continue;
    }
    if(transient && claimed.attempts<claimed.max_attempts){
      const backoff=Math.min(3600000,1000*Math.pow(2,claimed.attempts-1));
      const jitter=Math.floor(Math.random()*1000);
      await db.prepare("UPDATE eg_workflow_steps SET state='RETRYING',available_at=?,lease_id=NULL,lease_until=NULL,error_code=?,updated_at=? WHERE id=? AND owner=? AND lease_id=? AND state='RUNNING'")
        .bind(now+Math.max(delay,backoff)+jitter,errorCode,nowIso(),claimed.id,owner,lease).run();
    } else {
      const serialized=JSON.stringify(result??{verified:false,error:errorCode||"execution_error"});
      await db.prepare("UPDATE eg_workflow_steps SET state='VERIFYING',result=?,updated_at=? WHERE id=? AND owner=? AND lease_id=? AND state='RUNNING'")
        .bind(serialized,nowIso(),claimed.id,owner,lease).run();
      const verified=result?.verified===true;
      const digest=createHash("sha256").update(serialized,"utf8").digest("hex");
      const evidence=JSON.stringify({verified,operation:claimed.operation,checked_at:result?.checked_at||nowIso(),result_sha256:digest});
      const finalState=verified?"SUCCEEDED":"FAILED";
      await db.prepare("UPDATE eg_workflow_steps SET state=?,evidence=?,error_code=?,lease_id=NULL,lease_until=NULL,updated_at=? WHERE id=? AND owner=? AND lease_id=? AND state='VERIFYING'")
        .bind(finalState,evidence,verified?null:(errorCode||"verification_failed"),nowIso(),claimed.id,owner,lease).run();
    }
    await refreshWorkflowState(db,owner,claimed.project,claimed.workflow_id);
    executed++;
  }
  return {executed};
}

export async function executionFinalize(db, owner, args) {
  const status=await workflowStatus(db,owner,args);
  if(!status.found)return status;
  const verified=status.workflow.state==="SUCCEEDED"&&status.steps.length>0&&status.steps.every(step=>{
    if(step.state!=="SUCCEEDED"||step.evidence?.verified!==true||!step.result)return false;
    const digest=createHash("sha256").update(JSON.stringify(step.result),"utf8").digest("hex");
    return digest===step.evidence.result_sha256;
  });
  return {workflow_id:args.workflow_id,state:status.workflow.state,verified,steps:status.steps.length,verified_steps:status.steps.filter(step=>step.evidence?.verified===true).length};
}
