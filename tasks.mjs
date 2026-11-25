import { runWorkflowBatch } from "./orchestrator.mjs";

// Durable queue for explicitly allowed, deterministic operations only.
export const MAX_ATTEMPTS=3;
const leaseMs=120000;
const projects=/^[a-z0-9][a-z0-9_-]{0,63}$/;
const keys=/^[a-zA-Z0-9_-]{8,64}$/;
const ids=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const secretValue=/(?:gh[pousr]_[A-Za-z0-9_]{20,}|Bearer\s+[A-Za-z0-9._~-]{20,}|-----BEGIN (?:RSA|OPENSSH|EC) PRIVATE KEY-----|AKIA[0-9A-Z]{16})/;
const schema="CREATE TABLE IF NOT EXISTS eg_tasks (id TEXT PRIMARY KEY, owner TEXT NOT NULL, project TEXT NOT NULL, idem TEXT NOT NULL, kind TEXT NOT NULL, payload TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('queued','running','succeeded','failed','cancelled')), attempts INTEGER NOT NULL DEFAULT 0, available_at INTEGER NOT NULL, lease_id TEXT, lease_until INTEGER, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, result TEXT, error_code TEXT, UNIQUE(owner,project,idem))";
const index="CREATE INDEX IF NOT EXISTS eg_tasks_dispatch ON eg_tasks(state,available_at,lease_until)";
const allkeys=(a,k)=>a&&typeof a==="object"&&!Array.isArray(a)&&Object.keys(a).length===k.length&&k.every(v=>Object.hasOwn(a,v));
const projectOk=p=>typeof p==="string"&&projects.test(p);
const idOk=p=>typeof p==="string"&&ids.test(p);
async function exists(db){return !!(await db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='eg_tasks'").first());}
async function init(db){await db.prepare(schema).run();await db.prepare(index).run();}
const taskView=r=>r?{found:true,task_id:r.id,project:r.project,kind:r.kind,state:r.state,attempts:r.attempts,created_at:r.created_at,updated_at:r.updated_at,result:r.result?JSON.parse(r.result):null,error_code:r.error_code??null}:{found:false};
async function lookup(db,owner,project,id){return db.prepare("SELECT id,project,kind,state,attempts,created_at,updated_at,result,error_code FROM eg_tasks WHERE owner=? AND project=? AND id=?").bind(owner,project,id).first();}
function normalizedPayload(kind,p){
  if(kind==="health_probe"&&allkeys(p,[]))return "{}";
  if(kind==="sha256_verify"&&allkeys(p,["text","expected_sha256"])&&typeof p.text==="string"&&new TextEncoder().encode(p.text).length<=4096&&!secretValue.test(p.text)&&typeof p.expected_sha256==="string"&&/^[a-f0-9]{64}$/.test(p.expected_sha256))return JSON.stringify({text:p.text,expected_sha256:p.expected_sha256});
  return null;
}
export async function taskSubmit(db,owner,args,now=Date.now()){
  if(!allkeys(args,["project","idempotency_key","kind","payload"])||!projectOk(args.project)||typeof args.idempotency_key!=="string"||!keys.test(args.idempotency_key))return {error:"invalid_arguments"};
  const payload=normalizedPayload(args.kind,args.payload);if(payload===null)return {error:"invalid_kind_or_payload"};
  await init(db);
  const id=crypto.randomUUID();
  await db.prepare("INSERT INTO eg_tasks(id,owner,project,idem,kind,payload,state,available_at,created_at,updated_at) SELECT ?,?,?,?,?,?,'queued',?,?,? WHERE (SELECT COUNT(*) FROM eg_tasks WHERE owner=? AND state IN ('queued','running'))<50 AND (SELECT COUNT(*) FROM eg_tasks WHERE owner=?)<5000 ON CONFLICT(owner,project,idem) DO NOTHING").bind(id,owner,args.project,args.idempotency_key,args.kind,payload,now,now,now,owner,owner).run();
  const row=await db.prepare("SELECT * FROM eg_tasks WHERE owner=? AND project=? AND idem=?").bind(owner,args.project,args.idempotency_key).first();
  if(!row)return {error:"queue_capacity"};
  if(row.kind!==args.kind||row.payload!==payload)return {error:"idempotency_conflict"};
  return {...taskView(row),deduplicated:row.id!==id};
}
export async function taskStatus(db,owner,args){
  if(!allkeys(args,["project","task_id"])||!projectOk(args.project)||!idOk(args.task_id))return {error:"invalid_arguments"};
  if(!await exists(db))return {found:false};
  return taskView(await lookup(db,owner,args.project,args.task_id));
}
export async function taskCancel(db,owner,args,now=Date.now()){
  if(!allkeys(args,["project","task_id"])||!projectOk(args.project)||!idOk(args.task_id))return {error:"invalid_arguments"};
  if(!await exists(db))return {found:false};
  const r=await db.prepare("UPDATE eg_tasks SET state='cancelled',updated_at=? WHERE owner=? AND project=? AND id=? AND state='queued'").bind(now,owner,args.project,args.task_id).run();
  return {...taskView(await lookup(db,owner,args.project,args.task_id)),cancelled_now:r.meta.changes===1};
}
async function hash(text){
  const d=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(text));
  return Array.from(new Uint8Array(d),x=>x.toString(16).padStart(2,"0")).join("");
}
async function execute(db,row){
  if(row.kind==="health_probe"){
    const r=await db.prepare("SELECT value FROM eg_probe WHERE id=1").first();
    if(r?.value!=="execution-guard-v030")throw Error("probe_unavailable");
    return {verified:true,database:"online",persistence_probe:"verified",checked_at:new Date().toISOString()};
  }
  if(row.kind==="sha256_verify"){
    const p=JSON.parse(row.payload), actual=await hash(p.text);
    return {verified:actual===p.expected_sha256,sha256:actual,expected_sha256:p.expected_sha256};
  }
  throw Error("unknown_kind");
}
export async function runNextTask(db,owner,now=Date.now()){
  if(!await exists(db))return {claimed:false};
  await db.prepare("UPDATE eg_tasks SET state='failed',lease_id=NULL,lease_until=NULL,error_code='lease_attempts_exhausted',updated_at=? WHERE owner=? AND state='running' AND lease_until<=? AND attempts>=?").bind(now,owner,now,MAX_ATTEMPTS).run();
  const lease=crypto.randomUUID();
  const row=await db.prepare("UPDATE eg_tasks SET state='running',attempts=attempts+1,lease_id=?,lease_until=?,updated_at=?,error_code=NULL WHERE id=(SELECT id FROM eg_tasks WHERE owner=? AND attempts<? AND ((state='queued' AND available_at<=?) OR (state='running' AND lease_until<=?)) ORDER BY created_at,id LIMIT 1) RETURNING id,kind,payload,attempts").bind(lease,now+leaseMs,now,owner,MAX_ATTEMPTS,now,now).first();
  if(!row)return {claimed:false};
  let result,state,error=null,available=now;
  try{
    result=await execute(db,row);state=result.verified?"succeeded":"failed";if(!result.verified)error="verification_mismatch";
  }catch{
    state=row.attempts>=MAX_ATTEMPTS?"failed":"queued";error="execution_error";available=now+60000*2**(row.attempts-1);
  }
  const update=await db.prepare("UPDATE eg_tasks SET state=?,result=?,error_code=?,available_at=?,lease_id=NULL,lease_until=NULL,updated_at=? WHERE owner=? AND id=? AND lease_id=? AND state='running'").bind(state,result?JSON.stringify(result):null,error,available,Date.now(),owner,row.id,lease).run();
  return {claimed:true,task_id:row.id,committed:update.meta.changes===1};
}
export async function runBatch(db,owner,limit=4){
  for(let i=0;i<Math.min(limit,4);i++){const r=await runNextTask(db,owner);if(!r.claimed)break;}
  await runWorkflowBatch(db,owner,limit);
}
