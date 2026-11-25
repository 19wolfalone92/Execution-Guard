import { isOwner, READ, WRITE, HOST } from "./security.mjs";
import { taskSubmit, taskStatus, taskCancel } from "./tasks.mjs";
import {
  projectCreate, projectGet, projectUpdate, projectHistory, projectResume,
  workflowCreate, workflowStart, workflowStatus, workflowPause, workflowResume,
  workflowCancel, workflowRetry, workflowDependenciesGet, taskEvidenceGet,
  executionAudit, executionFinalize, systemHealth,
  githubRepositoryStatus, githubCommitStatus, githubWorkflowStatus
} from "./orchestrator.mjs";

const projectPattern = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const workflowId = {type:"string",pattern:"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$"};
const ddl = "CREATE TABLE IF NOT EXISTS eg_checkpoints (owner TEXT NOT NULL, project TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision > 0), value TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY(owner, project))";
const recordSchema = {type:"object",properties:{
  goal:{type:"string",maxLength:2000},rules:{type:"array",maxItems:50,items:{type:"string",maxLength:1000}},
  repository:{type:"object",properties:{owner:{type:"string",maxLength:100},repo:{type:"string",maxLength:100}},additionalProperties:false},
  branch:{type:"string",maxLength:255},commit:{type:"string",maxLength:64},pull_request:{type:"integer",minimum:1},
  stage:{type:"string",maxLength:200},completed:{type:"array",maxItems:100,items:{type:"string",maxLength:500}},
  pending:{type:"array",maxItems:100,items:{type:"string",maxLength:500}},errors:{type:"array",maxItems:100,items:{type:"string",maxLength:1000}},
  tests:{type:"object"},limitations:{type:"array",maxItems:100,items:{type:"string",maxLength:1000}},
  next_action:{type:"string",maxLength:2000},evidence:{type:"array",maxItems:100,items:{type:"object"}}
},additionalProperties:false};
const stepSchema = {type:"object",properties:{
  key:{type:"string",pattern:"^[a-z0-9][a-z0-9_-]{0,31}$"},
  operation:{type:"string",enum:["health_probe","sha256_verify","github_repository_status","github_commit_status","github_workflow_status"]},
  input:{type:"object"},depends_on:{type:"array",maxItems:31,items:{type:"string"}},
  max_attempts:{type:"integer",minimum:1,maximum:5},timeout_ms:{type:"integer",minimum:1000,maximum:30000}
},required:["key","operation"],additionalProperties:false};
const def = (name,description,properties,required,write=false,destructive=false) => ({
  name, description, inputSchema:{type:"object",properties,required,additionalProperties:false},
  annotations:{readOnlyHint:!write,destructiveHint:destructive,idempotentHint:!write,openWorldHint:false},
  securitySchemes:[{type:"oauth2",scopes:write?[READ,WRITE]:[READ]}],
  _meta:{securitySchemes:[{type:"oauth2",scopes:write?[READ,WRITE]:[READ]}]}
});
const project = {type:"string",pattern:"^[a-z0-9][a-z0-9_-]{0,63}$"};
const taskId = {type:"string",pattern:"^[a-f0-9-]{36}$"};
const workflowRef = {project,workflow_id:workflowId};
const tools = [
  def("task_submit","Queue a bounded health probe or SHA-256 verification for the server scheduler. No arbitrary commands or external writes.",{project,idempotency_key:{type:"string",pattern:"^[a-zA-Z0-9_-]{8,64}$"},kind:{type:"string",enum:["health_probe","sha256_verify"]},payload:{type:"object",description:"Use {} for health_probe; use {text, expected_sha256} for sha256_verify.",properties:{text:{type:"string",maxLength:4096},expected_sha256:{type:"string",pattern:"^[a-f0-9]{64}$"}},additionalProperties:false}},["project","idempotency_key","kind","payload"],true),
  def("task_status","Read persisted task state and verification evidence.",{project,task_id:taskId},["project","task_id"]),
  def("task_cancel","Cancel a queued diagnostic task; running and terminal tasks are not changed.",{project,task_id:taskId},["project","task_id"],true,true),
  def("whoami","Verify authenticated owner identity and granted checkpoint scopes.",{},[]),
  def("checkpoint_get","Read a legacy project checkpoint and its revision.",{project},["project"]),
  def("checkpoint_put","Create or replace a legacy checkpoint using an expected revision. Never store passwords, credentials or private keys.",{project,expected_revision:{type:"integer",minimum:0,maximum:2147483646},value:{type:"string",maxLength:8192}},["project","expected_revision","value"],true),
  def("project_create","Create isolated structured project memory. Records are data only; secrets, tokens, credentials and private keys are rejected.",{project,record:recordSchema},["project","record"],true),
  def("project_get","Read the current structured project record and revision.",{project},["project"]),
  def("project_update","Patch project memory with optimistic revision checking; each accepted revision is retained in history.",{project,expected_revision:{type:"integer",minimum:1},patch:recordSchema},["project","expected_revision","patch"],true),
  def("project_history","Read prior project memory revisions.",{project,limit:{type:"integer",minimum:1,maximum:50}},["project","limit"]),
  def("project_resume","Read a saved project state and indicate whether external repository reconciliation is required.",{project},["project"]),
  def("workflow_create","Create a bounded DAG workflow. Only health, SHA-256 and public GitHub read operations are executable; arbitrary code and external writes are not supported.",{project,name:{type:"string",minLength:1,maxLength:160},steps:{type:"array",minItems:1,maxItems:32,items:stepSchema}},["project","name","steps"],true),
  def("workflow_start","Start a newly created workflow; dependency-free steps become queued.",workflowRef,["project","workflow_id"],true),
  def("workflow_status","Read workflow state, step states, results and verification evidence.",workflowRef,["project","workflow_id"]),
  def("workflow_pause","Pause new workflow steps while allowing an already-running bounded read to finish.",workflowRef,["project","workflow_id"],true),
  def("workflow_resume","Resume a paused workflow after dependency checks.",workflowRef,["project","workflow_id"],true),
  def("workflow_cancel","Cancel a workflow and prevent new steps from being claimed.",workflowRef,["project","workflow_id"],true,true),
  def("workflow_retry","Retry failed steps within their retry budget. Exhausted steps require a second explicit owner retry approval.",workflowRef,["project","workflow_id"],true),
  def("workflow_dependencies_get","Read the workflow dependency graph.",workflowRef,["project","workflow_id"]),
  def("task_evidence_get","Read the result and integrity evidence for one workflow step.",{project,workflow_id:workflowId,step_key:{type:"string",pattern:"^[a-z0-9][a-z0-9_-]{0,31}$"}},["project","workflow_id","step_key"]),
  def("github_repository_status","Read public GitHub repository metadata. Private repositories are not accessed; no GitHub token is stored.",{owner:{type:"string",maxLength:100},repo:{type:"string",maxLength:100}},["owner","repo"]),
  def("github_commit_status","Read public GitHub combined commit status.",{owner:{type:"string",maxLength:100},repo:{type:"string",maxLength:100},sha:{type:"string",pattern:"^(?:[a-f0-9]{40}|[a-f0-9]{64})$"}},["owner","repo","sha"]),
  def("github_workflow_status","Read public GitHub Actions run status. This does not dispatch, cancel or rerun workflows.",{owner:{type:"string",maxLength:100},repo:{type:"string",maxLength:100},run_id:{type:"integer",minimum:1}},["owner","repo","run_id"]),
  def("execution_audit","Read significant project and workflow audit events.",{project,limit:{type:"integer",minimum:1,maximum:100}},["project","limit"]),
  def("execution_finalize","Independently re-check workflow terminal state and the SHA-256 integrity of each stored result.",workflowRef,["project","workflow_id"]),
  def("system_health","Read database, persistence probe and per-owner workload counts.",{},[])
];
function json(value, status=200) { return Response.json(value,{status,headers:{"Cache-Control":"no-store"}}); }
function validArgs(args,keys) {return args && typeof args==="object" && !Array.isArray(args) && Object.keys(args).length===keys.length && keys.every(k=>Object.hasOwn(args,k));}
function writeChallenge(description) {
  return {"mcp/www_authenticate":[
    "Bearer resource_metadata=\""+HOST+"/.well-known/oauth-protected-resource/mcp-private\", error=\"insufficient_scope\", error_description=\""+description+"\", scope=\""+READ+" "+WRITE+"\""
  ]};
}
const writeNames = new Set(["task_submit","task_cancel","checkpoint_put","project_create","project_update","workflow_create","workflow_start","workflow_pause","workflow_resume","workflow_cancel","workflow_retry"]);
const handlers = {
  project_create:(db,owner,args)=>projectCreate(db,owner,args),
  project_get:(db,owner,args)=>projectGet(db,owner,args),
  project_update:(db,owner,args)=>projectUpdate(db,owner,args),
  project_history:(db,owner,args)=>projectHistory(db,owner,args),
  project_resume:(db,owner,args)=>projectResume(db,owner,args),
  workflow_create:(db,owner,args)=>workflowCreate(db,owner,args),
  workflow_start:(db,owner,args)=>workflowStart(db,owner,args),
  workflow_status:(db,owner,args)=>workflowStatus(db,owner,args),
  workflow_pause:(db,owner,args)=>workflowPause(db,owner,args),
  workflow_resume:(db,owner,args)=>workflowResume(db,owner,args),
  workflow_cancel:(db,owner,args)=>workflowCancel(db,owner,args),
  workflow_retry:(db,owner,args)=>workflowRetry(db,owner,args),
  workflow_dependencies_get:(db,owner,args)=>workflowDependenciesGet(db,owner,args),
  task_evidence_get:(db,owner,args)=>taskEvidenceGet(db,owner,args),
  execution_audit:(db,owner,args)=>executionAudit(db,owner,args),
  execution_finalize:(db,owner,args)=>executionFinalize(db,owner,args),
  system_health:(db,owner)=>systemHealth(db,owner)
};
export async function privateFetch(request,env,ctx) {
  if (!isOwner(env,ctx)) return json({error:"forbidden"},403);
  const origin=request.headers.get("Origin");
  if (origin && ![HOST,"https://chatgpt.com","https://www.chatgpt.com"].includes(origin)) return json({error:"forbidden"},403);
  if (!ctx.auth.scope.includes(READ)) return json({error:"insufficient_scope"},403);
  if (request.method!=="POST") return new Response(null,{status:405,headers:{Allow:"POST","Cache-Control":"no-store"}});
  const length=Number(request.headers.get("Content-Length"));
  if(length>16384) return json({error:"request_too_large"},413);
  const reader=request.body?.getReader();
  let byteCount=0;const chunks=[];
  if(reader){while(true){const {done,value}=await reader.read();if(done)break;byteCount+=value.byteLength;if(byteCount>16384){await reader.cancel();return json({error:"request_too_large"},413);}chunks.push(value);}}
  const data=new Uint8Array(byteCount);let offset=0;for(const chunk of chunks){data.set(chunk,offset);offset+=chunk.length;}
  let m;try{m=JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(data));}catch{return json({jsonrpc:"2.0",id:null,error:{code:-32700,message:"Parse error"}},400);}
  if(!m||Array.isArray(m)||m.jsonrpc!=="2.0"||typeof m.method!=="string")return json({jsonrpc:"2.0",id:null,error:{code:-32600,message:"Invalid request"}},400);
  if(!Object.hasOwn(m,"id"))return new Response(null,{status:202});
  const reply=result=>json({jsonrpc:"2.0",id:m.id,result});
  const rpcError=(code,message)=>json({jsonrpc:"2.0",id:m.id,error:{code,message}});
  const result=(value,isError=false)=>reply({content:[{type:"text",text:JSON.stringify(value)}],...(isError?{isError:true}:{})});
  if(m.method==="initialize"){
    const versions=["2025-03-26","2025-06-18","2025-11-25","2026-07-28"];
    const v=m.params?.protocolVersion;
    return reply({protocolVersion:versions.includes(v)?v:"2026-07-28",capabilities:{tools:{}},serverInfo:{name:"execution-guard-private",version:"0.6.0"}});
  }
  if(m.method==="ping")return reply({});
  if(m.method==="tools/list")return reply({tools});
  if(m.method!=="tools/call")return rpcError(-32601,"Method not found");
  const name=m.params?.name,args=m.params?.arguments??{},owner=ctx.props.userId;
  if(name==="whoami"){if(!validArgs(args,[]))return rpcError(-32602,"Invalid arguments");return result({authenticated:true,owner_verified:true,scopes:ctx.auth.scope});}
  if(["task_submit","task_status","task_cancel"].includes(name)){
    if(name!=="task_status"&&!ctx.auth.scope.includes(WRITE))return reply({isError:true,content:[{type:"text",text:"Write scope required"}],_meta:writeChallenge("Task write scope required")});
    try{const fn={task_submit:taskSubmit,task_status:taskStatus,task_cancel:taskCancel}[name];const r=await fn(env.DB,owner,args);return result(r,!!r.error);}catch{return result({error:"storage_error"},true);}
  }
  if(name==="checkpoint_get"||name==="checkpoint_put"){
    const write=name==="checkpoint_put";
    if(write&&!ctx.auth.scope.includes(WRITE))return reply({isError:true,content:[{type:"text",text:"Write scope required"}],_meta:writeChallenge("Checkpoint write scope required")});
    if(!validArgs(args,write?["project","expected_revision","value"]:["project"])||typeof args.project!=="string"||!projectPattern.test(args.project))return rpcError(-32602,"Invalid arguments");
    if(write&&(!Number.isInteger(args.expected_revision)||args.expected_revision<0||args.expected_revision>2147483646||typeof args.value!=="string"||new TextEncoder().encode(args.value).length>8192))return rpcError(-32602,"Invalid revision or value");
    try {
      if(!write){
        const table=await env.DB.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='eg_checkpoints'").first();
        if(!table)return result({project:args.project,found:false});
        const row=await env.DB.prepare("SELECT revision,value,updated_at FROM eg_checkpoints WHERE owner=? AND project=?").bind(owner,args.project).first();
        return result(row?{project:args.project,found:true,...row}:{project:args.project,found:false});
      }
      await env.DB.prepare(ddl).run();
      const now=new Date().toISOString();
      const change=args.expected_revision===0
        ? await env.DB.prepare("INSERT INTO eg_checkpoints (owner,project,revision,value,updated_at) VALUES (?,?,1,?,?) ON CONFLICT(owner,project) DO NOTHING").bind(owner,args.project,args.value,now).run()
        : await env.DB.prepare("UPDATE eg_checkpoints SET revision=revision+1,value=?,updated_at=? WHERE owner=? AND project=? AND revision=?").bind(args.value,now,owner,args.project,args.expected_revision).run();
      if(change?.meta?.changes!==1)return result({status:"conflict",project:args.project},true);
      return result({status:"saved",project:args.project,revision:args.expected_revision+1,updated_at:now});
    }catch{return result({status:"storage_error"},true);}
  }
  if(writeNames.has(name)&&!ctx.auth.scope.includes(WRITE))return reply({isError:true,content:[{type:"text",text:"Write scope required"}],_meta:writeChallenge("Project or workflow write scope required")});
  if(Object.hasOwn(handlers,name)){
    try{const r=await handlers[name](env.DB,owner,args);return result(r,!!r.error);}catch{return result({error:"execution_error"},true);}
  }
  if(name==="github_repository_status"||name==="github_commit_status"||name==="github_workflow_status"){
    try{
      const fn={github_repository_status:githubRepositoryStatus,github_commit_status:githubCommitStatus,github_workflow_status:githubWorkflowStatus}[name];
      const r=await fn(args);
      return result(r,!!r.error);
    }catch{return result({error:"github_read_failed"},true);}
  }
  return rpcError(-32602,"Unknown tool");
}
