import { isOwner, READ, WRITE, HOST } from "./security.mjs";
import { taskSubmit, taskStatus, taskCancel } from "./tasks.mjs";

const projectPattern = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const ddl = "CREATE TABLE IF NOT EXISTS eg_checkpoints (owner TEXT NOT NULL, project TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision > 0), value TEXT NOT NULL, updated_at TEXT NOT NULL, PRIMARY KEY(owner, project))";
const def = (name,description,properties,required,write=false) => ({
  name, description, inputSchema:{type:"object",properties,required,additionalProperties:false},
  annotations:{readOnlyHint:!write,destructiveHint:write,idempotentHint:!write,openWorldHint:false},
  securitySchemes:[{type:"oauth2",scopes:write?[READ,WRITE]:[READ]}],
  _meta:{securitySchemes:[{type:"oauth2",scopes:write?[READ,WRITE]:[READ]}]}
});
const project={type:"string",pattern:"^[a-z0-9][a-z0-9_-]{0,63}$"};
const taskId={type:"string",pattern:"^[a-f0-9-]{36}$"};
const tools=[
  def("task_submit","Queue a bounded health probe or SHA-256 verification for the server scheduler. No arbitrary commands or external writes.",{project,idempotency_key:{type:"string",pattern:"^[a-zA-Z0-9_-]{8,64}$"},kind:{type:"string",enum:["health_probe","sha256_verify"]},payload:{type:"object",description:"Use {} for health_probe; use {text, expected_sha256} for sha256_verify.",properties:{text:{type:"string",maxLength:4096},expected_sha256:{type:"string",pattern:"^[a-f0-9]{64}$"}},additionalProperties:false}},["project","idempotency_key","kind","payload"],true),
  def("task_status","Read persisted task state and verification evidence.",{project,task_id:taskId},["project","task_id"]),
  def("task_cancel","Cancel a queued task; running and terminal tasks are not changed.",{project,task_id:taskId},["project","task_id"],true),
  def("whoami","Verify authenticated owner identity and granted checkpoint scopes.",{},[]),
  def("checkpoint_get","Read a single project checkpoint and its revision.",{project},["project"]),
  def("checkpoint_put","Create or replace a project checkpoint using an expected revision. Never store passwords, credentials or private keys.",{project,expected_revision:{type:"integer",minimum:0,maximum:2147483646},value:{type:"string",maxLength:8192}},["project","expected_revision","value"],true)
];
function json(value, status=200) { return Response.json(value,{status,headers:{"Cache-Control":"no-store"}}); }
function validArgs(args,keys) {return args && typeof args==="object" && !Array.isArray(args) && Object.keys(args).length===keys.length && keys.every(k=>Object.hasOwn(args,k));}
export async function privateFetch(request,env,ctx) {
  if (!isOwner(env,ctx)) return json({error:"forbidden"},403);
  const origin=request.headers.get("Origin");
  if (origin && ![HOST,"https://chatgpt.com","https://www.chatgpt.com"].includes(origin)) return json({error:"forbidden"},403);
  if (!ctx.auth.scope.includes(READ)) return json({error:"insufficient_scope"},403);
  if (request.method!=="POST") return new Response(null,{status:405,headers:{Allow:"POST","Cache-Control":"no-store"}});
  const length=Number(request.headers.get("Content-Length"));
  if(length>16384) return json({error:"request_too_large"},413);
  const reader=request.body?.getReader();
  let bytes=0;const chunks=[];
  if(reader){while(true){const {done,value}=await reader.read();if(done)break;bytes+=value.byteLength;if(bytes>16384){await reader.cancel();return json({error:"request_too_large"},413);}chunks.push(value);}}
  const data=new Uint8Array(bytes);let offset=0;for(const chunk of chunks){data.set(chunk,offset);offset+=chunk.length;}
  let m;try{m=JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(data));}catch{return json({jsonrpc:"2.0",id:null,error:{code:-32700,message:"Parse error"}},400);}
  if(!m||Array.isArray(m)||m.jsonrpc!=="2.0"||typeof m.method!=="string")return json({jsonrpc:"2.0",id:null,error:{code:-32600,message:"Invalid request"}},400);
  if(!Object.hasOwn(m,"id"))return new Response(null,{status:202});
  const reply=result=>json({jsonrpc:"2.0",id:m.id,result});
  const rpcError=(code,message)=>json({jsonrpc:"2.0",id:m.id,error:{code,message}});
  const result=(value,isError=false)=>reply({content:[{type:"text",text:JSON.stringify(value)}],...(isError?{isError:true}:{})});
  if(m.method==="initialize"){const versions=["2025-03-26","2025-06-18","2025-11-25","2026-07-28"];const v=m.params?.protocolVersion;return reply({protocolVersion:versions.includes(v)?v:"2025-11-25",capabilities:{tools:{}},serverInfo:{name:"execution-guard-private",version:"0.5.0"}});}
  if(m.method==="ping")return reply({});
  if(m.method==="tools/list")return reply({tools});
  if(m.method!=="tools/call")return rpcError(-32601,"Method not found");
  const name=m.params?.name,args=m.params?.arguments??{},owner=ctx.props.userId;
  if(name==="whoami"){if(!validArgs(args,[]))return rpcError(-32602,"Invalid arguments");return result({authenticated:true,owner_verified:true,scopes:ctx.auth.scope});}
  if(["task_submit","task_status","task_cancel"].includes(name)){
    if(name!=="task_status"&&!ctx.auth.scope.includes(WRITE))return reply({isError:true,content:[{type:"text",text:"Write scope required"}],_meta:{"mcp/www_authenticate":[`Bearer resource_metadata="${HOST}/.well-known/oauth-protected-resource/mcp-private", error="insufficient_scope", error_description="Task write scope required", scope="${READ} ${WRITE}"`]}});
    try{const fn={task_submit:taskSubmit,task_status:taskStatus,task_cancel:taskCancel}[name];const r=await fn(env.DB,owner,args);return result(r,!!r.error);}catch{return result({error:"storage_error"},true);}
  }
  if(!["checkpoint_get","checkpoint_put"].includes(name))return rpcError(-32602,"Unknown tool");
  const write=name==="checkpoint_put";
  if(write&&!ctx.auth.scope.includes(WRITE))return reply({isError:true,content:[{type:"text",text:"Write scope required"}],_meta:{"mcp/www_authenticate":[`Bearer resource_metadata="${HOST}/.well-known/oauth-protected-resource/mcp-private", error="insufficient_scope", error_description="Checkpoint write scope required", scope="${READ} ${WRITE}"`]}});
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
