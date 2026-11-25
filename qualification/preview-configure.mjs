import assert from "node:assert/strict";
import {readFileSync,mkdtempSync,writeFileSync,rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {spawnSync} from "node:child_process";
const account=process.env.CLOUDFLARE_ACCOUNT_ID,management=process.env.CLOUDFLARE_MANAGEMENT_TOKEN,read=process.env.CLOUDFLARE_API_TOKEN;
const sha=process.env.GITHUB_SHA,branch="audit/oauth-e2e-20261125",worker="execution-guard";
const names={GITHUB_CLIENT_ID:process.env.EG_PREVIEW_GITHUB_CLIENT_ID,GITHUB_CLIENT_SECRET:process.env.EG_PREVIEW_GITHUB_CLIENT_SECRET,EG_PREVIEW_TICK_SECRET:process.env.EG_PREVIEW_TICK_SECRET,EG_OWNER_GITHUB_ID:"336868992"};
const out={sha,mode:"named_preview_only",checks:{}};
const emit=()=>console.log("CF_PREVIEW_MANAGEMENT "+JSON.stringify(out));
function check(name,ok){out.checks[name]=!!ok;if(!ok)throw Error(name);}
const config=JSON.parse(readFileSync("wrangler.jsonc","utf8"));
const apiRoot="https://api.cloudflare.com/client/v4";
async function api(path,token=read){const r=await fetch(apiRoot+path,{headers:{Authorization:"Bearer "+token},redirect:"error",signal:AbortSignal.timeout(20000)});const b=await r.json().catch(()=>null);if(!r.ok||b?.success!==true)throw Error("api_http_"+r.status);return b.result;}
const prefix="/accounts/"+account;
async function production(){const r=await api(prefix+"/workers/scripts/"+worker+"/deployments");return (r.deployments||[]).slice(0,1).map(d=>({id:d.id,versions:d.versions.map(v=>({id:v.version_id,percentage:v.percentage}))}));}
function command(label,args){
 const r=spawnSync("./node_modules/.bin/wrangler",args,{encoding:"utf8",timeout:100000,maxBuffer:2*1024*1024,env:{PATH:process.env.PATH,HOME:process.env.HOME,CI:"true",CLOUDFLARE_ACCOUNT_ID:account,CLOUDFLARE_API_TOKEN:management,WRANGLER_SEND_METRICS:"false"}});
 const msg=(r.stdout||"")+"\n"+(r.stderr||"");
 const urls=[...new Set(msg.match(/https:\/\/[a-f0-9]{8}-execution-guard\.19wolf-alone92\.workers\.dev/g)||[])];
 const codes=[...new Set([...msg.matchAll(/\[code:\s*(\d+)\]/g)].map(m=>Number(m[1])))];
 out[label]={exit:r.status,urls,codes,permission_denied:/403|permission|not authorized|authentication error/i.test(msg),quota_or_limit:/quota|limit exceeded|too many|maximum number/i.test(msg),missing_preview:/preview.*not found/i.test(msg),timeout:r.error?.code==="ETIMEDOUT"};
 if(r.status!==0)throw Error(label+"_failed");
 return r.stdout;
}
let before,dir;
try{
 check("exact_target",process.env.GITHUB_REPOSITORY==="19wolfalone92/Execution-Guard"&&process.env.GITHUB_REF==="refs/heads/"+branch&&/^[a-f0-9]{40}$/.test(sha||"")&&account==="04b45c9393f4e12159c6b8118ec54791"&&config.name===worker);
 check("preview_bindings_distinct",config.previews.d1_databases.length===1&&config.previews.kv_namespaces.length===1&&config.previews.d1_databases[0].database_id==="657131f8-b0f4-47f3-ab3d-91840843f2db"&&config.previews.kv_namespaces[0].id==="25a30c61f53b422fa11889babb147fd4"&&config.d1_databases[0].database_id!==config.previews.d1_databases[0].database_id&&config.kv_namespaces[0].id!==config.previews.kv_namespaces[0].id&&config.previews.vars.EG_AUTH_ENABLED==="true"&&config.previews.vars.EG_PREVIEW_READY==="true");
 out.checks.secret_presence=Object.fromEntries(Object.entries(names).map(([k,v])=>[k,typeof v==="string"&&v.length>0]));
 check("management_token_present",!!management);check("read_token_present",!!read);
 check("all_preview_credentials_present",Object.values(out.checks.secret_presence).every(Boolean)&&names.EG_PREVIEW_TICK_SECRET.length>=32);
 check("management_token_active",(await api("/user/tokens/verify",management)).status==="active");
 before=await production();check("production_before_captured",before.length===1);out.production_before=before;
 // All mutating commands explicitly target the named Preview. Never deploy production.
 dir=mkdtempSync(join(tmpdir(),"eg-preview-"));
 const file=join(dir,"secrets.json");writeFileSync(file,JSON.stringify(names),{mode:0o600});
 const target=["--worker-name",worker,"--name",branch];
 command("secret_bulk",["preview","secret","bulk",file,...target,"--message","Isolated Preview OAuth configuration"]);
 rmSync(dir,{recursive:true,force:true});dir=undefined;
 const list=JSON.parse(command("secret_list",["preview","secret","list",...target,"--json"]));
 const items=Array.isArray(list)?list:list.secrets;
 check("four_preview_secret_names",Array.isArray(items)&&Object.keys(names).every(n=>items.some(b=>b===n||b?.name===n)));
 command("preview_deploy",["preview",...target,"--tag",sha,"--message","Execution Guard qualification "+sha,"--json"]);
 const unique=out.preview_deploy.urls;
 check("unique_deployment_url",unique.length===1);
 const stable="https://"+branch+"-"+worker+".19wolf-alone92.workers.dev";
 const r=await fetch(stable+"/qualification/readiness",{redirect:"error",signal:AbortSignal.timeout(15000)});const j=await r.json();
 const keys=["environment","auth_enabled","ready_flag","owner_id_valid","github_client_id_present","github_client_secret_present","tick_secret_configured","d1_binding_present","kv_binding_present"];
 out.readiness={http:r.status,ready:j.ready===true,checks:Object.fromEntries(keys.map(k=>[k,j.checks?.[k]===true])),d1_marker:j.d1_marker==="verified",kv_marker:j.kv_marker==="verified"};
 check("live_preview_ready",r.ok&&j.ready===true&&keys.every(k=>j.checks?.[k]===true)&&out.readiness.d1_marker&&out.readiness.kv_marker);
 const health=await fetch(stable+"/health",{redirect:"error",signal:AbortSignal.timeout(15000)});const h=await health.json();
 out.health={http:health.status,version:h.version,database:h.database,persistence:h.persistence_probe,oauth:h.oauth?.discovery};
 check("live_oauth_discovery",health.ok&&h.version==="0.6.0"&&h.database==="online"&&h.persistence_probe==="verified"&&h.oauth?.discovery==="verified");
 const u=await fetch(stable+"/mcp-private",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({jsonrpc:"2.0",id:1,method:"tools/list"}),redirect:"manual",signal:AbortSignal.timeout(15000)});
 check("unauthenticated_rejected",u.status===401);
 out.status="preview_configuration_pass";
}catch(e){out.status="blocked";out.failure=typeof e.message==="string"&&/^[a-z0-9_]+$/.test(e.message)?e.message:"unexpected_error";process.exitCode=1;}
finally{if(dir)rmSync(dir,{recursive:true,force:true});if(before){try{out.production_after=await production();out.checks.production_unchanged=JSON.stringify(before)===JSON.stringify(out.production_after);if(!out.checks.production_unchanged)process.exitCode=1;}catch{out.checks.production_unchanged=false;process.exitCode=1;}}emit();}
