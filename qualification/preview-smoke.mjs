import assert from "node:assert/strict";
import {readFileSync,writeFileSync} from "node:fs";
import {spawnSync} from "node:child_process";
import {createHash} from "node:crypto";
const repo="19wolfalone92/Execution-Guard",branch="audit/oauth-e2e-20261125",sha=process.env.GITHUB_SHA,account=process.env.CLOUDFLARE_ACCOUNT_ID,management=process.env.CLOUDFLARE_MANAGEMENT_TOKEN,read=process.env.CLOUDFLARE_API_TOKEN,tick=process.env.EG_PREVIEW_TICK_SECRET;
const host="https://audit-oauth-e2e-20261125-execution-guard.19wolf-alone92.workers.dev";
const out={sha,checks:{},automatic_build:null};
const check=(name,ok)=>{out.checks[name]=Boolean(ok);assert.ok(ok,name);};
const req=(base,p,opts={})=>fetch(base+p,{...opts,redirect:"manual",signal:AbortSignal.timeout(20000)});
const get=async(base,p,opts={})=>{const r=await req(base,p,opts);return {http:r.status,body:await r.json().catch(()=>null)};};
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const cf=async(path,token=read)=>{const x=await get("https://api.cloudflare.com/client/v4","/accounts/"+account+path,{headers:{Authorization:"Bearer "+token}});return {http:x.http,ok:x.body?.success===true,result:x.body?.result,errors:(x.body?.errors||[]).map(e=>e.code).filter(Number.isInteger)};};
const prod=async()=>{const x=await cf("/workers/scripts/execution-guard/deployments");assert.ok(x.ok);return x.result.deployments.slice(0,1).map(d=>({id:d.id,versions:d.versions.map(v=>({id:v.version_id,percentage:v.percentage}))}));};
const config=JSON.parse(readFileSync("wrangler.jsonc","utf8"));
let before;
const proof="eg-qualification-browser-a34bbee1-4df0-4938-9f42-7c8751e44f50-p",project=proof.slice(0,-2),workflow="15992bad-d1dd-4b48-98cb-5b57c6ec635b",owner="336868992";
const digest=x=>createHash("sha256").update(JSON.stringify(x)).digest("hex");
async function snapshot(){
 const queries=[
 ["checkpoint","SELECT revision,value,updated_at FROM eg_checkpoints WHERE owner=? AND project IN (?,?) ORDER BY project",[owner,proof,"eg-qualification-"+workflow]],
 ["project","SELECT revision,value,updated_at FROM eg_projects WHERE owner=? AND project=?",[owner,project]],
 ["history","SELECT revision,value,updated_at FROM eg_project_history WHERE owner=? AND project=? ORDER BY revision",[owner,project]],
 ["workflow","SELECT id,state,updated_at FROM eg_workflows WHERE owner=? AND project=? AND id=?",[owner,project,workflow]],
 ["steps","SELECT id,state,attempts,result,evidence FROM eg_workflow_steps WHERE owner=? AND project=? AND workflow_id=? ORDER BY step_key",[owner,project,workflow]]
 ];
 const result={};for(const [key,sql,params] of queries){
 const response=await get("https://api.cloudflare.com/client/v4","/accounts/"+account+"/d1/database/657131f8-b0f4-47f3-ab3d-91840843f2db/query",{method:"POST",headers:{Authorization:"Bearer "+read,"Content-Type":"application/json"},body:JSON.stringify({sql,params})});
 assert.ok(response.http===200&&response.body?.success);const rows=response.body.result[0].results;assert.ok(rows.length>0);result[key]={count:rows.length,sha256:digest(rows)};
 }return result;
}

try{
 check("exact_checkout",process.env.GITHUB_REPOSITORY===repo&&process.env.GITHUB_REF==="refs/heads/"+branch&&/^[a-f0-9]{40}$/.test(sha||"")&&spawnSync("git",["rev-parse","HEAD"],{encoding:"utf8"}).stdout.trim()===sha);
 check("account_and_credentials",account==="04b45c9393f4e12159c6b8118ec54791"&&!!management&&!!read&&tick?.length>=32);
 check("isolated_config",config.name==="execution-guard"&&config.previews.vars.EG_ENVIRONMENT==="preview"&&config.previews.vars.EG_AUTH_ENABLED==="true"&&config.previews.vars.EG_PREVIEW_READY==="true"&&config.previews.d1_databases.length===1&&config.previews.kv_namespaces.length===1&&config.previews.d1_databases[0].database_id==="657131f8-b0f4-47f3-ab3d-91840843f2db"&&config.previews.kv_namespaces[0].id==="25a30c61f53b422fa11889babb147fd4"&&config.d1_databases.every(d=>d.database_id!==config.previews.d1_databases[0].database_id)&&config.kv_namespaces.every(k=>k.id!==config.previews.kv_namespaces[0].id));
 before=await prod();out.production_before=before;
 out.memory_before=await snapshot();
 // Wait for the automatic build to settle so it cannot overwrite the tagged direct deployment.
 let build;
 for(let i=0;i<24;i++){
   const r=await get("https://api.github.com","/repos/"+repo+"/commits/"+sha+"/check-runs",{headers:{Authorization:"Bearer "+process.env.GITHUB_TOKEN,Accept:"application/vnd.github+json","User-Agent":"eg-preview"}});
   check("github_checks_access",r.http===200);
   build=r.body?.check_runs?.find(x=>x.name==="Workers Builds: execution-guard");
   if(build?.status==="completed")break;
   await sleep(10000);
 }
 check("automatic_build_settled",build?.status==="completed");
 out.automatic_build={conclusion:build.conclusion,id:build.id,details_url:build.details_url};
 const buildId=build.details_url?.match(/\/builds\/([a-f0-9-]{36})$/)?.[1];
 if(buildId){
   const logs=await cf("/builds/builds/"+buildId+"/logs",management);
   const raw=JSON.stringify(logs.result||"");
   out.automatic_build.logs={http:logs.http,ok:logs.ok,errors:logs.errors,authentication_error:/Authentication error/i.test(raw),authorization_error:/Authorization error/i.test(raw),permission_error:/not authorized|insufficient permission|permission denied/i.test(raw),codes:[...new Set([...raw.matchAll(/\[code:\s*(\d+)\]/g)].map(x=>Number(x[1])))],missing_previews:/missing a.*previews/i.test(raw),quota:/quota|limit exceeded|too many/i.test(raw),rate_limited:/rate.limit|retry_after_ms|10429/i.test(raw)};
 }
 // Install only the optional, repository-scoped read credential into the named Preview.
 const gitRead=process.env.EG_PREVIEW_GITHUB_READ_TOKEN;
 out.github_credential={provided:!!gitRead,installed:false};
 if(gitRead){
   // Validate the token against all needed read endpoints before any configuration write.
   const target="https://api.github.com/repos/"+repo;
   const headers={Authorization:"Bearer "+gitRead,Accept:"application/vnd.github+json","User-Agent":"eg-qualification","X-GitHub-Api-Version":"2022-11-28"};
   const responses=await Promise.all(["","/git/ref/heads/"+branch,"/commits/"+sha+"/status","/actions/runs?head_sha="+sha+"&per_page=1"].map(path=>fetch(target+path,{headers,redirect:"error",signal:AbortSignal.timeout(15000)})));
   out.github_credential.validation_http=responses.map(r=>r.status);check("github_read_credential_valid",responses.every(r=>r.ok));
   const put=spawnSync("./node_modules/.bin/wrangler",["preview","secret","put","EG_GITHUB_READ_TOKEN","--worker-name","execution-guard","--name",branch],{input:gitRead+"\n",encoding:"utf8",timeout:60000,maxBuffer:1024*1024,env:{PATH:process.env.PATH,HOME:process.env.HOME,CI:"true",CLOUDFLARE_ACCOUNT_ID:account,CLOUDFLARE_API_TOKEN:management,WRANGLER_SEND_METRICS:"false"}});
   out.github_credential.installed=put.status===0;check("github_read_credential_installed",put.status===0);
 }
 // Deploy only the isolated named Preview, with exact checked-out SHA in its runtime vars.
 config.previews.vars.EG_RELEASE_SHA=sha;writeFileSync("wrangler.jsonc",JSON.stringify(config,null,2)+"\n");
 const result=spawnSync("./node_modules/.bin/wrangler",["preview","--worker-name","execution-guard","--name",branch,"--tag",sha,"--message","Exact SHA qualification "+sha,"--json"],{encoding:"utf8",timeout:120000,maxBuffer:2*1024*1024,env:{PATH:process.env.PATH,HOME:process.env.HOME,CI:"true",CLOUDFLARE_ACCOUNT_ID:account,CLOUDFLARE_API_TOKEN:management,WRANGLER_SEND_METRICS:"false"}});
 const output=(result.stdout||"")+"\n"+(result.stderr||"");
 const unique=[...new Set(output.match(/https:\/\/[a-f0-9]{8}-execution-guard\.19wolf-alone92\.workers\.dev/g)||[])];
 out.direct_deploy={exit:result.status,urls:unique,codes:[...new Set([...output.matchAll(/\[code:\s*(\d+)\]/g)].map(x=>Number(x[1])))]};
 try{const j=JSON.parse(result.stdout);for(const k of ["preview_id","deployment_id","version_id"]){if(typeof j[k]==="string"&&/^[a-f0-9-]{32,36}$/.test(j[k]))out.direct_deploy[k]=j[k];}}catch{}
 check("direct_deploy",result.status===0&&unique.length===1);
 const immutable=unique[0];
 let sv,iv;
 for(let i=0;i<15;i++){
   try{[sv,iv]=await Promise.all([get(host,"/qualification/version"),get(immutable,"/qualification/version")]);if(sv.body?.sha===sha&&iv.body?.sha===sha&&sv.body?.version_id===iv.body?.version_id&&/^[a-f0-9-]{36}$/.test(sv.body?.version_id||""))break;}catch{}
   await sleep(4000);
 }
 out.version={stable:sv?.body,immutable:iv?.body};
 check("exact_runtime_version",sv?.http===200&&iv?.http===200&&sv.body?.sha===sha&&iv.body?.sha===sha&&sv.body.version_id===iv.body.version_id&&/^[a-f0-9-]{36}$/.test(sv.body.version_id));
 const h=await get(immutable,"/health");check("immutable_storage_guard",h.http===200&&h.body?.version==="0.6.0"&&h.body?.database==="not_verified"&&h.body?.oauth_storage==="not_bound"&&h.body?.storage_guard?.state==="blocked"&&h.body.storage_guard.d1_binding_present===true&&h.body.storage_guard.kv_binding_present===true);
 check("immutable_private_denied",(await req(immutable,"/mcp-private",{method:"POST",body:"{}"})).status===404);
 check("immutable_tick_denied",(await req(immutable,"/qualification/tick",{method:"POST"})).status===404);
 let readiness;
 for(let i=0;i<15;i++){try{readiness=await get(host,"/qualification/readiness");if(readiness.body?.ready)break;}catch{}await sleep(4000);}
 check("stable_readiness",readiness?.http===200&&readiness.body?.ready===true&&Object.values(readiness.body.checks).every(Boolean)&&readiness.body.d1_marker==="verified"&&readiness.body.kv_marker==="verified");
 const health=await get(host,"/health");check("stable_health",health.http===200&&health.body?.version==="0.6.0"&&health.body?.database==="online"&&health.body?.persistence_probe==="verified"&&health.body?.oauth?.discovery==="verified");
 const unauthorized=await req(host,"/mcp-private",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({jsonrpc:"2.0",id:1,method:"tools/list"})});
 check("private_auth_required",unauthorized.status===401);
 const provision=await get(host,"/qualification/tick",{method:"POST",headers:{Authorization:"Bearer "+tick}});
 check("provision_tick",provision.http===200&&provision.body?.status==="tick_completed");
 const probe=await get(host,"/qualification/tick?diagnostic=github",{method:"POST",headers:{Authorization:"Bearer "+tick}});out.github_worker_probe={http:probe.http,body:probe.body};
 let page;for(let i=0;i<20;i++){try{page=await req(host,"/qualification/oauth");if(page.status===200)break;}catch{}await sleep(3000);}
 check("browser_authorization_ready",page?.status===200&&(await page.text()).includes("Начать проверку"));
 const js=await req(host,"/qualification/oauth.js");check("browser_script_available",js.status===200&&js.headers.get("Content-Type")?.includes("javascript"));
 check("production_browser_route_denied",(await req("https://execution-guard.19wolf-alone92.workers.dev","/qualification/oauth")).status===404);
 out.memory_after=await snapshot();check("prior_live_memory_preserved",JSON.stringify(out.memory_before)===JSON.stringify(out.memory_after));
 check("prior_dag_seven_steps",out.memory_after.steps.count===7);
 out.status="DIRECT_PREVIEW_PASS";
}catch(e){out.status="FAILED";out.failure=e?.name==="AssertionError"&&/^[a-z_]+$/.test(e.message)?e.message:"request_or_execution_error";process.exitCode=1;}
finally{if(before){try{out.production_after=await prod();out.checks.production_unchanged=JSON.stringify(before)===JSON.stringify(out.production_after);if(!out.checks.production_unchanged)process.exitCode=1;}catch{out.checks.production_unchanged=false;process.exitCode=1;}}console.log("EXACT_PREVIEW_EVIDENCE "+JSON.stringify(out));}
