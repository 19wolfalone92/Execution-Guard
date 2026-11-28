import assert from "node:assert/strict";
import {createHash,randomBytes} from "node:crypto";
import {deploymentMetadata} from "./backup-evidence.mjs";
const host="https://audit-oauth-e2e-20261125-execution-guard.19wolf-alone92.workers.dev",prod="https://execution-guard.19wolf-alone92.workers.dev";
const account=process.env.CLOUDFLARE_ACCOUNT_ID,read=process.env.CLOUDFLARE_API_TOKEN,manage=process.env.CLOUDFLARE_MANAGEMENT_TOKEN,tick=process.env.EG_PREVIEW_TICK_SECRET;
// The probes below inspect OAuth and resource state. They cannot authenticate an
// independently retrieved backup/restore artifact or qualify its source snapshot.
const out={sha:process.env.GITHUB_SHA,checked_at:new Date().toISOString(),status:"BLOCKED",blockers:["independently_verified_backup_restore_required"],checks:{},api:{}};
const check=(n,b)=>{out.checks[n]=Boolean(b);};
const req=(base,path,options={})=>fetch(base+path,{...options,redirect:"manual",signal:AbortSignal.timeout(20000)});
const get=async(base,path,options={})=>{const r=await req(base,path,options);return {http:r.status,body:await r.json().catch(()=>null)};};
const api=async(n,path,token=read,method="GET",body)=>{try{const x=await get("https://api.cloudflare.com/client/v4",path,{method,headers:{Authorization:"Bearer "+token,...(body?{"Content-Type":"application/json"}:{})},...(body?{body:JSON.stringify(body)}:{})});out.api[n]={http:x.http,ok:x.body?.success===true,error_codes:(x.body?.errors||[]).map(e=>e.code).filter(Number.isInteger)};return x.body?.success===true?x.body.result:null;}catch{out.api[n]={ok:false};return null;}};
const prefix="/accounts/"+account;
try{
 assert.equal(process.env.GITHUB_REPOSITORY,"19wolfalone92/Execution-Guard");
 assert.match(out.sha||"",/^[a-f0-9]{40}$/);
 assert.equal(account,"04b45c9393f4e12159c6b8118ec54791");assert.equal(process.env.GITHUB_REF,"refs/heads/audit/oauth-e2e-20261125");assert.ok(read&&manage&&tick?.length>=32);
 const before=await api("production_deployments",prefix+"/workers/scripts/execution-guard/deployments");
 out.production=(before?.deployments||[]).slice(0,1).map(d=>({id:d.id,versions:d.versions.map(v=>({id:v.version_id,percentage:v.percentage}))}));
 check("production_deployment_verified",deploymentMetadata(out.production));
 const bookmark=await api("production_bookmark",prefix+"/d1/database/e7699170-b634-48ce-a3b0-733aedb9b898/time_travel/bookmark");out.bookmark=typeof bookmark?.bookmark==="string"&&/^[a-f0-9-]+$/i.test(bookmark.bookmark)?bookmark.bookmark:null;
 const scripts=await api("workers",prefix+"/workers/scripts");const tag=(Array.isArray(scripts)?scripts:[]).find(s=>s.id==="execution-guard")?.tag;
 if(tag&&/^[a-f0-9-]{32,36}$/.test(tag)){
   const tr=await api("build_triggers",prefix+"/builds/workers/"+tag+"/triggers",manage);
   out.triggers=(Array.isArray(tr)?tr:[]).map(t=>({id:t.trigger_uuid,includes:t.branch_includes,excludes:t.branch_excludes,deploy_command_known:["npx wrangler versions upload","npx wrangler deploy","npx wrangler preview","npx wrangler preview --ignore-base-config"].includes(t.deploy_command)?t.deploy_command:"other"}));
 }
 check("controlled_production_trigger",out.triggers?.some(t=>t.id==="9ee2b6ad-e77b-48ce-833c-5bbcd9f4af83"&&JSON.stringify(t.includes)===JSON.stringify(["main"])&&t.deploy_command_known==="npx wrangler versions upload"));
 const logs=await api("build_logs_management",prefix+"/builds/builds/c6cf387b-24fa-4f68-ad99-6f43bb9195ca/logs",manage);
 if(logs){const raw=JSON.stringify(logs);out.build_log_indicators={received:true,quota:/quota|limit exceeded|too many/i.test(raw),auth:/authentication|permission|not authorized/i.test(raw),missing_previews:/missing a.*previews/i.test(raw),error_marker:/\[ERROR\]/.test(raw)};}
 const health=await get(prod,"/health");out.production_health={http:health.http,version:health.body?.version,db:health.body?.database,oauth:health.body?.oauth?.discovery};
 const readiness=await get(host,"/qualification/readiness");check("readiness",readiness.http===200&&readiness.body?.ready===true&&Object.values(readiness.body.checks).every(Boolean)&&readiness.body.d1_marker==="verified"&&readiness.body.kv_marker==="verified");
 assert.ok(out.checks.readiness);
 const forbidden=await req(host,"/qualification/tick",{method:"POST"});check("tick_requires_secret",forbidden.status===403);
 const prodTick=await req(prod,"/qualification/tick",{method:"POST"});check("production_tick_unavailable",prodTick.status===404);
 const initial=await get(host,"/oauth/client-info");out.client_before={http:initial.http,status:initial.body?.status};
 if(initial.body?.status!=="ready"){
   const result=await get(host,"/qualification/tick",{method:"POST",headers:{Authorization:"Bearer "+tick}});check("provision_tick",result.http===200&&result.body?.status==="tick_completed");
 }
 let client;
 for(let i=0;i<8;i++){client=await get(host,"/oauth/client-info");if(client.http===200&&client.body?.status==="ready")break;await new Promise(r=>setTimeout(r,2000));}
 check("registered_client",client.http===200&&client.body?.status==="ready"&&client.body.redirect_uri==="https://chatgpt.com/connector_platform_oauth_redirect"&&client.body.token_endpoint_auth_method==="none"&&typeof client.body.client_id==="string");
 if(out.checks.registered_client)out.client={id:client.body.client_id,redirect_uri:client.body.redirect_uri,auth_method:client.body.token_endpoint_auth_method};
 const m=await get(host,"/.well-known/oauth-authorization-server"),resource=host+"/mcp-private",rm=await get(host,"/.well-known/oauth-protected-resource/mcp-private");
 check("metadata",m.http===200&&m.body?.issuer===host&&m.body.authorization_endpoint===host+"/authorize"&&m.body.token_endpoint===host+"/oauth/token"&&m.body.code_challenge_methods_supported?.includes("S256"));
 check("resource_metadata",rm.http===200&&rm.body?.resource===resource&&rm.body.authorization_servers?.includes(host));
 const params=new URLSearchParams({response_type:"code",client_id:client.body?.client_id||"unavailable",redirect_uri:"https://chatgpt.com/connector_platform_oauth_redirect",scope:"eg:read eg:write",resource,state:randomBytes(24).toString("hex"),code_challenge:createHash("sha256").update(randomBytes(48).toString("base64url")).digest("base64url"),code_challenge_method:"S256"});
 const auth=await req(host,"/authorize?"+params);check("consent_page",auth.status===200&&(await auth.text()).includes("Continue to GitHub"));
 const bad=new URLSearchParams(params);bad.set("redirect_uri","https://example.invalid/callback");const rejected=await req(host,"/authorize?"+bad);check("wrong_redirect_rejected",rejected.status>=400);
 const noPkce=new URLSearchParams(params);noPkce.delete("code_challenge");noPkce.delete("code_challenge_method");const no=await req(host,"/authorize?"+noPkce);check("pkce_required",no.status>=400||((no.status===302||no.status===303)&&new URL(no.headers.get("Location"),host).searchParams.has("error")));
 const cb=await req(host,"/callback?state=invalid&code=invalid");check("invalid_callback_rejected",cb.status>=400);
 const token=await get(host,"/oauth/token",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:new URLSearchParams({grant_type:"refresh_token",client_id:client.body?.client_id||"unavailable",refresh_token:"invalid-test-token",resource})});check("invalid_refresh_rejected",token.http>=400);
 const mcp=await req(host,"/mcp-private",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({jsonrpc:"2.0",id:1,method:"tools/list"})});check("unauthorized_mcp",mcp.status===401);
 const after=await api("production_after",prefix+"/workers/scripts/execution-guard/deployments");
 const deployments=(after?.deployments||[]).slice(0,1).map(d=>({id:d.id,versions:d.versions.map(v=>({id:v.version_id,percentage:v.percentage}))}));
 check("production_unchanged",deploymentMetadata(out.production)&&deploymentMetadata(deployments)&&JSON.stringify(out.production)===JSON.stringify(deployments));
}catch(e){out.failure=e?.name==="AssertionError"?"assertion_failed":"request_failed";}
console.log("EG_RELEASE_PREFLIGHT "+JSON.stringify(out));
process.exitCode=1;
