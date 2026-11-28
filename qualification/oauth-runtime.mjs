import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Miniflare, createFetchMock } from "miniflare";
import { mcpSuiteSource } from "../mcp-suite.mjs";

const config=JSON.parse(readFileSync("wrangler.jsonc","utf8"));
const script=readdirSync(".oauth-build").filter(x=>/\.(m?js)$/.test(x));
assert.equal(script.length,1,"Expected one bundled Worker entry point");
const preview=process.env.EG_TEST_PREVIEW==="1";
const host=preview?"https://audit-oauth-e2e-20261125-execution-guard.19wolf-alone92.workers.dev":"https://execution-guard.19wolf-alone92.workers.dev";
const testTickSecret="qualification-only-test-secret-0123456789";
const resource=host+"/mcp-private";
const redirect="https://chatgpt.com/connector_platform_oauth_redirect";
const owner="123456";
const upstreamToken="qualification-fake-github-token";
const mock=createFetchMock();
mock.disableNetConnect();
const candidatePath=".oauth-build/"+script[0];
const baselinePath=process.env.EG_BASELINE_BUNDLE;
const persistence=mkdtempSync(join(tmpdir(),"eg-migration-"));
const options=scriptPath=>({
  modules:true,scriptPath,kvPersist:join(persistence,"kv"),d1Persist:join(persistence,"d1"),
  // Installed workerd 4.x test binary supports dates through 2026-08-06.
  // This is a test-only cap; production Wrangler configuration is unchanged.
  compatibilityDate:config.compatibility_date>"2026-08-06"?"2026-08-06":config.compatibility_date,
  compatibilityFlags:config.compatibility_flags,
  bindings:{EG_AUTH_ENABLED:"true",EG_OWNER_GITHUB_ID:owner,GITHUB_CLIENT_ID:"qualification-client",GITHUB_CLIENT_SECRET:"qualification-secret",...(preview?{EG_ENVIRONMENT:"preview",EG_PREVIEW_READY:"true",EG_PREVIEW_TICK_SECRET:testTickSecret,EG_PREVIEW_BROWSER_QUALIFICATION:"true",EG_RELEASE_SHA:"b".repeat(40)}:{})},
  kvNamespaces:["OAUTH_KV"],d1Databases:["DB"],fetchMock:mock,cf:false
});
let mf=new Miniflare(options(baselinePath||candidatePath));
async function switchWorker(path){await mf.dispose();mf=new Miniflare(options(path));await mf.ready;}
const testDb=await mf.getD1Database("DB");
await testDb.exec(readFileSync("probe.sql","utf8"));
if(preview){
  await testDb.exec("CREATE TABLE eg_preview_identity(id INTEGER PRIMARY KEY,value TEXT NOT NULL);");
  await testDb.exec("INSERT INTO eg_preview_identity(id,value) VALUES(1,'execution-guard-preview-v1');");
  await (await mf.getKVNamespace("OAUTH_KV")).put("eg:preview:identity","execution-guard-preview-v1");
}
let checks=0;
function ok(condition,label){assert.ok(condition,label);checks++;console.log("PASS "+label);}
const sha=v=>createHash("sha256").update(v).digest("base64url");
const form=v=>new URLSearchParams(v).toString();
function call(path,opts={}){return mf.dispatchFetch(new URL(path,host).href,{...opts,redirect:"manual"});}
function cookies(response,jar=new Map()){
  const all=response.headers.getSetCookie?.()??(response.headers.get("set-cookie")||"").split(/,(?=\s*[^;,=]+=[^;,]*)/);
  for(const c of all){if(!c)continue;const pair=c.split(";")[0],index=pair.indexOf("=");if(index<0)continue;const k=pair.slice(0,index).trim(),v=pair.slice(index+1);if(v)jar.set(k,v);else jar.delete(k);}
  return jar;
}
const cookieHeader=jar=>Array.from(jar,([k,v])=>k+"="+v).join("; ");
async function json(response){const body=await response.text();assert.match(response.headers.get("Content-Type")||"",/json/i,"Expected JSON, status "+response.status);return JSON.parse(body);}
async function tick(){
  if(preview){const r=await call("/qualification/tick",{method:"POST",headers:{Authorization:"Bearer "+testTickSecret}});assert.equal(r.status,200,await r.clone().text());}
  else await (await mf.getWorker()).scheduled({cron:"*/5 * * * *"});
}
async function provision(){
  await tick();
  for(let i=0;i<50;i++){const r=await call("/oauth/client-info");const b=await json(r);if(b.status==="ready"){ok(r.status===200&&b.redirect_uri===redirect&&b.token_endpoint_auth_method==="none"&&typeof b.client_id==="string","registered public client");return b.client_id;}await new Promise(resolve=>setTimeout(resolve,100));}
  assert.fail("Scheduled provisioning did not produce a client");
}
let clientId;
const verifier="A".repeat(64);
function authorizationURL(scope="eg:read eg:write",changes={}){
  return "/authorize?"+form({response_type:"code",client_id:clientId,redirect_uri:redirect,scope,resource,state:"test-chatgpt-state",code_challenge:sha(verifier),code_challenge_method:"S256",...changes});
}
async function begin(scope){
  const r=await call(authorizationURL(scope));
  assert.equal(r.status,200,await r.clone().text());
  const html=await r.text();const handle=html.match(/name="handle" value="([^"]+)"/)?.[1];assert.ok(handle,"consent handle");
  return {jar:cookies(r),handle};
}
async function approve(scope){
  const {jar,handle}=await begin(scope);
  const r=await call("/authorize",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded",Cookie:cookieHeader(jar)},body:form({decision:"approve",handle})});
  assert.equal(r.status,303,await r.clone().text());cookies(r,jar);
  const target=new URL(r.headers.get("Location"));
  assert.equal(target.origin,"https://github.com");
  assert.equal(target.pathname,"/login/oauth/authorize");
  assert.equal(target.searchParams.get("redirect_uri"),host+"/callback");
  assert.equal(target.searchParams.get("code_challenge_method"),"S256");
  assert.ok(target.searchParams.get("code_challenge"));
  return {jar,state:target.searchParams.get("state")};
}
function fakeGitHub(id,status=200){
  mock.get("https://github.com").intercept({path:"/login/oauth/access_token",method:"POST"}).reply(200,JSON.stringify({access_token:upstreamToken,token_type:"bearer"}),{headers:{"content-type":"application/json"}});
  mock.get("https://api.github.com").intercept({path:"/user",method:"GET",headers:{authorization:"Bearer "+upstreamToken}}).reply(status,JSON.stringify({id}),{headers:{"content-type":"application/json"}});
}
function callback(flow,withCookie=true){return call("/callback?"+form({state:flow.state,code:"qualification-code"}),{headers:withCookie?{Cookie:cookieHeader(flow.jar)}:{}});}
async function issue(scope){
  const flow=await approve(scope);fakeGitHub(Number(owner));
  const r=await callback(flow);assert.equal(r.status,302,await r.clone().text());
  const u=new URL(r.headers.get("Location"));assert.equal(u.origin+u.pathname,redirect);
  assert.equal(u.searchParams.get("state"),"test-chatgpt-state");
  assert.equal(u.searchParams.get("iss"),host);
  const code=u.searchParams.get("code");assert.ok(code);
  return {code,flow};
}
function tokenRequest(params){return call("/oauth/token",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded",Accept:"application/json"},body:form(params)});}
function exchange(code,proof=verifier){return tokenRequest({grant_type:"authorization_code",client_id:clientId,code,redirect_uri:redirect,code_verifier:proof,resource});}
let rpcId=0;
async function rpc(access,method,params={}){
  const r=await call("/mcp-private",{method:"POST",headers:{Authorization:"Bearer "+access,"Content-Type":"application/json",Accept:"application/json, text/event-stream","MCP-Protocol-Version":"2025-11-25"},body:JSON.stringify({jsonrpc:"2.0",id:++rpcId,method,params})});
  assert.equal(r.status,200,await r.clone().text());
  const b=await json(r);assert.equal(b.jsonrpc,"2.0");assert.equal(b.id,rpcId);assert.ok(!b.error,JSON.stringify(b.error));return b.result;
}
async function tool(access,name,args={}){return rpc(access,"tools/call",{name,arguments:args});}
const value=r=>JSON.parse(r.content[0].text);
try{
  const deniedTick=await call("/qualification/tick",{method:"POST"});
  ok(deniedTick.status===(preview?403:404),"qualification tick denied without separate secret or outside Preview");
  const meta=await json(await call("/.well-known/oauth-authorization-server"));
  ok(meta.issuer===host&&meta.authorization_endpoint===host+"/authorize"&&meta.token_endpoint===host+"/oauth/token"&&meta.authorization_response_iss_parameter_supported===true&&meta.code_challenge_methods_supported.includes("S256")&&meta.token_endpoint_auth_methods_supported.includes("none"),"authorization metadata, issuer and S256");
  const resMeta=await json(await call("/.well-known/oauth-protected-resource/mcp-private"));
  ok(resMeta.resource===resource&&resMeta.authorization_servers.includes(host),"protected resource audience");
  const unauthorized=await call("/mcp-private",{method:"POST",headers:{"Content-Type":"application/json"},body:'{"jsonrpc":"2.0","id":1,"method":"tools/list"}'});
  ok(unauthorized.status===401&&/resource_metadata=/.test(unauthorized.headers.get("WWW-Authenticate")||""),"unauthenticated MCP discovery challenge");
  clientId=await provision();
  if(preview){
    const page=await call("/qualification/oauth");ok(page.status===200,"isolated browser qualification page available");
    const html=await page.text();const browserId=html.match(/name="client-id" content="([^"]+)"/)?.[1];ok(!!browserId&&browserId!==clientId,"separate fixed-return public qualification client");
    const consent=await call(authorizationURL(undefined,{client_id:browserId,redirect_uri:host+"/qualification/oauth/return"}));ok(consent.status===200,"browser qualification client accepts exact redirect");
    const bad=await call(authorizationURL(undefined,{client_id:browserId,redirect_uri:"https://example.invalid/callback"}));ok(bad.status>=400,"browser qualification rejects wrong redirect");
  }
  const unknown=await call(authorizationURL(undefined,{client_id:"unapproved"}));ok(unknown.status===403,"unknown client rejected");
  const unsafe=await call(authorizationURL(undefined,{redirect_uri:"https://example.invalid/callback"}));ok(unsafe.status>=400,"unregistered redirect rejected");
  const noPkce=await call(authorizationURL(undefined,{code_challenge:"",code_challenge_method:""}));ok(noPkce.status>=400||new URL(noPkce.headers.get("Location")||host).searchParams.has("error"),"missing PKCE rejected");
  const denied=await begin();const deny=await call("/authorize",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded",Cookie:cookieHeader(denied.jar)},body:form({decision:"deny",handle:denied.handle})});
  const denyUrl=new URL(deny.headers.get("Location"));ok(deny.status===302&&denyUrl.origin+denyUrl.pathname===redirect&&denyUrl.searchParams.get("error")==="access_denied"&&denyUrl.searchParams.get("iss")===host,"consent denial returns valid OAuth error");
  const wrong=await approve();fakeGitHub(999999);const forbidden=await callback(wrong);
  ok(forbidden.status===403&&(await forbidden.text()).includes("owner_required"),"non-owner cannot receive authorization code");
  const noCookie=await approve();const rejected=await callback(noCookie,false);
  ok(rejected.status===400&&(await rejected.text()).includes("browser_cookie_missing"),"callback without session cookie rejected");
  const {code,flow}=await issue();ok(true,"real library issues authorization code after owner verification");
  const replayCallback=await callback(flow);ok(replayCallback.status===400,"consumed upstream transaction cannot replay");
  const bad=await exchange(code,"B".repeat(64));ok(bad.status>=400,"incorrect PKCE verifier rejected");
  const tokenResponse=await exchange(code);assert.equal(tokenResponse.status,200,await tokenResponse.clone().text());const tokens=await json(tokenResponse);
  ok(typeof tokens.access_token==="string"&&typeof tokens.refresh_token==="string"&&tokens.token_type.toLowerCase()==="bearer","authorization code exchanged for MCP tokens");
  const refreshResponse=await tokenRequest({grant_type:"refresh_token",client_id:clientId,refresh_token:tokens.refresh_token,resource});
  assert.equal(refreshResponse.status,200,await refreshResponse.clone().text());
  const refreshedTokens=await json(refreshResponse);
  ok(typeof refreshedTokens.access_token==="string"&&refreshedTokens.token_type.toLowerCase()==="bearer","refresh token grant issues a new MCP access token");
  const invalidRefresh=await tokenRequest({grant_type:"refresh_token",client_id:clientId,refresh_token:"invalid-refresh-token",resource});
  ok(invalidRefresh.status>=400,"invalid refresh token rejected");
  const refreshedWho=value(await tool(refreshedTokens.access_token,"whoami"));
  ok(refreshedWho.authenticated&&refreshedWho.owner_verified,"refreshed access token is accepted by protected MCP");
  const init=await rpc(tokens.access_token,"initialize",{protocolVersion:"2025-11-25",capabilities:{},clientInfo:{name:"qualification",version:"1"}});
  ok(init.serverInfo.name==="execution-guard-private"&&init.protocolVersion==="2025-11-25","MCP initialize");
  const notification=await call("/mcp-private",{method:"POST",headers:{Authorization:"Bearer "+tokens.access_token,"Content-Type":"application/json"},body:JSON.stringify({jsonrpc:"2.0",method:"notifications/initialized"})});ok(notification.status===202,"MCP initialized notification");
  const legacyTools=await rpc(tokens.access_token,"tools/list");ok(["whoami","checkpoint_get","checkpoint_put","task_submit","task_status","task_cancel"].every(x=>legacyTools.tools.some(t=>t.name===x)),"legacy MCP tools discovered");
  const latestInit=await rpc(tokens.access_token,"initialize",{protocolVersion:"2026-07-28",capabilities:{},clientInfo:{name:"qualification-latest",version:"1"}});ok(latestInit.protocolVersion==="2026-07-28","latest supported MCP protocol version");
  const who=value(await tool(tokens.access_token,"whoami"));ok(who.authenticated&&who.owner_verified&&who.scopes.includes("eg:write"),"authenticated owner and scope");
  const tickRequest=access=>call("/mcp-private",{method:"POST",headers:{"Content-Type":"application/json",...(access?{Authorization:"Bearer "+access}:{})},body:JSON.stringify({jsonrpc:"2.0",id:1009,method:"qualification/tick",params:{proof_project:"eg-qualification-browser-00000000-0000-4000-8000-000000000001-p"}})});
  ok((await tickRequest(null)).status===401,"owner qualification tick rejects no token");
  const noSession=await json(await tickRequest(tokens.access_token));ok(!!noSession.error,"owner qualification tick rejects missing session or production");
  if(preview){
    const project="eg-qualification-browser-00000000-0000-4000-8000-000000000001",proof_project=project+"-p";
    ok(value(await tool(tokens.access_token,"project_create",{project,record:{goal:"Owner tick fixture"}})).status==="created","owner tick project created");
    const w=value(await tool(tokens.access_token,"workflow_create",{project,name:"owner tick test",idempotency_key:"owner-tick-test",steps:[{key:"health",operation:"health_probe",input:{}}]}));
    ok(w.status==="created","owner tick fixture created");const ref={project,workflow_id:w.workflow_id};
    ok(value(await tool(tokens.access_token,"workflow_start",ref)).status==="started","owner tick fixture queued");
    const proof={project,proof_project,sha:"b".repeat(40),state:"QUEUED",owner_verified:true,workflow_id:w.workflow_id,control_id:w.workflow_id};
    ok(value(await tool(tokens.access_token,"checkpoint_put",{project:proof_project,expected_revision:0,value:JSON.stringify(proof)})).status==="saved","owner tick session persisted");
    const progressed=await json(await tickRequest(tokens.access_token));ok(progressed.result?.environment==="preview"&&progressed.result.executed===1,"owner-scoped bounded tick executes existing scheduler");
    ok(value(await tool(tokens.access_token,"workflow_status",ref)).workflow.state==="SUCCEEDED","owner tick workflow persisted");
  }
  const saved=value(await tool(tokens.access_token,"checkpoint_put",{project:"qualification",expected_revision:0,value:"proof"}));ok(saved.status==="saved"&&saved.revision===1,"D1 checkpoint write");
  const got=value(await tool(tokens.access_token,"checkpoint_get",{project:"qualification"}));ok(got.found&&got.value==="proof"&&got.revision===1,"D1 checkpoint readback");
  const conflict=await tool(tokens.access_token,"checkpoint_put",{project:"qualification",expected_revision:0,value:"wrong"});ok(conflict.isError&&value(conflict).status==="conflict","checkpoint revision conflict rejected");
  const queued=value(await tool(tokens.access_token,"task_submit",{project:"qualification",idempotency_key:"qualification1",kind:"sha256_verify",payload:{text:"proof",expected_sha256:createHash("sha256").update("proof").digest("hex")}}));
  ok(queued.state==="queued","durable task submitted");
  await tick();
  let final;
  for(let i=0;i<50;i++){final=value(await tool(tokens.access_token,"task_status",{project:"qualification",task_id:queued.task_id}));if(final.state==="succeeded")break;await new Promise(resolve=>setTimeout(resolve,100));}
ok(final.state==="succeeded"&&final.result.verified===true,"scheduled task completed and result verified");
  if(baselinePath){
    ok(init.serverInfo.version==="0.5.0","migration starts on exact 0.5.0 baseline bundle");
    await switchWorker(candidatePath);
    const upgraded=await rpc(tokens.access_token,"initialize",{protocolVersion:"2025-11-25",capabilities:{},clientInfo:{name:"migration",version:"1"}});
    ok(upgraded.serverInfo.version==="0.6.0","candidate loaded after real workerd restart");
    const preserved=value(await tool(tokens.access_token,"checkpoint_get",{project:"qualification"}));
    ok(preserved.found&&preserved.value==="proof"&&preserved.revision===1,"legacy checkpoint and OAuth session survive upgrade");
    const oldTask=value(await tool(tokens.access_token,"task_status",{project:"qualification",task_id:queued.task_id}));
    ok(oldTask.state==="succeeded"&&oldTask.result.verified===true,"legacy task survives upgrade");
  }
  const tools=await rpc(tokens.access_token,"tools/list");ok(["whoami","checkpoint_get","checkpoint_put","task_submit","task_status","task_cancel","project_create","project_get","project_update","project_history","project_resume","workflow_create","workflow_start","workflow_status","workflow_pause","workflow_resume","workflow_cancel","workflow_retry","workflow_dependencies_get","task_evidence_get","github_repository_status","github_commit_status","github_workflow_status","execution_audit","execution_finalize","system_health"].every(x=>tools.tools.some(t=>t.name===x)),"MCP private tools discovered");

  const projectCreated=value(await tool(tokens.access_token,"project_create",{project:"workflow-qualification",record:{goal:"Exercise project memory and DAG orchestration in workerd",rules:["Owner-scoped","No secrets"],repository:{owner:"octo",repo:"repo"},stage:"initial"}}));
  ok(projectCreated.status==="created"&&projectCreated.revision===1,"structured project memory created");
  const projectRead=value(await tool(tokens.access_token,"project_get",{project:"workflow-qualification"}));
  ok(projectRead.found&&projectRead.revision===1&&projectRead.record.goal.includes("DAG"),"structured project memory readback");
  const projectUpdated=value(await tool(tokens.access_token,"project_update",{project:"workflow-qualification",expected_revision:1,patch:{stage:"workerd-qualified"}}));
  ok(projectUpdated.status==="saved"&&projectUpdated.revision===2,"optimistic project revision update");
  const projectHistory=value(await tool(tokens.access_token,"project_history",{project:"workflow-qualification",limit:10}));
  ok(projectHistory.history.length===2&&projectHistory.history[0].revision===2,"project revision history persisted");
  const projectResume=value(await tool(tokens.access_token,"project_resume",{project:"workflow-qualification"}));
  ok(projectResume.resume_ready&&projectResume.reconcile_required,"project resume marks external reconciliation");
  const workflowArgs={project:"workflow-qualification",name:"workerd DAG",idempotency_key:"workerd-dag-2026",steps:[
    {key:"health",operation:"health_probe",input:{}},
    {key:"hash",operation:"sha256_verify",input:{text:"proof",expected_sha256:createHash("sha256").update("proof").digest("hex")},depends_on:["health"]}
  ]};
  const createdWorkflow=value(await tool(tokens.access_token,"workflow_create",workflowArgs));
  ok(createdWorkflow.status==="created"&&createdWorkflow.state==="CREATED","DAG workflow created");
  const duplicateWorkflow=value(await tool(tokens.access_token,"workflow_create",workflowArgs));
  ok(duplicateWorkflow.status==="existing"&&duplicateWorkflow.deduplicated&&duplicateWorkflow.workflow_id===createdWorkflow.workflow_id,"workflow creation idempotency");
  const conflictingWorkflow=await tool(tokens.access_token,"workflow_create",{...workflowArgs,name:"different definition"});
  ok(conflictingWorkflow.isError&&value(conflictingWorkflow).error==="idempotency_conflict","workflow idempotency key cannot bind a different definition");
  const graph=value(await tool(tokens.access_token,"workflow_dependencies_get",{project:"workflow-qualification",workflow_id:createdWorkflow.workflow_id}));
  ok(graph.dependencies.find(x=>x.key==="health").dependents.includes("hash"),"workflow dependency graph readback");
  const startedWorkflow=value(await tool(tokens.access_token,"workflow_start",{project:"workflow-qualification",workflow_id:createdWorkflow.workflow_id}));
  ok(startedWorkflow.status==="started","workflow start transition");
  await tick();
  let workflowState;
  for(let i=0;i<50;i++){
    workflowState=value(await tool(tokens.access_token,"workflow_status",{project:"workflow-qualification",workflow_id:createdWorkflow.workflow_id}));
    if(workflowState.workflow?.state==="SUCCEEDED")break;
    await new Promise(resolve=>setTimeout(resolve,100));
    await tick();
  }
  console.log("WORKFLOW DIAGNOSTIC "+JSON.stringify(workflowState));
  ok(workflowState.workflow.state==="SUCCEEDED"&&workflowState.steps.every(x=>x.state==="SUCCEEDED"),"DAG dependencies executed by actual scheduled Worker");
  const wfRef={project:"workflow-qualification",workflow_id:createdWorkflow.workflow_id};
  const deps=value(await tool(tokens.access_token,"workflow_dependencies_get",wfRef));
  ok(deps.dependencies.some(x=>x.key==="hash"&&x.depends_on.includes("health")),"workflow dependency graph read through MCP");
  const cancellable=value(await tool(tokens.access_token,"task_submit",{project:"qualification",idempotency_key:"qualification-cancel",kind:"health_probe",payload:{}}));
  ok(value(await tool(tokens.access_token,"task_cancel",{project:"qualification",task_id:cancellable.task_id})).state==="cancelled","queued diagnostic task cancelled through MCP");
  const temporary=value(await tool(tokens.access_token,"workflow_create",{project:"workflow-qualification",name:"control qualification",idempotency_key:"control-qualification",steps:[{key:"bad",operation:"sha256_verify",input:{text:"not matching",expected_sha256:"0".repeat(64)}}]}));
  const tempRef={project:"workflow-qualification",workflow_id:temporary.workflow_id};
  ok(value(await tool(tokens.access_token,"workflow_start",tempRef)).status==="started","control workflow started");
  ok(value(await tool(tokens.access_token,"workflow_pause",tempRef)).status==="paused","workflow pause through MCP");
  ok(value(await tool(tokens.access_token,"workflow_resume",tempRef)).status==="resumed","workflow resume through MCP");
  await tick();
  for(let i=0;i<20;i++){if(value(await tool(tokens.access_token,"workflow_status",tempRef)).workflow.state==="FAILED")break;await new Promise(r=>setTimeout(r,100));}
  ok(value(await tool(tokens.access_token,"workflow_status",tempRef)).workflow.state==="FAILED","incorrect digest fails workflow");
  ok(value(await tool(tokens.access_token,"workflow_retry",tempRef)).status==="retrying","workflow retry through MCP");
  ok(value(await tool(tokens.access_token,"workflow_cancel",tempRef)).status==="cancelled","workflow cancel through MCP");
  ok(value(await tool(tokens.access_token,"workflow_status",tempRef)).workflow.state==="CANCELLED","cancelled workflow remains terminal");
  const evidence=value(await tool(tokens.access_token,"task_evidence_get",{project:"workflow-qualification",workflow_id:createdWorkflow.workflow_id,step_key:"hash"}));
  ok(evidence.evidence.verified===true&&typeof evidence.evidence.result_sha256==="string","workflow step evidence stored");
  const finalized=value(await tool(tokens.access_token,"execution_finalize",{project:"workflow-qualification",workflow_id:createdWorkflow.workflow_id}));
  ok(finalized.verified===true&&finalized.verified_steps===2,"workflow finalization rechecks result integrity");
  const audit=value(await tool(tokens.access_token,"execution_audit",{project:"workflow-qualification",limit:20}));
  ok(audit.events.some(x=>x.event==="workflow_started")&&audit.events.some(x=>x.event==="project_updated"),"workflow and project audit history");
  const system=value(await tool(tokens.access_token,"system_health"));
  ok(system.status==="online"&&system.database==="online"&&system.persistence_probe==="verified","MCP system health");
  const gh=mock.get("https://api.github.com");
  gh.intercept({path:"/repos/octo/repo",method:"GET"}).reply(200,JSON.stringify({id:7,full_name:"octo/repo",private:false,archived:false,default_branch:"main",updated_at:"2026-11-25T00:00:00Z"}),{headers:{"content-type":"application/json"}});
  gh.intercept({path:"/repos/octo/repo/commits/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/status",method:"GET"}).reply(200,JSON.stringify({state:"success",total_count:1,statuses:[{context:"ci",state:"success",description:"passed",updated_at:"2026-11-25T00:00:00Z"}]}),{headers:{"content-type":"application/json"}});
  gh.intercept({path:"/repos/octo/repo/actions/runs/123",method:"GET"}).reply(200,JSON.stringify({id:123,status:"completed",conclusion:"success",run_number:3,head_sha:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",html_url:"https://github.com/octo/repo/actions/runs/123",updated_at:"2026-11-25T00:00:00Z"}),{headers:{"content-type":"application/json"}});
  const repoStatus=value(await tool(tokens.access_token,"github_repository_status",{owner:"octo",repo:"repo"}));
  ok(repoStatus.verified&&repoStatus.repository.default_branch==="main","public GitHub repository read adapter");
  const commitStatus=value(await tool(tokens.access_token,"github_commit_status",{owner:"octo",repo:"repo",sha:"a".repeat(40)}));
  ok(commitStatus.verified&&commitStatus.state==="success","public GitHub commit status adapter");
  const runStatus=value(await tool(tokens.access_token,"github_workflow_status",{owner:"octo",repo:"repo",run_id:123}));
  ok(runStatus.verified&&runStatus.conclusion==="success","public GitHub Actions run adapter");

  // Actual workerd D1 and protected MCP, simulated GitHub responses only.
  const qp="eg-qualification-workerd",headSha="a".repeat(40),qualificationNames=["Qualification","OAuth and MCP runtime qualification","Exact Preview HTTP and isolation qualification"];
  ok(value(await tool(tokens.access_token,"project_create",{project:qp,record:{goal:"Release evidence integration",repository:{owner:"19wolfalone92",repo:"Execution-Guard"}}})).status==="created","release qualification project created");
  gh.intercept({path:"/repos/19wolfalone92/Execution-Guard",method:"GET"}).reply(200,JSON.stringify({id:7,full_name:"19wolfalone92/Execution-Guard",default_branch:"main",private:false,archived:false}),{headers:{"content-type":"application/json"}});
  gh.intercept({path:"/repos/19wolfalone92/Execution-Guard/git/ref/heads/audit/oauth-e2e-20261125",method:"GET"}).reply(200,JSON.stringify({ref:"refs/heads/audit/oauth-e2e-20261125",object:{type:"commit",sha:headSha}}),{headers:{"content-type":"application/json"}});
  gh.intercept({path:"/repos/19wolfalone92/Execution-Guard/actions/runs?head_sha="+headSha+"&per_page=100",method:"GET"}).reply(200,JSON.stringify({total_count:3,workflow_runs:qualificationNames.map((name,i)=>({id:i+101,name,head_sha:headSha,status:"completed",conclusion:"success"}))}),{headers:{"content-type":"application/json"}});
  const proof=value(await tool(tokens.access_token,"workflow_create",{project:qp,name:"release qualification",idempotency_key:"release-qualification-workerd",steps:[
    {key:"health",operation:"health_probe",input:{}},
    {key:"repo",operation:"github_repository_status",input:{owner:"19wolfalone92",repo:"Execution-Guard"}},
    {key:"head",operation:"github_branch_head",input:{owner:"19wolfalone92",repo:"Execution-Guard",branch:"audit/oauth-e2e-20261125"},depends_on:["repo"]},
    {key:"ci",operation:"github_actions_for_branch",input:{branch_step:"head"},depends_on:["head"]},
    {key:"collect",operation:"qualification_collect",depends_on:["health","repo","head","ci"]},
    {key:"verify",operation:"qualification_verify",depends_on:["collect"]},
    {key:"save",operation:"qualification_checkpoint",depends_on:["verify"]}
  ]}));
  ok(proof.status==="created","seven-stage release proof created through MCP");
  const proofRef={project:qp,workflow_id:proof.workflow_id};
  ok(value(await tool(tokens.access_token,"workflow_start",proofRef)).status==="started","release proof queued");
  let proofState;
  for(let i=0;i<12;i++){await tick();await new Promise(r=>setTimeout(r,100));proofState=value(await tool(tokens.access_token,"workflow_status",proofRef));if(["SUCCEEDED","FAILED"].includes(proofState.workflow.state))break;}
  console.log("RELEASE DAG EVIDENCE "+JSON.stringify(proofState));
  ok(proofState.workflow.state==="SUCCEEDED"&&proofState.steps.length===7&&proofState.steps.every(s=>s.evidence.verified&&s.attempts===1),"all seven release proof steps persisted in actual workerd D1");
  const proofSaved=proofState.steps.find(s=>s.key==="save").result;
  const proofRead=value(await tool(tokens.access_token,"checkpoint_get",{project:proofSaved.checkpoint}));
  ok(proofRead.found&&proofRead.revision===1&&JSON.parse(proofRead.value).snapshot.sha===headSha&&JSON.parse(proofRead.value).sha256===proofSaved.sha256,"release proof checkpoint read through MCP");
  ok(value(await tool(tokens.access_token,"execution_finalize",proofRef)).verified,"release proof independently finalized");
  if(preview)for(const rateLimited of [false,true]){
    // Execute the exact shared browser MCP suite against protected workerd,
    // using simulated upstream GitHub responses only (not a live OAuth claim).
    const project="eg-qualification-browser-"+crypto.randomUUID(),proofProject=project+"-p",sha="b".repeat(40),target={owner:"19wolfalone92",repo:"Execution-Guard"};
    const reply=(path,data)=>gh.intercept({path,method:"GET"}).reply(200,JSON.stringify(data),{headers:{"content-type":"application/json"}});
    const root="/repos/19wolfalone92/Execution-Guard",metadata={id:7,full_name:"19wolfalone92/Execution-Guard",default_branch:"main",private:false,archived:false};
    if(rateLimited)gh.intercept({path:root,method:"GET"}).reply(403,JSON.stringify({message:"API rate limit exceeded"}),{headers:{"content-type":"application/json","x-ratelimit-remaining":"0"}});else reply(root,metadata);
    reply(root+"/commits/"+sha+"/status",{state:"success",total_count:0,statuses:[]});reply(root+"/actions/runs/123",{id:123,status:"completed",conclusion:"success",head_sha:sha});
    reply(root,metadata);reply(root+"/git/ref/heads/audit/oauth-e2e-20261125",{ref:"refs/heads/audit/oauth-e2e-20261125",object:{type:"commit",sha}});
    reply(root+"/actions/runs?head_sha="+sha+"&per_page=100",{total_count:3,workflow_runs:qualificationNames.map((name,i)=>({id:i+201,name,head_sha:sha,status:"completed",conclusion:"success"}))});
    const inventory=(await rpc(tokens.access_token,"tools/list")).tools;
    const report={project,proof_project:proofProject,sha,state:"AUTHORIZED",owner_verified:true,refresh:true,tools:Object.fromEntries(inventory.map(t=>[t.name,{valid:false,scope:t.securitySchemes[0].scopes.includes("eg:write")?true:null}]))};let rev=0;
    const raw=async(access,method,params)=>{const r=await call("/mcp-private",{method:"POST",headers:{"Content-Type":"application/json",...(access?{Authorization:"Bearer "+access}:{})},body:JSON.stringify({jsonrpc:"2.0",id:1234,method,params})});return {http:r.status,data:await r.json().catch(()=>({}))};};
    const persist=async()=>{const x=value(await tool(tokens.access_token,"checkpoint_put",{project:proofProject,expected_revision:rev,value:JSON.stringify(report)}));assert.equal(x.status,"saved",JSON.stringify(x));rev=x.revision;};
    await persist();
    const suite=new Function("return ("+mcpSuiteSource+")")();
    await suite({rpc:raw,access:tokens.access_token,tools:inventory,report,project,proofProject,persist,uuid:()=>crypto.randomUUID(),digestHex:async x=>createHash("sha256").update(x).digest("hex"),sleep:async()=>{},status:()=>{},fixture:{run_id:123,sha}});
    console.log("BROWSER SUITE "+JSON.stringify({all:report.all_tools_valid,state:report.state,groups:report.group_failures,tools:report.tools}));
    if(rateLimited){ok(!report.all_tools_valid&&report.tools.github_repository_status.failed===true&&Object.entries(report.tools).filter(([n])=>n!=="github_repository_status").every(([,v])=>v.valid)&&report.state==="SUCCEEDED"&&report.workflow_evidence?.verified,"simulated GitHub 403 is isolated; other 25 tools and DAG continue");}
    else ok(report.all_tools_valid&&report.state==="SUCCEEDED"&&report.workflow_evidence?.verified,"same browser suite exercises all 26 tools and DAG on protected workerd");
  }
  const ownedInventory=(await rpc(tokens.access_token,"tools/list")).tools;
  for(const t of ownedInventory){
    const raw=await call("/mcp-private",{method:"POST",headers:{Authorization:"Bearer "+tokens.access_token,"Content-Type":"application/json"},body:JSON.stringify({jsonrpc:"2.0",id:1002,method:"tools/call",params:{name:t.name,arguments:{unexpected:true}}})});
    const b=await json(raw);
    ok(!!b.error||b.result?.isError===true,"invalid arguments rejected even for full-scope owner: "+t.name);
  }
  const refresh=await tokenRequest({grant_type:"refresh_token",client_id:clientId,refresh_token:tokens.refresh_token,resource});assert.equal(refresh.status,200,await refresh.clone().text());const refreshed=await json(refresh);
  ok(value(await tool(refreshed.access_token,"whoami")).owner_verified,"refreshed token usable");
  // RFC 6749 §10.5: replay of a genuine authorization code revokes its grant and tokens.
  // Exercise replay only after using and refreshing the legitimate token.
  const replay=await exchange(code);ok(replay.status>=400,"authorization code cannot replay");
  const revoked=await call("/mcp-private",{method:"POST",headers:{Authorization:"Bearer "+refreshed.access_token,"Content-Type":"application/json"},body:JSON.stringify({jsonrpc:"2.0",id:99,method:"tools/list"})});
  ok(revoked.status===401,"replay revokes previously issued tokens");
  const readOnly=await issue("eg:read");const readTokenResponse=await exchange(readOnly.code);assert.equal(readTokenResponse.status,200,await readTokenResponse.clone().text());const readTokens=await json(readTokenResponse);
  ok(value(await tool(readTokens.access_token,"checkpoint_get",{project:"qualification"})).found,"read-only scope permits read");
  const readonlyTick=await json(await tickRequest(readTokens.access_token));ok(!!readonlyTick.error,"qualification tick rejects read-only token");
  const blocked=await tool(readTokens.access_token,"checkpoint_put",{project:"qualification",expected_revision:1,value:"forbidden"});
  ok(blocked.isError===true,"read-only scope cannot write");
  const unchanged=value(await tool(readTokens.access_token,"checkpoint_get",{project:"qualification"}));ok(unchanged.value==="proof"&&unchanged.revision===1,"scope denial leaves data unchanged");
  const allTools=(await rpc(readTokens.access_token,"tools/list")).tools;
  const expectedTools=["task_submit","task_status","task_cancel","whoami","checkpoint_get","checkpoint_put","project_create","project_get","project_update","project_history","project_resume","workflow_create","workflow_start","workflow_status","workflow_pause","workflow_resume","workflow_cancel","workflow_retry","workflow_dependencies_get","task_evidence_get","github_repository_status","github_commit_status","github_workflow_status","execution_audit","execution_finalize","system_health"];
  ok(allTools.length===expectedTools.length&&new Set(allTools.map(t=>t.name)).size===expectedTools.length&&expectedTools.every(n=>allTools.some(t=>t.name===n)),"exactly "+expectedTools.length+" unique MCP tools with unchanged names");
  console.log("MCP TOOL INVENTORY "+JSON.stringify(allTools.map(t=>t.name)));
  for(const t of allTools){
    ok(t.inputSchema.type==="object"&&t.inputSchema.additionalProperties===false&&Array.isArray(t.inputSchema.required)&&t.securitySchemes?.[0]?.scopes?.includes("eg:read"),"tool schema and read scope: "+t.name);
    const raw=await call("/mcp-private",{method:"POST",headers:{Authorization:"Bearer "+readTokens.access_token,"Content-Type":"application/json"},body:JSON.stringify({jsonrpc:"2.0",id:1000,method:"tools/call",params:{name:t.name,arguments:{unexpected:true}}})});
    const b=await json(raw);
    ok(!!b.error||b.result?.isError===true,"invalid arguments or missing write scope rejected: "+t.name);
    if(t.securitySchemes[0].scopes.includes("eg:write"))ok(b.result?.isError===true,"read-only caller cannot invoke write tool: "+t.name);
    const noAuth=await call("/mcp-private",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({jsonrpc:"2.0",id:1001,method:"tools/call",params:{name:t.name,arguments:{}}})});
    ok(noAuth.status===401,"unauthenticated tool call rejected: "+t.name);
  }

  if(baselinePath){
    await switchWorker(baselinePath);
    const rolled=await rpc(readTokens.access_token,"initialize",{protocolVersion:"2025-11-25",capabilities:{},clientInfo:{name:"rollback",version:"1"}});
    ok(rolled.serverInfo.version==="0.5.0","rollback loads original Worker");
    ok(value(await tool(readTokens.access_token,"checkpoint_get",{project:"qualification"})).value==="proof","legacy read and OAuth session survive rollback");
    ok(value(await tool(readTokens.access_token,"task_status",{project:"qualification",task_id:queued.task_id})).result.verified===true,"legacy task survives rollback");
    await switchWorker(candidatePath);
    const restored=value(await tool(readTokens.access_token,"execution_finalize",{project:"workflow-qualification",workflow_id:createdWorkflow.workflow_id}));
    ok(restored.verified===true,"candidate evidence survives rollback and re-upgrade");
  }
  mock.assertNoPendingInterceptors();
  console.log("QUALIFICATION PASS: "+checks+" assertions; actual workerd and OAuth library; simulated GitHub only.");
}finally{await mf.dispose();await mock.close();rmSync(persistence,{recursive:true,force:true});}

/* Independent production smoke, read-only, no OAuth secrets or issued tokens. */
if(!preview)try {
  const live=(path,opts={})=>fetch(host+path,{...opts,redirect:"manual",signal:AbortSignal.timeout(12000)});
  const healthResponse=await live("/health");assert.equal(healthResponse.status,200);
  const health=await healthResponse.json();
  assert.equal(health.status,"online");assert.equal(health.database,"online");
  assert.equal(health.persistence_probe,"verified");assert.equal(health.oauth?.discovery,"verified");
  const clientResponse=await live("/oauth/client-info");assert.equal(clientResponse.status,200);
  const client=await clientResponse.json();assert.equal(client.status,"ready");assert.equal(client.redirect_uri,redirect);
  const authResponse=await live("/.well-known/oauth-authorization-server");assert.equal(authResponse.status,200);
  const metadata=await authResponse.json();assert.equal(metadata.issuer,host);assert.equal(metadata.authorization_response_iss_parameter_supported,true);assert.ok(metadata.code_challenge_methods_supported.includes("S256"));
  const privateResponse=await live("/mcp-private",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({jsonrpc:"2.0",id:1,method:"tools/list"})});
  assert.equal(privateResponse.status,401);assert.match(privateResponse.headers.get("WWW-Authenticate")||"",/resource_metadata=/);
  console.log("LIVE SMOKE PASS: D1, persistence, discovery, registered client, unauthenticated MCP rejected. No user sign-in attempted.");
}catch(e){console.log("LIVE SMOKE NOT CONFIRMED: "+(e?.name||"Error"));}
