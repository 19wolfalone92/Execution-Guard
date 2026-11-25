import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { Miniflare, createFetchMock } from "miniflare";

const config=JSON.parse(readFileSync("wrangler.jsonc","utf8"));
const script=readdirSync(".oauth-build").filter(x=>/\.(m?js)$/.test(x));
assert.equal(script.length,1,"Expected one bundled Worker entry point");
const host="https://execution-guard.19wolf-alone92.workers.dev";
const resource=host+"/mcp-private";
const redirect="https://chatgpt.com/connector_platform_oauth_redirect";
const owner="123456";
const upstreamToken="qualification-fake-github-token";
const mock=createFetchMock();
mock.disableNetConnect();
const mf=new Miniflare({
  modules:true,scriptPath:".oauth-build/"+script[0],
  // Installed workerd 4.x test binary supports dates through 2026-08-06.
  // This is a test-only cap; production Wrangler configuration is unchanged.
  compatibilityDate:config.compatibility_date>"2026-08-06"?"2026-08-06":config.compatibility_date,
  compatibilityFlags:config.compatibility_flags,
  bindings:{EG_AUTH_ENABLED:"true",EG_OWNER_GITHUB_ID:owner,GITHUB_CLIENT_ID:"qualification-client",GITHUB_CLIENT_SECRET:"qualification-secret"},
  kvNamespaces:["OAUTH_KV"],d1Databases:["DB"],fetchMock:mock,cf:false
});
const testDb=await mf.getD1Database("DB");
await testDb.exec(readFileSync("probe.sql","utf8"));
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
async function provision(){
  const worker=await mf.getWorker();
  await worker.scheduled({cron:"*/5 * * * *"});
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
  const meta=await json(await call("/.well-known/oauth-authorization-server"));
  ok(meta.issuer===host&&meta.authorization_endpoint===host+"/authorize"&&meta.token_endpoint===host+"/oauth/token"&&meta.authorization_response_iss_parameter_supported===true&&meta.code_challenge_methods_supported.includes("S256")&&meta.token_endpoint_auth_methods_supported.includes("none"),"authorization metadata, issuer and S256");
  const resMeta=await json(await call("/.well-known/oauth-protected-resource/mcp-private"));
  ok(resMeta.resource===resource&&resMeta.authorization_servers.includes(host),"protected resource audience");
  const unauthorized=await call("/mcp-private",{method:"POST",headers:{"Content-Type":"application/json"},body:'{"jsonrpc":"2.0","id":1,"method":"tools/list"}'});
  ok(unauthorized.status===401&&/resource_metadata=/.test(unauthorized.headers.get("WWW-Authenticate")||""),"unauthenticated MCP discovery challenge");
  clientId=await provision();
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
  const init=await rpc(tokens.access_token,"initialize",{protocolVersion:"2025-11-25",capabilities:{},clientInfo:{name:"qualification",version:"1"}});
  ok(init.serverInfo.name==="execution-guard-private"&&init.protocolVersion==="2025-11-25","MCP initialize");
  const notification=await call("/mcp-private",{method:"POST",headers:{Authorization:"Bearer "+tokens.access_token,"Content-Type":"application/json"},body:JSON.stringify({jsonrpc:"2.0",method:"notifications/initialized"})});ok(notification.status===202,"MCP initialized notification");
  const tools=await rpc(tokens.access_token,"tools/list");ok(["whoami","checkpoint_get","checkpoint_put","task_submit","task_status","task_cancel","project_create","project_get","project_update","project_history","project_resume","workflow_create","workflow_start","workflow_status","workflow_pause","workflow_resume","workflow_cancel","workflow_retry","workflow_dependencies_get","task_evidence_get","github_repository_status","github_commit_status","github_workflow_status","execution_audit","execution_finalize","system_health"].every(x=>tools.tools.some(t=>t.name===x)),"MCP private tools discovered");
  const latestInit=await rpc(tokens.access_token,"initialize",{protocolVersion:"2026-07-28",capabilities:{},clientInfo:{name:"qualification-latest",version:"1"}});ok(latestInit.protocolVersion==="2026-07-28","latest supported MCP protocol version");
  const who=value(await tool(tokens.access_token,"whoami"));ok(who.authenticated&&who.owner_verified&&who.scopes.includes("eg:write"),"authenticated owner and scope");
  const saved=value(await tool(tokens.access_token,"checkpoint_put",{project:"qualification",expected_revision:0,value:"proof"}));ok(saved.status==="saved"&&saved.revision===1,"D1 checkpoint write");
  const got=value(await tool(tokens.access_token,"checkpoint_get",{project:"qualification"}));ok(got.found&&got.value==="proof"&&got.revision===1,"D1 checkpoint readback");
  const conflict=await tool(tokens.access_token,"checkpoint_put",{project:"qualification",expected_revision:0,value:"wrong"});ok(conflict.isError&&value(conflict).status==="conflict","checkpoint revision conflict rejected");
  const queued=value(await tool(tokens.access_token,"task_submit",{project:"qualification",idempotency_key:"qualification1",kind:"sha256_verify",payload:{text:"proof",expected_sha256:createHash("sha256").update("proof").digest("hex")}}));
  ok(queued.state==="queued","durable task submitted");
  await (await mf.getWorker()).scheduled({cron:"*/5 * * * *"});
  let final;
  for(let i=0;i<50;i++){final=value(await tool(tokens.access_token,"task_status",{project:"qualification",task_id:queued.task_id}));if(final.state==="succeeded")break;await new Promise(resolve=>setTimeout(resolve,100));}
ok(final.state==="succeeded"&&final.result.verified===true,"scheduled task completed and result verified");
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
  const worker=await mf.getWorker();
  await worker.scheduled({cron:"*/5 * * * *"});
  let workflowState;
  for(let i=0;i<50;i++){
    workflowState=value(await tool(tokens.access_token,"workflow_status",{project:"workflow-qualification",workflow_id:createdWorkflow.workflow_id}));
    if(workflowState.workflow?.state==="SUCCEEDED")break;
    await new Promise(resolve=>setTimeout(resolve,100));
    await worker.scheduled({cron:"*/5 * * * *"});
  }
  console.log("WORKFLOW DIAGNOSTIC "+JSON.stringify(workflowState));
  ok(workflowState.workflow.state==="SUCCEEDED"&&workflowState.steps.every(x=>x.state==="SUCCEEDED"),"DAG dependencies executed by actual scheduled Worker");
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

  const refresh=await tokenRequest({grant_type:"refresh_token",client_id:clientId,refresh_token:tokens.refresh_token,resource});assert.equal(refresh.status,200,await refresh.clone().text());const refreshed=await json(refresh);
  ok(value(await tool(refreshed.access_token,"whoami")).owner_verified,"refreshed token usable");
  // RFC 6749 §10.5: replay of a genuine authorization code revokes its grant and tokens.
  // Exercise replay only after using and refreshing the legitimate token.
  const replay=await exchange(code);ok(replay.status>=400,"authorization code cannot replay");
  const revoked=await call("/mcp-private",{method:"POST",headers:{Authorization:"Bearer "+refreshed.access_token,"Content-Type":"application/json"},body:JSON.stringify({jsonrpc:"2.0",id:99,method:"tools/list"})});
  ok(revoked.status===401,"replay revokes previously issued tokens");
  const readOnly=await issue("eg:read");const readTokenResponse=await exchange(readOnly.code);assert.equal(readTokenResponse.status,200,await readTokenResponse.clone().text());const readTokens=await json(readTokenResponse);
  ok(value(await tool(readTokens.access_token,"checkpoint_get",{project:"qualification"})).found,"read-only scope permits read");
  const blocked=await tool(readTokens.access_token,"checkpoint_put",{project:"qualification",expected_revision:1,value:"forbidden"});
  ok(blocked.isError===true,"read-only scope cannot write");
  const unchanged=value(await tool(readTokens.access_token,"checkpoint_get",{project:"qualification"}));ok(unchanged.value==="proof"&&unchanged.revision===1,"scope denial leaves data unchanged");
  mock.assertNoPendingInterceptors();
  console.log("QUALIFICATION PASS: "+checks+" assertions; actual workerd and OAuth library; simulated GitHub only.");
}finally{await mf.dispose();await mock.close();}

/* Independent production smoke, read-only, no OAuth secrets or issued tokens. */
try {
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
