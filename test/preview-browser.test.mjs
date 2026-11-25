import test from "node:test";
import assert from "node:assert/strict";
import {PREVIEW_HOST,HOST} from "../security.mjs";
import {browserClientApproved,provisionBrowserClient,browserQualificationRoute} from "../preview-browser.mjs";
const key="eg:preview:browser-qualification-client:v1";
function fixture(){const m=new Map([["eg:preview:identity","execution-guard-preview-v1"]]);const env={EG_ENVIRONMENT:"preview",EG_PREVIEW_BROWSER_QUALIFICATION:"true",EG_AUTH_ENABLED:"true",EG_PREVIEW_READY:"true",EG_OWNER_GITHUB_ID:"123",GITHUB_CLIENT_ID:"client",GITHUB_CLIENT_SECRET:"example",DB:{prepare(){return{first:async()=>({value:"execution-guard-preview-v1"})}}},OAUTH_KV:{get:async k=>m.get(k)||null,put:async(k,v)=>m.set(k,v)}};return{env,m}}
test("browser client is Preview only, fixed redirect, provisioned once",async()=>{
 const {env,m}=fixture();let created=0;const client={clientId:"test-public-client",redirectUris:[PREVIEW_HOST+"/qualification/oauth/return"],tokenEndpointAuthMethod:"none"};
 const oauth={createClient:async opts=>{created++;assert.deepEqual(opts.redirectUris,client.redirectUris);return client},lookupClient:async()=>client};
 assert.equal(await provisionBrowserClient({...env,EG_ENVIRONMENT:"production"},oauth),undefined);assert.equal(created,0);
 assert.equal(await provisionBrowserClient(env,oauth),client.clientId);assert.equal(await provisionBrowserClient(env,oauth),client.clientId);assert.equal(created,1);
 assert.equal(await browserClientApproved(env,client.clientId),true);assert.equal(await browserClientApproved({...env,EG_ENVIRONMENT:"production"},client.clientId),false);
 assert.equal(await browserClientApproved({...env,EG_PREVIEW_BROWSER_QUALIFICATION:"false"},client.clientId),false);
 assert.equal(m.get(key),client.clientId);
});
test("browser route fails closed and never renders secrets; script is parseable",async()=>{
 const {env,m}=fixture();m.set(key,"test-public-client");
 const route=(host,p,e=env)=>browserQualificationRoute(new Request(host+p),e);
 assert.equal((await route(HOST,"/qualification/oauth")).status,404);
 assert.equal((await route(PREVIEW_HOST,"/qualification/oauth",{...env,EG_PREVIEW_READY:"false"})).status,404);
 const page=await route(PREVIEW_HOST,"/qualification/oauth/return?code=not-rendered");assert.equal(page.status,200);assert.equal(page.headers.get("Referrer-Policy"),"no-referrer");assert.match(page.headers.get("Content-Security-Policy"),/frame-ancestors 'none'/);
 const html=await page.text();assert.ok(!html.includes("not-rendered")&&!html.includes("example"));
 const js=await route(PREVIEW_HOST,"/qualification/oauth.js");assert.equal(js.status,200);
 const code=await js.text();assert.doesNotThrow(()=>new Function(code));
});
