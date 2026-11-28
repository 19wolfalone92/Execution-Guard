import {spawnSync} from "node:child_process";
const account=process.env.CLOUDFLARE_ACCOUNT_ID, token=process.env.CLOUDFLARE_API_TOKEN;
const expected="04b45c9393f4e12159c6b8118ec54791";
if(!token||account!==expected){console.log("CF_DIAGNOSTICS "+JSON.stringify({status:"missing_secret_or_account_mismatch",token_present:!!token,account_matches:account===expected}));process.exit(1);}
const root="https://api.cloudflare.com/client/v4", prefix="/accounts/"+account;
const d1="657131f8-b0f4-47f3-ab3d-91840843f2db",kv="25a30c61f53b422fa11889babb147fd4";
const names=["EG_OWNER_GITHUB_ID","GITHUB_CLIENT_ID","GITHUB_CLIENT_SECRET","EG_PREVIEW_TICK_SECRET"];
const uuid=x=>typeof x==="string"&&/^[a-f0-9-]{36}$/.test(x)?x:null;
const id=x=>typeof x==="string"&&/^[a-f0-9-]{32,36}$/.test(x)?x:null;
const out={sha:process.env.GITHUB_SHA,checked_at:new Date().toISOString(),mode:"read_only",checks:{}};
async function probe(name,path,project,{sql,raw=false}={}){
  try {
    const r=await fetch(root+path,{method:sql?"POST":"GET",headers:{Authorization:"Bearer "+token,...(sql?{"Content-Type":"application/json"}:{})},...(sql?{body:JSON.stringify({sql})}:{}),redirect:"error",signal:AbortSignal.timeout(20000)});
    const body=raw?await r.text():await r.json().catch(()=>null);
    const ok=r.ok&&(raw||body?.success===true);
    out.checks[name]={http:r.status,ok,...(ok?project(raw?body:body.result):{error_codes:(body?.errors||[]).map(x=>x.code).filter(Number.isInteger)})};
  }catch{out.checks[name]={ok:false,transport_or_schema_error:true};}
}
function bindingSummary(list){
  const a=Array.isArray(list)?list:Object.entries(list||{}).map(([name,v])=>({...v,name}));
  return {credential_names:Object.fromEntries(names.map(n=>[n,a.some(b=>b.name===n)])),storage:a.filter(b=>["DB","OAUTH_KV"].includes(b.name)).map(b=>({name:b.name,type:["d1","kv_namespace"].includes(b.type)?b.type:"other",resource_id:id(b.database_id||b.namespace_id||b.id)}))};
}
await probe("token","/user/tokens/verify",x=>({active:x?.status==="active"}));
await Promise.all([
  probe("production_settings",prefix+"/workers/scripts/execution-guard/settings",x=>bindingSummary(x?.bindings)),
  probe("production_deployments",prefix+"/workers/scripts/execution-guard/deployments",x=>({deployments:(x?.deployments||[]).slice(0,2).map(d=>({id:uuid(d.id),versions:(d.versions||[]).map(v=>({id:uuid(v.version_id),percentage:Number(v.percentage)}))}))})),
  probe("production_cron",prefix+"/workers/scripts/execution-guard/schedules",x=>({expected_cron_present:(Array.isArray(x)?x:x?.schedules||[]).some(y=>y.cron==="*/5 * * * *")})),
  probe("test_d1",prefix+"/d1/database/"+d1,x=>({id_matches:(x?.uuid||x?.id)===d1,name_matches:x?.name==="execution-guard-preview-db"})),
  probe("test_kv",prefix+"/storage/kv/namespaces/"+kv,x=>({id_matches:x?.id===kv,name_matches:x?.title==="execution-guard-preview-oauth"})),
  probe("test_d1_markers",prefix+"/d1/database/"+d1+"/query",x=>({identity:x?.[0]?.results?.[0]?.value==="execution-guard-preview-v1",probe:x?.[1]?.results?.[0]?.value==="execution-guard-v030"}),{sql:"SELECT value FROM eg_preview_identity WHERE id=1; SELECT value FROM eg_probe WHERE id=1;"}),
  probe("test_kv_marker",prefix+"/storage/kv/namespaces/"+kv+"/values/eg%3Apreview%3Aidentity",x=>({verified:x==="execution-guard-preview-v1"}),{raw:true}),
  probe("build_logs",prefix+"/builds/builds/b75fa293-51ae-436c-b6c0-8afeb95d9b68/logs",x=>{const s=JSON.stringify(x);return {received:s.length>2,length:s.length,preview_command:s.includes("wrangler preview"),missing_previews:s.includes("missing a"),error_marker:/\\[ERROR\\]/.test(s)};})
]);
function listSecrets(name,args){
  const r=spawnSync("./node_modules/.bin/wrangler",args,{encoding:"utf8",timeout:30000,maxBuffer:1024*1024,env:{...process.env,WRANGLER_SEND_METRICS:"false",CI:"true"}});
  if(r.status!==0){out.checks[name]={ok:false,exit:r.status??null,permission_denied:/403|permission|not authorized|authentication error/i.test(r.stderr||"")};return;}
  try {
    const x=JSON.parse(r.stdout);
    const a=Array.isArray(x)?x:Array.isArray(x.secrets)?x.secrets:null;
    if(!a)throw Error("schema");
    out.checks[name]={ok:true,credential_names:Object.fromEntries(names.map(n=>[n,a.some(b=>b===n||b?.name===n)]))};
  }catch{out.checks[name]={ok:false,output_schema_unrecognized:true};}
}
listSecrets("preview_secrets",["preview","secret","list","--worker-name","execution-guard","--name","audit-oauth-e2e-20261125","--json"]);
listSecrets("base_secrets",["preview","base-config","secret","list","--worker-name","execution-guard","--json"]);
try{
 const r=await fetch("https://audit-oauth-e2e-20261125-execution-guard.19wolf-alone92.workers.dev/qualification/readiness",{redirect:"error",signal:AbortSignal.timeout(15000)});
 const j=await r.json();const keys=["environment","auth_enabled","ready_flag","owner_id_valid","github_client_id_present","github_client_secret_present","tick_secret_configured","d1_binding_present","kv_binding_present"];
 const marker=x=>["verified","not_checked","read_failed","missing_or_mismatch"].includes(x)?x:"unknown";
 out.checks.runtime={http:r.status,ok:r.ok&&typeof j.ready==="boolean",ready:j.ready===true,checks:Object.fromEntries(keys.map(k=>[k,j.checks?.[k]===true])),d1_marker:marker(j.d1_marker),kv_marker:marker(j.kv_marker)};
}catch{out.checks.runtime={ok:false};}
console.log("CF_DIAGNOSTICS "+JSON.stringify(out));
if(!out.checks.token?.ok||!out.checks.production_settings?.ok||!out.checks.test_d1?.ok||!out.checks.test_kv?.ok)process.exitCode=1;
