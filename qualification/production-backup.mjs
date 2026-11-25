import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {DatabaseSync} from "node:sqlite";
import {mkdtempSync,writeFileSync,rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {spawnSync} from "node:child_process";
const account=process.env.CLOUDFLARE_ACCOUNT_ID,read=process.env.CLOUDFLARE_API_TOKEN,manage=process.env.CLOUDFLARE_MANAGEMENT_TOKEN,backup=process.env.CLOUDFLARE_D1_BACKUP_TOKEN;
const production="e7699170-b634-48ce-a3b0-733aedb9b898",preview="657131f8-b0f4-47f3-ab3d-91840843f2db",trigger="9ee2b6ad-e77b-48ce-833c-5bbcd9f4af83";
const root="https://api.cloudflare.com/client/v4/accounts/"+account,run=process.env.GITHUB_RUN_ID,sha=process.env.GITHUB_SHA;
const out={sha,checked_at:new Date().toISOString(),source:production,checks:{},backup_token_present:!!backup};
const check=(name,v)=>{out.checks[name]=Boolean(v);assert.ok(v,name);};
let stage="preflight",temp,local;
const digest=v=>createHash("sha256").update(v).digest("hex");
async function api(path,token=read,method="GET",body){
 const r=await fetch(root+path,{method,headers:{Authorization:"Bearer "+token,...(body?{"Content-Type":"application/json"}:{})},...(body?{body:JSON.stringify(body)}:{}),redirect:"error",signal:AbortSignal.timeout(30000)});
 const j=await r.json().catch(()=>null);
 return {http:r.status,ok:r.ok&&j?.success===true,result:j?.result,errors:(j?.errors||[]).map(e=>e.code).filter(Number.isInteger),info:j?.result_info};
}
const query=async(id,sql,token=read)=>{assert.ok(id===production||id===out.restore_id);const r=await api("/d1/database/"+id+"/query",token,"POST",{sql});assert.ok(r.ok&&r.result?.[0]?.success!==false);return r.result[0].results;};
const schemaSql="SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE type IN ('table','index','trigger','view') AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%' ORDER BY type,name";
const tableName=n=>{assert.ok(/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(n));return '"'+n+'"';};
const summarizeSchema=rows=>rows.map(x=>({type:x.type,name:x.name,tbl_name:x.tbl_name,sql:x.sql?.replace(/\s+/g," ").trim()||null}));
const deploy=async()=>{const r=await api("/workers/scripts/execution-guard/deployments");assert.ok(r.ok);return r.result.deployments.slice(0,1).map(d=>({id:d.id,versions:d.versions.map(v=>({id:v.version_id,percentage:v.percentage}))}));};
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
try{
 check("fixed_target",process.env.GITHUB_REPOSITORY==="19wolfalone92/Execution-Guard"&&process.env.GITHUB_REF==="refs/heads/audit/oauth-e2e-20261125"&&account==="04b45c9393f4e12159c6b8118ec54791"&&/^[0-9]+$/.test(run||"")&&/^[a-f0-9]{40}$/.test(sha||""));
 check("read_management_present",!!read&&!!manage);
 const config=JSON.parse(await (await import("node:fs/promises")).readFile("wrangler.jsonc","utf8"));
 check("config_ids",config.d1_databases.length===1&&config.d1_databases[0].database_id===production&&config.previews.d1_databases[0].database_id===preview);
 out.production_before=await deploy();
 const source=await api("/d1/database/"+production),list=await api("/d1/database?per_page=100");
 check("source_identity",source.ok&&(source.result.uuid||source.result.id)===production&&source.result.name==="execution-guard-db");
 check("list_access",list.ok&&Array.isArray(list.result));
 out.source_bytes=source.result.file_size??null;out.database_count=list.info?.total_count??list.result.length;
 const rows=await query(production,schemaSql);out.source_schema=summarizeSchema(rows).map(x=>({type:x.type,name:x.name}));out.source_schema_sha256=digest(JSON.stringify(summarizeSchema(rows)));
 const tables=rows.filter(x=>x.type==="table");
 out.source_counts={};for(const t of tables){out.source_counts[t.name]=(await query(production,"SELECT COUNT(*) AS n FROM "+tableName(t.name)))[0].n;}
 const bm=await api("/d1/database/"+production+"/time_travel/bookmark");out.bookmark=bm.ok?bm.result?.bookmark:null;check("bookmark",typeof out.bookmark==="string"&&out.bookmark.length>0);
 // Prevent an automatic promotion on eventual merge. Only exact existing main trigger.
 stage="controlled_trigger";
 const workers=await api("/workers/scripts");const tag=workers.result?.find(x=>x.id==="execution-guard")?.tag;
 check("worker_tag",workers.ok&&typeof tag==="string"&&/^[a-f0-9-]{32,36}$/.test(tag));
 const getTrigger=async()=>{const list=await api("/builds/workers/"+tag+"/triggers",manage);return {...list,result:list.result?.find(t=>t.trigger_uuid===trigger)};};
 const tr=await getTrigger();out.trigger_before={http:tr.http,ok:tr.ok,errors:tr.errors,command:tr.result?.deploy_command,branches:tr.result?.branch_includes};
 if(tr.ok&&tr.result?.trigger_uuid===trigger&&Array.isArray(tr.result.branch_includes)&&tr.result.branch_includes.length===1&&tr.result.branch_includes[0]==="main"&&["npx wrangler deploy","npx wrangler versions upload"].includes(tr.result.deploy_command)){
  if(tr.result.deploy_command==="npx wrangler deploy"){
   const change=await api("/builds/triggers/"+trigger,manage,"PATCH",{deploy_command:"npx wrangler versions upload"});out.trigger_update={http:change.http,ok:change.ok,errors:change.errors};
  }
  const after=await getTrigger();out.trigger_after={http:after.http,ok:after.ok,command:after.result?.deploy_command,branches:after.result?.branch_includes};
  out.controlled_trigger=after.ok&&after.result?.deploy_command==="npx wrangler versions upload"&&JSON.stringify(after.result.branch_includes)===JSON.stringify(["main"]);
 }else out.controlled_trigger=false;
 if(!backup){out.status="BLOCKED";out.reason="missing_d1_edit_token";process.exitCode=1;}
 else{
  stage="backup_limits";check("free_database_slot",out.database_count<10);check("bounded_size",Number.isFinite(out.source_bytes)&&out.source_bytes<=16*1024*1024);
  check("no_virtual_tables",!tables.some(x=>/^CREATE VIRTUAL TABLE/i.test(x.sql||"")));
  const name="execution-guard-backup-"+run;check("unique_backup_name",!list.result.some(x=>x.name===name));
  // D1 export locks the source temporarily; bounded polling, no SQL or signed URL in logs.
  stage="export";let bookmark,url;
  for(let i=0;i<45;i++){
   const e=await api("/d1/database/"+production+"/export",backup,"POST",{output_format:"polling",...(bookmark?{current_bookmark:bookmark}:{})});
   if(!e.ok){out.export_http=e.http;out.export_errors=e.errors;throw Error("export");}
   bookmark=e.result?.at_bookmark||bookmark;if(e.result?.status==="error")throw Error("export");
   if(e.result?.status==="complete"){url=e.result?.result?.signed_url;break;}
   assert.ok(bookmark);await sleep(2000);
  }
  check("export_complete",typeof url==="string"&&typeof bookmark==="string");out.export_bookmark=bookmark;
  const signed=new URL(url);check("signed_url_https",signed.protocol==="https:"&&!signed.username&&!signed.password);
  const download=await fetch(signed,{redirect:"error",signal:AbortSignal.timeout(30000)});check("download_ok",download.ok);
  const sql=Buffer.from(await download.arrayBuffer());check("sql_bounded",sql.length>0&&sql.length<=16*1024*1024);
  out.sql_bytes=sql.length;out.sql_sha256=digest(sql);
  temp=mkdtempSync(join(tmpdir(),"eg-backup-"));const file=join(temp,"backup.sql");writeFileSync(file,sql,{mode:0o600});
  stage="local_restore";local=new DatabaseSync(":memory:");local.exec(sql.toString("utf8"));
  check("local_integrity",local.prepare("PRAGMA integrity_check").get().integrity_check==="ok");
  const localSchema=local.prepare(schemaSql).all();check("schema_matches_export",JSON.stringify(summarizeSchema(localSchema))===JSON.stringify(summarizeSchema(rows)));
  const data={};for(const t of localSchema.filter(x=>x.type==="table")){
   const q=tableName(t.name),cols=local.prepare("PRAGMA table_info("+q+")").all().map(x=>tableName(x.name));
   const order=cols.join(",");const h=createHash("sha256");let n=0;
   for(const row of local.prepare("SELECT * FROM "+q+" ORDER BY "+order).iterate()){h.update(JSON.stringify(Object.values(row))+"\n");n++;}
   data[t.name]={rows:n,sha256:h.digest("hex"),order};
  }
  out.backup_tables=Object.fromEntries(Object.entries(data).map(([n,d])=>[n,{rows:d.rows,sha256:d.sha256}]));
  stage="create_isolated_restore";
  const create=await api("/d1/database",backup,"POST",{name});out.create_http=create.http;out.create_errors=create.errors;
  check("restore_database_created",create.ok&&create.result?.name===name&&/^[a-f0-9-]{36}$/.test(create.result?.uuid||create.result?.id||""));
  out.restore_id=create.result.uuid||create.result.id;out.restore_name=name;
  check("restore_distinct",out.restore_id!==production&&out.restore_id!==preview);
  const tempConfig=join(temp,"wrangler.jsonc");
  writeFileSync(tempConfig,JSON.stringify({name:"execution-guard-backup-restore-only",compatibility_date:"2026-11-25",d1_databases:[{binding:"RESTORE_DB",database_name:name,database_id:out.restore_id}]}),{mode:0o600});
  stage="remote_import";
  const wrangler=spawnSync("./node_modules/.bin/wrangler",["d1","execute","RESTORE_DB","--remote","--file",file,"--yes","--config",tempConfig],{encoding:"utf8",timeout:120000,maxBuffer:4*1024*1024,env:{PATH:process.env.PATH,HOME:process.env.HOME,CI:"true",CLOUDFLARE_ACCOUNT_ID:account,CLOUDFLARE_API_TOKEN:backup,WRANGLER_SEND_METRICS:"false"}});
  check("remote_import",wrangler.status===0);
  stage="remote_verify";
  const restoredSchema=await query(out.restore_id,schemaSql,backup);check("restored_schema",JSON.stringify(summarizeSchema(restoredSchema))===JSON.stringify(summarizeSchema(localSchema)));
  out.restore_tables={};
  for(const [n,d] of Object.entries(data)){
   const q=tableName(n),count=(await query(out.restore_id,"SELECT COUNT(*) AS n FROM "+q,backup))[0].n;
   const h=createHash("sha256");for(let off=0;off<count;off+=100){const page=await query(out.restore_id,"SELECT * FROM "+q+" ORDER BY "+d.order+" LIMIT 100 OFFSET "+off,backup);for(const row of page)h.update(JSON.stringify(Object.values(row))+"\n");}
   out.restore_tables[n]={rows:count,sha256:h.digest("hex")};check("restored_"+n,count===d.rows&&out.restore_tables[n].sha256===d.sha256);
  }
  const integrity=await query(out.restore_id,"PRAGMA integrity_check",backup);check("remote_integrity",integrity[0]?.integrity_check==="ok");
  const settings=await api("/workers/scripts/execution-guard/settings");check("restore_not_bound",settings.ok&&!JSON.stringify(settings.result?.bindings||[]).includes(out.restore_id));
  // The isolated restored D1 is the retained private snapshot; SQL remains
  // temporary, no public Actions artifact and no plaintext output.
  out.retained_backup="unbound_private_D1";out.status="PASS";
 }
}catch(e){out.status="BLOCKED";out.reason=stage;process.exitCode=1;}
finally{
 if(local)local.close();if(temp)rmSync(temp,{recursive:true,force:true});
 if(out.production_before){try{out.production_after=await deploy();out.checks.production_worker_unchanged=JSON.stringify(out.production_before)===JSON.stringify(out.production_after);if(!out.checks.production_worker_unchanged){out.status="FAIL";process.exitCode=1;}}catch{out.checks.production_worker_unchanged=false;out.status="BLOCKED";process.exitCode=1;}}
 console.log("EG_BACKUP_PREFLIGHT "+JSON.stringify(out));
}
