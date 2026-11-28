import assert from "node:assert/strict";
import {DatabaseSync} from "node:sqlite";
import {mkdtempSync,writeFileSync,rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {spawnSync} from "node:child_process";
import {deploymentMetadata,digest,FINGERPRINT_FORMAT,fingerprint,projectedRows,readLocalFingerprint,snapshotComparable,typedProjection} from "./backup-evidence.mjs";
const account=process.env.CLOUDFLARE_ACCOUNT_ID,read=process.env.CLOUDFLARE_API_TOKEN,manage=process.env.CLOUDFLARE_MANAGEMENT_TOKEN,backup=process.env.CLOUDFLARE_D1_BACKUP_TOKEN;
const maxSqlBytes=16*1024*1024;
const production="e7699170-b634-48ce-a3b0-733aedb9b898",preview="657131f8-b0f4-47f3-ab3d-91840843f2db",trigger="9ee2b6ad-e77b-48ce-833c-5bbcd9f4af83";
const root="https://api.cloudflare.com/client/v4/accounts/"+account,run=process.env.GITHUB_RUN_ID,sha=process.env.GITHUB_SHA;
const out={sha,checked_at:new Date().toISOString(),source:production,fingerprint_format:FINGERPRINT_FORMAT,checks:{},backup_token_present:!!backup};
const check=(name,v)=>{out.checks[name]=Boolean(v);assert.ok(v,name);};
let stage="preflight",temp,local;
async function api(path,token=read,method="GET",body){
 const r=await fetch(root+path,{method,headers:{Authorization:"Bearer "+token,...(body?{"Content-Type":"application/json"}:{})},...(body?{body:JSON.stringify(body)}:{}),redirect:"error",signal:AbortSignal.timeout(30000)});
 const j=await r.json().catch(()=>null);
 return {http:r.status,ok:r.ok&&j?.success===true,result:j?.result,errors:(j?.errors||[]).map(e=>e.code).filter(Number.isInteger),info:j?.result_info};
}
const query=async(id,sql,token=read)=>{
 assert.ok(id===production||id===out.restore_id);
 const r=await api("/d1/database/"+id+"/query",token,"POST",{sql});
 assert.ok(r.ok&&r.result?.length===1&&r.result[0].success===true&&Array.isArray(r.result[0].results));
 return r.result[0].results;
};
const schemaSql="SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE type IN ('table','index','trigger','view') AND name NOT GLOB '_cf_*' AND (name NOT GLOB 'sqlite_*' OR name='sqlite_sequence') ORDER BY type,name";
const tableName=n=>{assert.ok(/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(n));return '"'+n+'"';};
const summarizeSchema=rows=>rows.map(({type,name,tbl_name,sql})=>({type,name,tbl_name,sql}));
const deploy=async()=>{const r=await api("/workers/scripts/execution-guard/deployments");assert.ok(r.ok);return r.result.deployments.slice(0,1).map(d=>({id:d.id,versions:d.versions.map(v=>({id:v.version_id,percentage:v.percentage}))}));};
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const bookmark=async()=>{
 const r=await api("/d1/database/"+production+"/time_travel/bookmark");
 assert.ok(r.ok&&typeof r.result?.bookmark==="string"&&r.result.bookmark.length>0);
 return r.result.bookmark;
};
async function readRemoteTables(id,tables,token){
 const encoding=await query(id,"PRAGMA encoding",token);
 check(id===production?"source_utf8":"restore_utf8",encoding.length===1&&encoding[0].encoding==="UTF-8");
 const results=[];
 for(const {name} of tables){
  const table=tableName(name);
  const columns=(await query(id,"PRAGMA table_xinfo("+table+")",token)).map(column=>column.name);
  const count=await query(id,"SELECT CAST(COUNT(*) AS TEXT) AS n FROM "+table,token);
  const projected=await query(id,"SELECT "+typedProjection(columns)+" FROM "+table,token);
  // The default projection rejects REAL until binary64 can be verified in D1.
  const result=fingerprint(columns,projectedRows(columns,projected));
  check("complete_"+(id===production?"source_":"restore_")+name,count.length===1&&count[0].n===String(result.rows));
  results.push([name,result]);
 }
 return Object.fromEntries(results);
}
try{
 check("fixed_target",process.env.GITHUB_REPOSITORY==="19wolfalone92/Execution-Guard"&&process.env.GITHUB_REF==="refs/heads/audit/oauth-e2e-20261125"&&account==="04b45c9393f4e12159c6b8118ec54791"&&/^[0-9]+$/.test(run||"")&&/^[a-f0-9]{40}$/.test(sha||""));
 check("qualified_sha_selected",process.env.EG_PRODUCTION_BACKUP_QUALIFIED_SHA===sha);
 check("read_management_present",!!read&&!!manage);
 const config=JSON.parse(await (await import("node:fs/promises")).readFile("wrangler.jsonc","utf8"));
 check("config_ids",config.d1_databases.length===1&&config.d1_databases[0].database_id===production&&config.previews.d1_databases[0].database_id===preview);
 out.production_before=await deploy();
 check("production_deployment_verified",deploymentMetadata(out.production_before));
 const source=await api("/d1/database/"+production),list=await api("/d1/database?per_page=100");
 check("source_identity",source.ok&&(source.result.uuid||source.result.id)===production&&source.result.name==="execution-guard-db");
 check("list_access",list.ok&&Array.isArray(list.result));
 out.source_bytes=source.result.file_size??null;out.database_count=list.info?.total_count??list.result.length;
 const before=await bookmark();
 const rows=await query(production,schemaSql);out.source_schema=summarizeSchema(rows).map(x=>({type:x.type,name:x.name}));out.source_schema_sha256=digest(JSON.stringify(summarizeSchema(rows)));
 const tables=rows.filter(x=>x.type==="table");
 // Backups inspect the production trigger without changing it.
 stage="controlled_trigger";
 const workers=await api("/workers/scripts");const tag=workers.result?.find(x=>x.id==="execution-guard")?.tag;
 check("worker_tag",workers.ok&&typeof tag==="string"&&/^[a-f0-9-]{32,36}$/.test(tag));
 const getTrigger=async()=>{const list=await api("/builds/workers/"+tag+"/triggers",manage);return {...list,result:list.result?.find(t=>t.trigger_uuid===trigger)};};
 const tr=await getTrigger();out.trigger_before={http:tr.http,ok:tr.ok,errors:tr.errors};
 check("controlled_trigger",tr.ok&&tr.result?.trigger_uuid===trigger&&tr.result?.deploy_command==="npx wrangler versions upload"&&JSON.stringify(tr.result.branch_includes)===JSON.stringify(["main"]));
 if(!backup){out.status="BLOCKED";out.reason="missing_d1_edit_token";process.exitCode=1;}
 else{
  stage="backup_limits";check("free_database_slot",out.database_count<10);check("bounded_size",Number.isSafeInteger(out.source_bytes)&&out.source_bytes>0&&out.source_bytes<=maxSqlBytes);
  check("supported_source_tables",tables.length>0&&!tables.some(x=>/^CREATE\s+VIRTUAL\s+TABLE/i.test(x.sql||"")));
  const name="execution-guard-backup-"+run;check("unique_backup_name",!list.result.some(x=>x.name===name));
  stage="source_exact_fingerprint";
  out.source_tables=await readRemoteTables(production,tables,read);
  const after=await bookmark();
  check("source_snapshot_stable",before===after);
  // D1 export locks the source temporarily; bounded polling, no SQL or signed URL in logs.
  stage="export";let exportBookmark,url;
  for(let i=0;i<45;i++){
   const e=await api("/d1/database/"+production+"/export",backup,"POST",{output_format:"polling",...(exportBookmark?{current_bookmark:exportBookmark}:{})});
   if(!e.ok){out.export_http=e.http;out.export_errors=e.errors;throw Error("export");}
   exportBookmark=e.result?.at_bookmark||exportBookmark;if(e.result?.status==="error")throw Error("export");
   if(e.result?.status==="complete"){exportBookmark=e.result?.at_bookmark;url=e.result?.result?.signed_url;break;}
   assert.ok(exportBookmark);await sleep(2000);
  }
  check("export_complete",typeof url==="string"&&typeof exportBookmark==="string");
  out.snapshot={before,after,exportBookmark};
  check("source_snapshot_verified",snapshotComparable(out.snapshot));
  const signed=new URL(url);check("signed_url_https",signed.protocol==="https:"&&!signed.username&&!signed.password);
  const download=await fetch(signed,{redirect:"error",signal:AbortSignal.timeout(30000)});check("download_ok",download.ok);
  const chunks=[];let size=0;
  for await(const chunk of download.body){
   size+=chunk.length;
   assert.ok(size<=maxSqlBytes);
   chunks.push(chunk);
  }
  check("sql_bounded",size>0);
  const sql=Buffer.concat(chunks,size);
  out.sql_bytes=sql.length;out.sql_sha256=digest(sql);
  temp=mkdtempSync(join(tmpdir(),"eg-backup-"));const file=join(temp,"backup.sql");writeFileSync(file,sql,{mode:0o600});
  stage="local_restore";local=new DatabaseSync(":memory:",{allowExtension:false});
  local.exec(new TextDecoder("utf-8",{fatal:true}).decode(sql));
  check("local_integrity",local.prepare("PRAGMA integrity_check").get().integrity_check==="ok");
  check("local_foreign_keys",local.prepare("PRAGMA foreign_key_check").all().length===0);
  const localSchema=local.prepare(schemaSql).all();
  out.dump_schema_sha256=digest(JSON.stringify(summarizeSchema(localSchema)));
  check("schema_matches_export",out.dump_schema_sha256===out.source_schema_sha256);
  out.dump_tables=Object.fromEntries(tables.map(({name})=>{
   const columns=local.prepare("PRAGMA table_xinfo("+tableName(name)+")").all().map(column=>column.name);
   return [name,readLocalFingerprint(local,name,columns)];
  }));
  check("dump_matches_source",JSON.stringify(out.dump_tables)===JSON.stringify(out.source_tables));
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
  const restoredSchema=await query(out.restore_id,schemaSql,backup);
  out.restore_schema_sha256=digest(JSON.stringify(summarizeSchema(restoredSchema)));
  check("restored_schema",out.restore_schema_sha256===out.source_schema_sha256);
  out.restore_tables=await readRemoteTables(out.restore_id,tables,backup);
  check("restore_matches_source",JSON.stringify(out.restore_tables)===JSON.stringify(out.source_tables));
  const integrity=await query(out.restore_id,"PRAGMA quick_check",backup);
  check("remote_quick_check",integrity.length===1&&integrity[0].quick_check==="ok");
  check("remote_foreign_keys",(await query(out.restore_id,"PRAGMA foreign_key_check",backup)).length===0);
  const settings=await api("/workers/scripts/execution-guard/settings");check("restore_not_bound",settings.ok&&!JSON.stringify(settings.result?.bindings||[]).includes(out.restore_id));
  // The isolated restored D1 is the retained private snapshot; SQL remains
  // temporary, no public Actions artifact and no plaintext output.
  out.retained_backup="unbound_private_D1";
  out.status="PARTIAL";out.reason="independent_provenance_not_verified";process.exitCode=1;
 }
}catch(e){out.status="BLOCKED";out.reason=stage;process.exitCode=1;}
finally{
 if(local)local.close();if(temp)rmSync(temp,{recursive:true,force:true});
 if(out.production_before){try{out.production_after=await deploy();out.checks.production_worker_unchanged=deploymentMetadata(out.production_before)&&deploymentMetadata(out.production_after)&&JSON.stringify(out.production_before)===JSON.stringify(out.production_after);if(!out.checks.production_worker_unchanged){out.status="FAIL";process.exitCode=1;}}catch{out.checks.production_worker_unchanged=false;out.status="BLOCKED";process.exitCode=1;}}
 console.log("EG_BACKUP_PREFLIGHT "+JSON.stringify(out));
}
