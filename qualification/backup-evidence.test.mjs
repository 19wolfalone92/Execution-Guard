import test from 'node:test';
import assert from 'node:assert/strict';
import {validateEvidence, fingerprint, snapshotComparable, deploymentMetadata, digest, FINGERPRINT_FORMAT, realBits, typedProjection, projectedRows} from './backup-evidence.mjs';
const id=n=>`00000000-0000-0000-0000-${String(n).padStart(12,'0')}`;
const sha='a'.repeat(40), h=digest('fixture'), now=Date.parse('2026-11-25T15:00:00Z');
const deployment=[{id:id(4),versions:[{id:id(5),percentage:100}]}];
const expected={fingerprint_format:FINGERPRINT_FORMAT,repository:'synthetic/repo',sha,source:id(1),preview:id(2),version:'0.6.0',workflow_sha256:h,now,current_deployment:deployment,required_tables:['checkpoints','tasks']};
const tables={checkpoints:{rows:2,sha256:h},tasks:{rows:0,sha256:h}};
const checks=Object.fromEntries(['source_identity','full_export','local_integrity','local_foreign_keys','remote_quick_check','remote_foreign_keys','restore_unbound','temporary_cleanup','dependency_review','controlled_trigger','no_destructive_sql','private_retention','source_snapshot_verified'].map(k=>[k,true]));
const fixture=()=>structuredClone({fingerprint_format:FINGERPRINT_FORMAT,repository:expected.repository,sha,version:expected.version,source:expected.source,status:'PASS',schema_only:false,run_id:'123',workflow_sha256:h,started_at:'2026-11-25T14:50:00Z',completed_at:'2026-11-25T14:55:00Z',snapshot:{before:'bookmark-A',after:'bookmark-A',exportBookmark:'bookmark-A'},source_bytes:100,sql_bytes:200,sql_sha256:h,restore_id:id(3),source_schema_sha256:h,dump_schema_sha256:h,restore_schema_sha256:h,source_tables:tables,dump_tables:structuredClone(tables),restore_tables:structuredClone(tables),production_before:deployment,production_after:structuredClone(deployment),checks,qualification:{sha,ci:true,migration:true,rollback:true,preview:true,security:true,oauth:true,critical_defects:0}});
test('valid synthetic shape (NOT real release evidence)',()=>assert.deepEqual(validateEvidence(fixture(),expected),{ok:true,errors:[]}));
for(const [name,change] of Object.entries({
  absent_backup:e=>delete e.sql_sha256, schema_only:e=>e.schema_only=true, forged_pass_only:e=>{for(const k of Object.keys(e))if(k!=='status')delete e[k]}, wrong_repo:e=>e.repository='other/repo',wrong_sha:e=>e.sha='b'.repeat(40),wrong_version:e=>e.version='0.5.0',wrong_source:e=>e.source=id(8),wrong_workflow:e=>e.workflow_sha256='b'.repeat(64),missing_run:e=>delete e.run_id,stale:e=>e.completed_at='2026-11-25T13:00:00Z',future:e=>e.completed_at='2026-11-26T00:00:00Z',changed_bookmark:e=>e.snapshot.after='bookmark-B',export_bookmark_mismatch:e=>e.snapshot.exportBookmark='bookmark-B',empty_bookmarks:e=>e.snapshot={before:'',after:'',exportBookmark:''},zero_size:e=>e.sql_bytes=0,oversize:e=>e.sql_bytes=17*1024*1024,production_restore:e=>e.restore_id=id(1),preview_restore:e=>e.restore_id=id(2),schema_mismatch:e=>e.restore_schema_sha256='b'.repeat(64),missing_table:e=>delete e.dump_tables.tasks,missing_required_all:e=>{delete e.source_tables.tasks;delete e.dump_tables.tasks;delete e.restore_tables.tasks},count_mismatch:e=>e.dump_tables.checkpoints.rows=1,hash_mismatch:e=>e.restore_tables.checkpoints.sha256='b'.repeat(64),empty_deployments:e=>{e.production_before=[];e.production_after=[]},bad_traffic:e=>e.production_after[0].versions[0].percentage=90,changed_deployment:e=>e.production_after[0].id=id(9),wrong_current_deployment:e=>{e.production_before[0].id=id(9);e.production_after[0].id=id(9)},missing_migrations:e=>delete e.qualification.migration,rollback_failure:e=>e.qualification.rollback=false,critical_defect:e=>e.qualification.critical_defects=1,wrong_qualification_sha:e=>e.qualification.sha='b'.repeat(40),missing_ci:e=>delete e.qualification.ci,missing_oauth:e=>delete e.qualification.oauth,missing_preview:e=>delete e.qualification.preview,missing_security:e=>delete e.qualification.security,malformed:e=>e.source_tables=null
})){test(name,()=>{const e=fixture();change(e);assert.equal(validateEvidence(e,expected).ok,false)});}
for(const k of Object.keys(checks))test('missing check '+k,()=>{const e=fixture();delete e.checks[k];assert.equal(validateEvidence(e,expected).ok,false)});
test('no evidence',()=>assert.equal(validateEvidence(null,expected).ok,false));
test('no trusted context',()=>assert.equal(validateEvidence(fixture(),null).ok,false));
test('bookmark changed despite same count not comparable',()=>assert.equal(snapshotComparable({before:'a',after:'b',exportBookmark:'a'}),false));
test('empty deployment invalid',()=>assert.equal(deploymentMetadata([]),false));
const a=[['integer','9007199254740993'],['text','78']],b=[['integer','9007199254740992'],['text','78']];
test('large integers distinct',()=>assert.notEqual(fingerprint(['id','v'],[a]).sha256,fingerprint(['id','v'],[b]).sha256));
test('row ordering irrelevant',()=>assert.deepEqual(fingerprint(['id','v'],[a,b]),fingerprint(['id','v'],[b,a])));
test('duplicates retained',()=>assert.notDeepEqual(fingerprint(['id','v'],[a,a]),fingerprint(['id','v'],[a])));
test('types distinct',()=>assert.notEqual(fingerprint(['x'],[[['text','31']]]).sha256,fingerprint(['x'],[[['integer','1']]]).sha256));
test('null versus empty blob distinct',()=>assert.notEqual(fingerprint(['x'],[[['null',null]]]).sha256,fingerprint(['x'],[[['blob','']]]).sha256));
test('malformed cell rejected',()=>assert.throws(()=>fingerprint(['x'],[[['integer',1]]])));

test('raw text rejected rather than silently hashing truncated text',()=>assert.throws(()=>fingerprint(['x'],[[['text','raw text']]])));
test('same bytes text versus blob distinct',()=>assert.notEqual(fingerprint(['x'],[[['text','610062']]]).sha256,fingerprint(['x'],[[['blob','610062']]]).sha256));

const fp=(type,value)=>fingerprint(['x'],[[[type,value]]]);
test('int64 endpoints accepted and distinct',()=>assert.notDeepEqual(fp('integer','-9223372036854775808'),fp('integer','9223372036854775807')));
for(const value of ['9223372036854775808','-9223372036854775809','-0','01','+1','1\n','1e2',''])test('invalid int64 '+JSON.stringify(value),()=>assert.throws(()=>fp('integer',value)));
for(const value of ['0.0','-0.0','1e999','Infinity','7FF8000000000000','7FF0000000000001','FFF8000000000000','000000000000000','0000000000000000\n','000000000000000g'])test('invalid REAL '+JSON.stringify(value),()=>assert.throws(()=>fp('real',value)));
test('binary64 signed zeros and infinities distinct',()=>{
 const values=[-0,0,Infinity,-Infinity,Number.MIN_VALUE,-Number.MIN_VALUE,Number.MAX_VALUE,-Number.MAX_VALUE,2**-1022,-(2**-1022)];
 assert.equal(new Set(values.map(v=>fp('real',realBits(v)).sha256)).size,values.length);
 assert.equal(realBits(-0),'8000000000000000');assert.equal(realBits(0),'0000000000000000');
 assert.throws(()=>realBits(NaN));assert.throws(()=>realBits(null));assert.throws(()=>realBits(1n));
});
test('all five storage classes distinct',()=>assert.equal(new Set([fp('null',null),fp('text',''),fp('blob',''),fp('integer','0'),fp('real',realBits(0))].map(v=>v.sha256)).size,5));
test('reject malformed bytes and sparse arrays',()=>{
 for(const v of ['A','FF\n','ff','A G','FFFF\r\n'])assert.throws(()=>fp('text',v));
 for(const r of [Array(1),[Array(1)],[[Array(2)]]])assert.throws(()=>fingerprint(['x'],r));
 assert.throws(()=>fingerprint(Array(1),[]));
 assert.throws(()=>projectedRows(['x'],Array(1)));
});
test('default projection fails closed for REAL and excludes decimal fallback',()=>{
 const sql=typedProjection(['x']);assert.match(sql,/WHEN 'real' THEN NULL/);assert.doesNotMatch(sql,/printf|ieee754/);
 assert.match(typedProjection(['x'],'ieee754'),/hex\(ieee754_to_blob/);
 assert.throws(()=>typedProjection(['x'],'decimal'));
 assert.throws(()=>fingerprint(['x'],projectedRows(['x'],[{t0:'real',v0:null}])));
});
test('missing aliases and extraneous response fields rejected',()=>{
 for(const row of [{t0:'text'},{t0:'text',v0:'61',other:'x'},{t1:'text',v1:'61'}])assert.throws(()=>projectedRows(['x'],[row]));
});
test('legacy evidence format rejected even with PASS and equal hashes',()=>{
 const e=fixture();delete e.fingerprint_format;assert.equal(validateEvidence(e,expected).ok,false);
 e.fingerprint_format='eg-sqlite-typed-v1';assert.equal(validateEvidence(e,expected).ok,false);
 assert.equal(validateEvidence(fixture(),{...expected,fingerprint_format:undefined}).ok,false);
});
test('complete synthetic evidence is still only shape, not independent provenance',()=>{
 assert.equal(validateEvidence(fixture(),expected).ok,true);
 // This helper deliberately does not authenticate run metadata or artifacts.
 // No release decision may use this result alone.
});
