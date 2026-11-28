// Offline validation module. No network, credentials, deployment or release authority.
import { createHash } from 'node:crypto';
const sha = x => typeof x === 'string' && /^[a-f0-9]{64}$/.test(x);
const commit = x => typeof x === 'string' && /^[a-f0-9]{40}$/.test(x);
const uuid = x => typeof x === 'string' && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(x);
const obj = x => x !== null && typeof x === 'object' && !Array.isArray(x);
const nonempty = x => typeof x === 'string' && x.trim().length > 0;
const integer = x => Number.isSafeInteger(x) && x >= 0;
export const digest = x => createHash('sha256').update(x).digest('hex');
export function canonical(x) {
  if (x === null || typeof x === 'string' || typeof x === 'boolean') return JSON.stringify(x);
  if (typeof x === 'number' && Number.isFinite(x)) return JSON.stringify(x);
  if (Array.isArray(x)) return '['+x.map(canonical).join(',')+']';
  if (obj(x) && (Object.getPrototypeOf(x) === Object.prototype || Object.getPrototypeOf(x) === null)) return '{'+Object.keys(x).sort().map(k=>JSON.stringify(k)+':'+canonical(x[k])).join(',')+'}';
  throw new TypeError('Unsupported canonical JSON type');
}
// Versioned typed-value contract. It does not prove physical SQLite page identity.
export const FINGERPRINT_FORMAT = 'eg-sqlite-typed-v2';
const INT64_MIN = -(1n << 63n), INT64_MAX = (1n << 63n) - 1n;
const binary64 = /^[0-9A-F]{16}$/;
const dense = x => Array.isArray(x) && Array.from(x,(_,i)=>Object.hasOwn(x,i)).every(Boolean);
export function realBits(value) {
  if (typeof value !== 'number' || Number.isNaN(value)) throw new TypeError('REAL not representable');
  const buffer = Buffer.alloc(8);
  buffer.writeDoubleBE(value);
  return buffer.toString('hex').toUpperCase();
}
const validReal = value => {
  if (value.length!==16 || !binary64.test(value)) return false;
  const bits = BigInt('0x'+value);
  // SQLite turns NaN into NULL; reject impossible REAL NaN encodings.
  return (bits & 0x7FF0000000000000n) !== 0x7FF0000000000000n ||
         (bits & 0x000FFFFFFFFFFFFFn) === 0n;
};
function validColumns(columns) {
  return dense(columns) && columns.length > 0 && new Set(columns).size === columns.length &&
    columns.every(c => nonempty(c) && !c.includes('\0') && Buffer.from(c,'utf8').toString('utf8')===c);
}
const quoteIdentifier = name => {
  if (!validColumns([name])) throw new TypeError('identifier');
  return '"'+name.replaceAll('"','""')+'"';
};
// Explicit mode: blocked is safe for a remote source without verified IEEE extension.
// "ieee754" is NOT a capability assertion. The caller must test the actual endpoint.
// Require UTF-8 database encoding to be verified independently before using this SQL.
export function typedProjection(columns, mode='blocked') {
  if (!validColumns(columns)) throw new TypeError('columns');
  if (!['blocked','local','ieee754'].includes(mode)) throw new TypeError('REAL mode');
  return columns.flatMap((name,i)=>{
    const col=quoteIdentifier(name);
    const real=mode==='local'?`eg_real_bits_v2(${col})`:mode==='ieee754'?`hex(ieee754_to_blob(${col}))`:'NULL';
    return [`typeof(${col}) AS t${i}`,`CASE typeof(${col}) WHEN 'null' THEN NULL WHEN 'blob' THEN hex(${col}) WHEN 'text' THEN hex(CAST(${col} AS BLOB)) WHEN 'integer' THEN CAST(${col} AS TEXT) WHEN 'real' THEN ${real} ELSE NULL END AS v${i}`];
  }).join(',');
}
export function projectedRows(columns, result) {
  if (!validColumns(columns)||!dense(result)) throw new TypeError('projection shape');
  const keys=columns.flatMap((_,i)=>['t'+i,'v'+i]);
  return result.map(row=>{
    if (!obj(row)||Object.keys(row).length!==keys.length||!keys.every(k=>Object.hasOwn(row,k))) throw new TypeError('projection aliases');
    return columns.map((_,i)=>[row['t'+i],row['v'+i]]);
  });
}
// Local Node SQLite only. No loading extensions or network access.
export function readLocalFingerprint(db,table,columns) {
  if (db.prepare('PRAGMA main.encoding').get()?.encoding!=='UTF-8') throw new TypeError('unverified UTF-8 database encoding');
  const name=quoteIdentifier(table);
  if (!validColumns(columns)) throw new TypeError('columns');
  const meta=db.prepare('PRAGMA main.table_list').all().find(r=>r.name===table);
  if (meta?.type!=='table') throw new TypeError('ordinary main table required');
  const actual=db.prepare(`PRAGMA main.table_xinfo(${name})`).all().map(r=>r.name);
  if (canonical(actual)!==canonical(columns)) throw new TypeError('columns must match full table schema');
  db.function('eg_real_bits_v2',{deterministic:true,directOnly:true},realBits);
  const sql=`SELECT ${typedProjection(columns,'local')} FROM main.${name}`;
  return fingerprint(columns,projectedRows(columns,db.prepare(sql).all()));
}
export function fingerprint(columns, rows) {
  if (!validColumns(columns)) throw new TypeError('columns');
  if (!dense(rows)) throw new TypeError('rows');
  const encoded = rows.map(row => {
    if (!dense(row) || row.length !== columns.length) throw new TypeError('row shape');
    for(const cell of row) {
      if(!dense(cell)||cell.length!==2) throw new TypeError('cell shape');
      const [type,value]=cell;
      if(type==='null' ? value!==null : !['integer','real','text','blob'].includes(type)||typeof value!=='string') throw new TypeError('cell type');
      if(type==='integer') {
        if(value.length>20 || !/^(0|-?[1-9]\d*)$/.test(value)) throw new TypeError('integer');
        const n=BigInt(value);
        if(n.toString()!==value || n<INT64_MIN||n>INT64_MAX) throw new RangeError('integer range');
      }
      if((type==='blob'||type==='text')&&(value.length%2!==0 || /[^0-9A-F]/.test(value))) throw new TypeError('byte representation');
      if(type==='real'&&!validReal(value)) throw new TypeError('REAL requires exact non-NaN IEEE 754 binary64 bytes');
    }
    return canonical(row);
  }).sort();
  return {rows:rows.length, sha256:digest(canonical([FINGERPRINT_FORMAT,columns,encoded]))};
}
export function snapshotComparable({before,after,exportBookmark}={}) {
  // Conservative sufficient condition; Cloudflare may advance bookmarks without writes.
  return nonempty(before) && before===after && after===exportBookmark;
}
export function deploymentMetadata(value) {
  return Array.isArray(value)&&value.length===1&&uuid(value[0]?.id)&&Array.isArray(value[0].versions)&&value[0].versions.length>0&&value[0].versions.every(v=>uuid(v?.id)&&typeof v.percentage==='number'&&Number.isFinite(v.percentage)&&v.percentage>0&&v.percentage<=100)&&new Set(value[0].versions.map(v=>v.id)).size===value[0].versions.length&&value[0].versions.reduce((s,v)=>s+v.percentage,0)===100;
}
const validTableMap = x => obj(x)&&Object.keys(x).length>0&&Object.values(x).every(t=>obj(t)&&integer(t.rows)&&sha(t.sha256));
const equal = (a,b) => canonical(a)===canonical(b);
const checks = ['source_identity','full_export','local_integrity','local_foreign_keys','remote_quick_check','remote_foreign_keys','restore_unbound','temporary_cleanup','dependency_review','controlled_trigger','no_destructive_sql','private_retention','source_snapshot_verified'];
// This only validates shape and consistency. Authenticity must be established independently
// by a trusted caller checking immutable run metadata and artifact provenance. Never treat
// self-reported fields as authorization. No live deployment code is included.
export function validateEvidence(e, expected) {
  const errors=[];const need=(c,n)=>{if(!c) errors.push(n);};
  if(!obj(e)||!obj(expected))return {ok:false,errors:['missing_evidence_or_context']};
  try {
    need(nonempty(expected.repository)&&commit(expected.sha)&&uuid(expected.source)&&uuid(expected.preview)&&expected.source!==expected.preview&&nonempty(expected.version),'invalid_expected_context');
    need(e.repository===expected.repository&&e.sha===expected.sha&&e.version===expected.version&&e.source===expected.source,'identity');
    need(e.status==='PASS'&&e.schema_only===false,'full_backup');
    need(e.fingerprint_format===FINGERPRINT_FORMAT && expected.fingerprint_format===FINGERPRINT_FORMAT,'fingerprint_format');
    need(typeof e.run_id==='string'&&/^[1-9]\d*$/.test(e.run_id)&&sha(e.workflow_sha256),'run_metadata');
    need(sha(expected.workflow_sha256)&&e.workflow_sha256===expected.workflow_sha256,'workflow_digest');
    const now=expected.now, started=Date.parse(e.started_at), ended=Date.parse(e.completed_at);
    need(Number.isFinite(now)&&Number.isFinite(started)&&Number.isFinite(ended)&&started<=ended&&ended<=now&&now-ended<=3600000&&ended-started<=900000,'freshness');
    need(snapshotComparable(e.snapshot),'snapshot_consistency');
    need(integer(e.source_bytes)&&e.source_bytes>0&&e.source_bytes<=16*1024*1024&&integer(e.sql_bytes)&&e.sql_bytes>0&&e.sql_bytes<=16*1024*1024&&sha(e.sql_sha256),'dump_metadata');
    need(uuid(e.restore_id)&&e.restore_id!==expected.source&&e.restore_id!==expected.preview,'restore_isolation');
    need(sha(e.source_schema_sha256)&&e.source_schema_sha256===e.dump_schema_sha256&&e.source_schema_sha256===e.restore_schema_sha256,'schema');
    need(validTableMap(e.source_tables)&&validTableMap(e.dump_tables)&&validTableMap(e.restore_tables)&&equal(e.source_tables,e.dump_tables)&&equal(e.dump_tables,e.restore_tables),'table_content');
    need(Array.isArray(expected.required_tables)&&expected.required_tables.length>0&&expected.required_tables.every(k=>nonempty(k)&&Object.hasOwn(e.source_tables??{},k)),'required_tables');
    need(deploymentMetadata(e.production_before)&&deploymentMetadata(e.production_after)&&equal(e.production_before,e.production_after),'deployment');
    need(deploymentMetadata(expected.current_deployment)&&equal(e.production_after,expected.current_deployment),'current_deployment');
    need(obj(e.checks)&&checks.every(k=>e.checks[k]===true),'required_checks');
    // Separate evidence for qualification; same commit, independently authenticated by caller.
    const q=e.qualification;
    need(obj(q)&&q.sha===expected.sha&&['ci','migration','rollback','preview','security','oauth'].every(k=>q[k]===true),'qualification');
    need(q?.critical_defects===0,'critical_defects');
  } catch {errors.push('malformed_evidence');}
  return {ok:errors.length===0,errors};
}
