import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {fingerprint, readLocalFingerprint, typedProjection, projectedRows, realBits} from './backup-evidence.mjs';
function sample() {
 const db=new DatabaseSync(':memory:');
 db.exec("CREATE TABLE parent(id INTEGER PRIMARY KEY); CREATE TABLE sample(id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id), payload BLOB, note TEXT, amount REAL); CREATE INDEX sample_note ON sample(note); INSERT INTO parent VALUES(1); INSERT INTO sample VALUES(9007199254740993,1,X'00FF','a',0.12345678901234567),(9007199254740992,1,NULL,'b',-1.25);");return db;
}
function inspect(db) {
 const columns=['id','parent_id','payload','note','amount'];
 return readLocalFingerprint(db,'sample',columns);
}
test('Independent SQLite copies preserve large integer, blob, null and real',()=>{const a=sample(),b=sample();try{assert.deepEqual(inspect(a),inspect(b));assert.equal(a.prepare('PRAGMA integrity_check').get().integrity_check,'ok');assert.equal(b.prepare('PRAGMA quick_check').get().quick_check,'ok');assert.deepEqual(b.prepare('PRAGMA foreign_key_check').all(),[]);}finally{a.close();b.close();}});
test('SQLite same row count but modified value detected',()=>{const a=sample(),b=sample();try{b.exec("UPDATE sample SET note='changed' WHERE id=9007199254740993");assert.equal(inspect(a).rows,inspect(b).rows);assert.notEqual(inspect(a).sha256,inspect(b).sha256);}finally{a.close();b.close();}});
test('SQLite truncated restore is detected',()=>{const a=sample(),b=sample();try{b.exec('DELETE FROM sample WHERE id=9007199254740993');assert.notDeepEqual(inspect(a),inspect(b));}finally{a.close();b.close();}});
test('SQLite foreign key corruption detected independently of quick_check',()=>{const a=sample();try{a.exec('PRAGMA foreign_keys=OFF; UPDATE sample SET parent_id=9;');assert.equal(a.prepare('PRAGMA quick_check').get().quick_check,'ok');const fk=a.prepare('PRAGMA foreign_key_check');fk.setReadBigInts(true);assert.equal(fk.all().length,2);}finally{a.close();}});

test('embedded NUL is distinguished from truncated text in actual SQLite',()=>{const a=sample(),b=sample();try{assert.equal(a.prepare('PRAGMA encoding').get().encoding,'UTF-8');a.exec("UPDATE sample SET note=CAST(X'610062' AS TEXT) WHERE id=9007199254740993");assert.notDeepEqual(inspect(a),inspect(b));assert.equal(a.prepare("SELECT hex(note) AS h FROM sample WHERE id=9007199254740993").get().h,'610062');}finally{a.close();b.close();}});
test('invalid UTF-8 text bytes are distinguished by hex projection',()=>{const a=sample(),b=sample();try{a.exec("UPDATE sample SET note=CAST(X'FF' AS TEXT) WHERE id=9007199254740993");b.exec("UPDATE sample SET note=CAST(X'FE' AS TEXT) WHERE id=9007199254740993");assert.notDeepEqual(inspect(a),inspect(b));}finally{a.close();b.close();}});
test('SQL round trip distinguishes lossless byte literal from truncated SQLite quote()',()=>{const a=sample(),b=sample();try{
 a.exec("UPDATE sample SET note=CAST(X'610062' AS TEXT) WHERE id=9007199254740993");
 const r=a.prepare("SELECT hex(CAST(note AS BLOB)) AS bytes, quote(note) AS quoted FROM sample WHERE id=9007199254740993").get();
 assert.equal(r.bytes,'610062');assert.equal(r.quoted,"'a'");
 b.exec(`UPDATE sample SET note=CAST(X'${r.bytes}' AS TEXT) WHERE id=9007199254740993`);assert.deepEqual(inspect(a),inspect(b));
 b.exec(`UPDATE sample SET note=${r.quoted} WHERE id=9007199254740993`);assert.notDeepEqual(inspect(a),inspect(b));
}finally{a.close();b.close();}});

import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
const shaBytes=x=>createHash('sha256').update(x).digest();
const hex=x=>Buffer.from(x).toString('hex').toUpperCase();
const read=db=>readLocalFingerprint(db,'t',['v']);
function py(args,script){const p=spawnSync('python3',['-c',script,...args],{encoding:'utf8',maxBuffer:32*1024*1024,timeout:30000});assert.equal(p.status,0,p.stderr);return p.stdout;}
const oracle=String.raw`
import sqlite3,struct,hashlib,json,sys
con=sqlite3.connect(sys.argv[1]); con.text_factory=bytes
rows=[]
for t,v in con.execute('SELECT typeof(v),v FROM t'):
    t=t.decode('ascii')
    if t=='real': v=struct.pack('>d',v).hex().upper()
    elif t=='integer': v=str(v)
    elif t in ('text','blob'): v=v.hex().upper()
    rows.append(json.dumps([[t,v]],separators=(',',':'),ensure_ascii=True))
encoded=json.dumps(['eg-sqlite-typed-v2',['v'],sorted(rows)],separators=(',',':'),ensure_ascii=True).encode('ascii')
print(json.dumps({'rows':len(rows),'sha256':hashlib.sha256(encoded).hexdigest()}))
`;
function inFile(fn){const dir=mkdtempSync(join(tmpdir(),'eg-r42-'));try{fn(join(dir,'source.sqlite'),join(dir,'restore.sqlite'));}finally{rmSync(dir,{recursive:true,force:true});}}
function expectedRow(type,value){return fingerprint(['v'],[[[type,value]]]);}
test('local read checks full schema, main table and UTF-8',()=>{
 const db=new DatabaseSync(':memory:');try{
 db.exec('CREATE TABLE t(v, w); CREATE TEMP TABLE t(v); CREATE VIEW vv AS SELECT v FROM main.t;');
 assert.throws(()=>read(db));assert.throws(()=>readLocalFingerprint(db,'t',['v','missing']));
 assert.throws(()=>readLocalFingerprint(db,'vv',['v']));
 assert.deepEqual(readLocalFingerprint(db,'t',['v','w']),fingerprint(['v','w'],[]));
 }finally{db.close();}
 const utf=new DatabaseSync(':memory:');try{utf.exec("PRAGMA encoding='UTF-16le'; CREATE TABLE t(v)");assert.throws(()=>read(utf),/UTF-8/);}finally{utf.close();}
});
test('SQLite native extension availability is checked, not assumed',()=>{
 const d=new DatabaseSync(':memory:');try{
 const funcs=d.prepare('PRAGMA function_list').all().map(r=>r.name);
 assert.ok(funcs.includes('typeof')&&funcs.includes('hex'));
 // Node 22.16.0 SQLite 3.49.1 lacks the optional ieee754 extension.
 if(funcs.includes('ieee754_to_blob'))assert.equal(d.prepare('SELECT hex(ieee754_to_blob(-0.0)) AS v').get().v,'8000000000000000');
 else assert.throws(()=>d.prepare('SELECT ieee754_to_blob(1.0)'));
 if(funcs.includes('ieee754_from_blob'))assert.equal(d.prepare("SELECT ieee754_from_blob(X'3FF0000000000000') AS v").get().v,1);
 else assert.throws(()=>d.prepare("SELECT ieee754_from_blob(X'3FF0000000000000')"));
 }finally{d.close();}
});
test('actual SQLite REAL sign, infinities and NaN storage behavior',()=>inFile(path=>{
 let db=new DatabaseSync(path);db.exec('CREATE TABLE t(v)');const ins=db.prepare('INSERT INTO t VALUES(?)');
 for(const v of [-0,0,Infinity,-Infinity,NaN,Number.MIN_VALUE,-Number.MIN_VALUE,Number.MAX_VALUE,-Number.MAX_VALUE])ins.run(v);
 db.close();db=new DatabaseSync(path);try{
 const raw=db.prepare('SELECT typeof(v) AS t,v FROM t ORDER BY rowid').all();
 assert.ok(Object.is(raw[0].v,-0));assert.ok(Object.is(raw[1].v,0));assert.equal(raw[4].t,'null');
 const expect=[-0,0,Infinity,-Infinity,null,Number.MIN_VALUE,-Number.MIN_VALUE,Number.MAX_VALUE,-Number.MAX_VALUE].map(v=>[[v===null?'null':'real',v===null?null:realBits(v)]]);
 assert.deepEqual(read(db),fingerprint(['v'],expect));assert.deepEqual(read(db),JSON.parse(py([path],oracle)));
 // SQL CAST AS BLOB is text bytes, not REAL binary64.
 assert.notEqual(db.prepare('SELECT hex(CAST(1.0 AS BLOB)) AS v').get().v,realBits(1));
 }finally{db.close();}
}));
test('unqualified remote-style projection rejects a REAL row before hashing',()=>{
 const db=new DatabaseSync(':memory:');try{db.exec('CREATE TABLE t(v); INSERT INTO t VALUES(1.0)');const rows=db.prepare(`SELECT ${typedProjection(['v'])} FROM t`).all();assert.throws(()=>fingerprint(['v'],projectedRows(['v'],rows)));}finally{db.close();}
});
test('UTF-8 bytes including invalid sequences, long strings, empty text and BLOB with all bytes',()=>inFile(path=>{
 let db=new DatabaseSync(path);db.exec('CREATE TABLE t(v)');const values=['','610062','6100','C3A9','65CC81','F09F9880','FF','FE','C080','EDA080',hex(Buffer.from('Кириллица')), '61'.repeat(100000)];
 const binary=hex(Buffer.from(Array.from({length:256},(_,i)=>i)));
 for(const v of values)db.exec(`INSERT INTO t VALUES(CAST(X'${v}' AS TEXT))`);
 for(const v of ['',binary,'610062'])db.exec(`INSERT INTO t VALUES(X'${v}')`);
 db.exec('INSERT INTO t VALUES(NULL)');db.close();db=new DatabaseSync(path);try{
 assert.deepEqual(read(db),fingerprint(['v'],[...values.map(v=>[['text',v]]),...['',binary,'610062'].map(v=>[['blob',v]]),[['null',null]]]));
 assert.deepEqual(read(db),JSON.parse(py([path],oracle)));
 }finally{db.close();}
}));
test('independent generative binary64 and random BLOB oracle on persisted SQLite',()=>inFile(path=>{
 let db=new DatabaseSync(path);db.exec('CREATE TABLE t(v); BEGIN');const insert=db.prepare('INSERT INTO t VALUES(?)');
 const expected=[];const distinct=new Set();let pairs=0;let legacyRoundtripMismatch=0;
 const view=new DataView(new ArrayBuffer(8));
 for(let i=0;i<25000;i++){
  const base=shaBytes('eg-r42-ieee754-'+i).readBigUInt64BE();
  if(((base>>52n)&0x7FFn)===0x7FFn||(((base+1n)>>52n)&0x7FFn)===0x7FFn||base===0xFFFFFFFFFFFFFFFFn)continue;
  const pair=[];
  for(const bits of [base,base+1n]){
   view.setBigUint64(0,bits,false);const v=view.getFloat64(0,false);const h=bits.toString(16).toUpperCase().padStart(16,'0');
   assert.equal(realBits(v),h);insert.run(v);expected.push([['real',h]]);pair.push(h);distinct.add(h);
  }
  assert.notEqual(pair[0],pair[1]);pairs++;
 }
 assert.ok(pairs>24900);assert.equal(distinct.size,pairs*2);
 for(let i=0;i<512;i++){const b=Buffer.concat([shaBytes('eg-r42-blob-'+i),shaBytes('eg-r42-blob-tail-'+i)]).subarray(0,i%65);insert.run(b);expected.push([['blob',hex(b)]]);}
 for(const n of [-9223372036854775808n,9223372036854775807n,9007199254740992n,9007199254740993n]){insert.run(n);expected.push([['integer',n.toString()]]);}
 db.exec('COMMIT');db.close();db=new DatabaseSync(path);try{
 const fp=read(db);assert.deepEqual(fp,fingerprint(['v'],expected));assert.deepEqual(fp,JSON.parse(py([path],oracle)));
 const legacy=db.prepare("SELECT v,printf('%!.26g',v) AS txt FROM t WHERE typeof(v)='real'").all();
 for(const row of legacy)if(!Object.is(row.v,Number(row.txt)))legacyRoundtripMismatch++;
 console.log(`ORACLE: ${pairs} adjacent finite pairs; ${pairs*2} REAL values; 512 BLOB; 4 int64; legacy roundtrip mismatches=${legacyRoundtripMismatch}`);
 // SQLite's decimal formatter varies by version. The independent byte oracle
 // above qualifies the fingerprint; the legacy count is diagnostic only.
 }finally{db.close();}
}));
const dumpScript="import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); print('\\n'.join(c.iterdump()))";
test('actual local SQL dump/import source and restore match for ordinary representable fixture',()=>inFile((source,restore)=>{
 let a=new DatabaseSync(source);a.exec("CREATE TABLE t(v); CREATE INDEX idx ON t(v); INSERT INTO t VALUES(NULL),(X'00FF'),('é'),(9223372036854775807),(1.25),(1.25)");const pre=read(a);a.close();
 const sql=py([source],dumpScript);const b=new DatabaseSync(restore);try{b.exec(sql);assert.deepEqual(pre,read(b));assert.deepEqual(JSON.parse(py([source],oracle)),JSON.parse(py([restore],oracle)));assert.equal(b.prepare('PRAGMA integrity_check').get().integrity_check,'ok');assert.ok(b.prepare("SELECT name FROM sqlite_schema WHERE type='index' AND name='idx'").get());}finally{b.close();}
}));
test('actual local SQL dump/import detects NUL and signed-zero loss even with equal row counts',()=>inFile((source,restore)=>{
 let a=new DatabaseSync(source);a.exec("CREATE TABLE t(v); INSERT INTO t VALUES(CAST(X'610062' AS TEXT)),(-0.0),(1.25)");const pre=read(a);a.close();
 const sql=py([source],dumpScript);const b=new DatabaseSync(restore);try{b.exec(sql);const post=read(b);assert.equal(pre.rows,post.rows);assert.notEqual(pre.sha256,post.sha256);assert.equal(b.prepare('PRAGMA integrity_check').get().integrity_check,'ok');
 assert.equal(b.prepare('SELECT hex(v) AS h FROM t WHERE rowid=1').get().h,'61');assert.ok(Object.is(b.prepare('SELECT v FROM t WHERE rowid=2').get().v,0));
 }finally{b.close();}
}));
test('JSON transport collapses signed zero, infinities and NaN; raw numeric fields disallowed',()=>{
 assert.equal(JSON.stringify(-0),'0');assert.equal(JSON.stringify(Infinity),'null');assert.equal(JSON.stringify(NaN),'null');
 assert.equal(JSON.parse('9007199254740993'),9007199254740992);
 assert.throws(()=>fingerprint(['v'],[[['real',-0]]]));assert.throws(()=>fingerprint(['v'],[[['integer',9007199254740992]]]));
});

test('typed-value equality is not physical file equality',()=>inFile((source,restore)=>{
 const a=new DatabaseSync(source),b=new DatabaseSync(restore);try{
 a.exec("CREATE TABLE t(v); INSERT INTO t VALUES('a'),('b')");b.exec("CREATE TABLE t(v); INSERT INTO t VALUES('b'),('a')");
 assert.deepEqual(read(a),read(b));
 }finally{a.close();b.close();}
 const sums=py([source,restore],"import hashlib,sys; print(' '.join(hashlib.sha256(open(p,'rb').read()).hexdigest() for p in sys.argv[1:]))").trim().split(' ');assert.notEqual(sums[0],sums[1]);
}));
test('explicit synthetic SQL byte literals preserve edge values after export-like restore',()=>inFile((source,restore)=>{
 const a=new DatabaseSync(source),b=new DatabaseSync(restore);try{
 const sql="CREATE TABLE t(v); INSERT INTO t VALUES(CAST(X'610062' AS TEXT)),(CAST(X'FF' AS TEXT)),(X'00FF'),(X''),(''),(-0.0),(0.0),(1e999),(-1e999),(4.9406564584124654e-324),(9223372036854775807),(-9223372036854775808),(NULL)";
 a.exec(sql);b.exec(sql);assert.deepEqual(read(a),read(b));assert.deepEqual(read(a),JSON.parse(py([source],oracle)));assert.deepEqual(read(b),JSON.parse(py([restore],oracle)));
 }finally{a.close();b.close();}
}));
test('invalid UTF-8 can make a conventional SQL exporter fail; no partial backup accepted',()=>inFile(path=>{
 const db=new DatabaseSync(path);db.exec("CREATE TABLE t(v); INSERT INTO t VALUES(CAST(X'FF' AS TEXT))");db.close();
 const p=spawnSync('python3',['-c',dumpScript,path],{encoding:'utf8',timeout:30000});assert.notEqual(p.status,0);
}));
test('random REAL SQL dump chain checked independently for exactness',()=>inFile((source,restore)=>{
 const a=new DatabaseSync(source);a.exec('CREATE TABLE t(v)');const ins=a.prepare('INSERT INTO t VALUES(?)');let n=0;
 for(let i=0;i<1024;i++){const v=shaBytes('eg-r42-dump-'+i).readDoubleBE();if(Number.isFinite(v)){ins.run(v);n++;}}
 const pre=read(a);a.close();const sql=py([source],dumpScript);const b=new DatabaseSync(restore);try{b.exec(sql);const post=read(b);assert.equal(pre.rows,n);assert.equal(post.rows,n);
 const oracleSource=JSON.parse(py([source],oracle)),oracleRestore=JSON.parse(py([restore],oracle));assert.deepEqual(pre,oracleSource);assert.deepEqual(post,oracleRestore);
 const mismatches=Number(py([source,restore],`import sqlite3,struct,sys\na,b=[sqlite3.connect(p) for p in sys.argv[1:]]\nx,y=[[struct.pack('>d',v) for (v,) in c.execute('select v from t order by rowid')] for c in (a,b)]\nprint(sum(a!=b for a,b in zip(x,y)))`));
 assert.equal(pre.sha256===post.sha256,mismatches===0);console.log(`SQL DUMP: ${n} finite REAL values; exact roundtrip differences=${mismatches}`);
 }finally{b.close();}
}));

test('unqualified REAL mode still fingerprints non-REAL rows without numeric transport',()=>{
 const db=new DatabaseSync(':memory:');try{db.exec("CREATE TABLE t(v); INSERT INTO t VALUES(9223372036854775807),(CAST(X'610062' AS TEXT)),(X'FF'),(NULL)");
 const r=db.prepare(`SELECT ${typedProjection(['v'])} FROM t`).all();assert.deepEqual(fingerprint(['v'],projectedRows(['v'],r)),read(db));
 const exists=db.prepare('PRAGMA function_list').all().some(x=>x.name==='ieee754_to_blob');
 if(!exists)assert.throws(()=>db.prepare(`SELECT ${typedProjection(['v'],'ieee754')} FROM t`));
 }finally{db.close();}
});
