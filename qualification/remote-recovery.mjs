import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
export async function remoteRecovery(host,tick){
 const matrix={},ids={},request=async(scenario,phase,early=false)=>{
  const params=new URLSearchParams({diagnostic:"recovery",case:scenario,phase,id:ids[scenario],...(early?{early:"1"}:{})});
  const r=await fetch(host+"/qualification/tick?"+params,{method:"POST",headers:{Authorization:"Bearer "+tick},redirect:"error",signal:AbortSignal.timeout(30000)});
  const body=await r.json().catch(()=>({status:"INVALID_RESPONSE"}));
  (matrix[scenario]??={calls:[]}).calls.push({http:r.status,...body});assert.ok(r.ok&&body.status==="OBSERVED",scenario+":"+phase);return body;
 };
 for(const scenario of ["lease","concurrent","429","503","timeout","backoff","exhaust","dependency","cancel_running","cancel_queued","tamper","memory"]){
  ids[scenario]=randomUUID();const m=matrix[scenario]={calls:[]};
  try{
   const start=await request(scenario,"setup");let final;
   if(scenario==="memory"){final=await request(scenario,"observe");assert.ok(final.memory_hash);}
   else if(scenario==="cancel_queued"){final=await request(scenario,"advance");assert.equal(final.executed,0);assert.equal(final.workflow_state,"CANCELLED");assert.equal(final.steps[0].attempts,0);}
   else if(scenario==="concurrent"){
    await request(scenario,"duplicate");
    const both=await Promise.all([request(scenario,"advance"),request(scenario,"advance")]);assert.equal(both.reduce((n,x)=>n+x.executed,0),1);final=await request(scenario,"observe");assert.equal(final.steps[0].attempts,1);assert.equal(final.workflow_state,"SUCCEEDED");
   }else{
    const first=await request(scenario,"advance");final=first;
    if(["429","503","timeout","backoff","exhaust"].includes(scenario)){
     assert.equal(first.steps[0].state,"RETRYING");assert.equal(first.steps[0].attempts,1);assert.equal(first.steps[0].error_code,scenario==="429"?"github_rate_limited":scenario==="timeout"?"github_timeout":"github_http_503");
     const wait=first.steps[0].available_at-first.scheduler_clock;assert.ok(wait>=(["429","503"].includes(scenario)?3000:1000));await request(scenario,"advance",true);
     final=await request(scenario,"advance");
     if(scenario==="backoff"){assert.equal(final.steps[0].state,"RETRYING");assert.ok(final.steps[0].available_at-final.scheduler_clock>=2000);await request(scenario,"advance",true);final=await request(scenario,"advance");assert.equal(final.steps[0].attempts,3);}
     assert.equal(final.workflow_state,scenario==="exhaust"?"FAILED":"SUCCEEDED");assert.equal(final.steps[0].attempts,scenario==="backoff"?3:2);
    }else if(scenario==="dependency"){assert.equal(first.workflow_state,"FAILED");assert.equal(first.steps.find(s=>s.key==="dependent").attempts,0);assert.equal((await request(scenario,"advance")).executed,0);}
    else if(scenario==="cancel_running"){assert.equal(first.workflow_state,"CANCELLED");assert.equal(first.steps[0].state,"CANCELLED");}
    else if(scenario==="tamper"){assert.equal(first.workflow_state,"SUCCEEDED");final=await request(scenario,"tamper");}
    else if(scenario==="lease"){assert.equal(first.workflow_state,"SUCCEEDED");assert.equal(first.steps[0].attempts,2);}
   }
   assert.ok(final.steps.every(s=>s.lease_released));m.status="PASS";
  }catch(e){m.status="FAIL";m.failure=e?.name==="AssertionError"?"assertion_failed":"transport_or_execution";}
 }
 return {mode:"real_preview_D1_controlled_faults",matrix,passed:Object.values(matrix).filter(m=>m.status==="PASS").length,total:Object.keys(matrix).length};
}
