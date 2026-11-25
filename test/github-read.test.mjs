import test from "node:test";import assert from "node:assert/strict";import {githubReadFetcher} from "../github-read.mjs";
test("GitHub credential is restricted to exact repository read, redirects manual",async()=>{
 const seen=[];const f=githubReadFetcher({EG_GITHUB_READ_TOKEN:"test-only"},async(u,o)=>{seen.push({u,auth:o.headers.get("Authorization"),redirect:o.redirect});return new Response("{}")});
 await f("https://api.github.com/repos/19wolfalone92/Execution-Guard");await f("https://api.github.com/repos/19wolfalone92/Execution-Guard/actions/runs");
 for(const u of ["https://api.github.com/repos/19wolfalone92/Williams","https://api.github.com/repos/19wolfalone92/Execution-Guard-Other","https://example.invalid/repos/19wolfalone92/Execution-Guard","https://api.github.com/repos/19wolfalone92/Execution-Guard/../Williams"])await f(u,{headers:{Authorization:"Bearer supplied"}});
 await f("https://api.github.com/repos/19wolfalone92/Execution-Guard",{method:"POST"});
 assert.deepEqual(seen.map(x=>x.auth),["Bearer test-only","Bearer test-only",null,null,null,null,null]);assert.ok(seen.every(x=>x.redirect==="manual"));
});