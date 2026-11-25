// Optional least-privilege credential for the single approved public repository.
// Never persist, return, or forward the credential to another host/repository.
// Public reads for other repositories remain unauthenticated.
export function githubReadFetcher(env,base=fetch){
  return async (target,options={})=>{
    const url=new URL(target),method=options.method??"GET";
    const allowed=url.origin==="https://api.github.com"&&!url.username&&!url.password&&method==="GET"&&/^\/repos\/19wolfalone92\/Execution-Guard(?:$|\/)/i.test(url.pathname);
    const headers=new Headers(options.headers);headers.delete("Authorization");
    if(allowed&&typeof env?.EG_GITHUB_READ_TOKEN==="string"&&env.EG_GITHUB_READ_TOKEN.length>0)headers.set("Authorization","Bearer "+env.EG_GITHUB_READ_TOKEN);
    return base(url.href,{...options,headers,redirect:"manual"});
  };
}
