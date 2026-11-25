# Execution Guard 0.3.1

Read-only MCP and D1 probe baseline. No credentials, job execution or database write tools are included. The database UUID in Wrangler is a resource identifier, not an access token. Keep credentials in Cloudflare Secrets, never in Git.

Cloudflare Workers Builds for existing Worker:
- Production branch: main
- Build command: npm test
- Deploy command: npx wrangler deploy
- Preview builds: disabled
- Enable builds only after checking configuration and code.

The existing production probe is not modified by deployment. probe.sql is for initialization only. Tests use temporary SQLite with a D1-shaped adapter, not production D1. After deployment verify version 0.3.1, database online and persistence_probe verified via MCP.

## Post-connection qualification

A push to main after enabling Workers Builds triggers deployment. Inspect Deployments > View Build History for the matching commit and verify both npm test and Wrangler deployment succeeded. The live MCP response must report version 0.3.1 with database online and persistence_probe verified. If a build fails, inspect its logs before retrying. Do not reinitialize production D1 or expose credentials.

## 0.4.0 — staged OAuth and checkpoints

The public /mcp remains read-only. The separate /mcp-private route is fail-closed until all configuration is present. The Cloudflare OAuth provider is pinned; use CIMD with the approved ChatGPT client. GitHub identity only (read:user), no repository token stored. Owner must create a GitHub OAuth App with homepage https://execution-guard.19wolf-alone92.workers.dev and callback /callback on that host, create KV namespace, and add its ID to Wrangler under kv_namespaces with binding OAUTH_KV. Set GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET and EG_OWNER_GITHUB_ID in Worker Secrets; enable EG_AUTH_ENABLED=true only after config and tests. Do not put credentials in Git. Then create a second MCP plugin for /mcp-private with OAuth, CIMD and scopes eg:read and eg:write. Private tools do not run commands or access other repositories. Test unauthenticated rejection, owner sign-in, read/write scope enforcement, checkpoint read-back, and stale revision rejection. Disable EG_AUTH_ENABLED for emergency access revocation. Existing public health is independent.

## 0.5.0 — durable diagnostic task queue

Cron runs every five minutes, no work when private authorization is disabled. The authenticated owner may submit health_probe or sha256_verify only; no shell, repository, GPU or device operations are accepted. Owner/project isolation, idempotency, a queue cap, atomic claim with leases, stale lease recovery, bounded retries and persisted evidence are included. Terminal records are retained; storage cap is 5000 tasks. Verify in live D1 only after private OAuth activation: submit a health_probe and check task_status after a scheduled invocation; submit sha256_verify with text abc and expected ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad. A mismatch must fail. The worker does not call AI models or automatically repair arbitrary code.
