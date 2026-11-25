# Execution Guard Pro — deployment and qualification

## Production baseline

The existing Cloudflare Worker is configured in `wrangler.jsonc` with:
- D1 binding `DB` and the existing production database.
- KV binding `OAUTH_KV`.
- `nodejs_compat` and `global_fetch_strictly_public`.
- A five-minute Cron Trigger.
- Cloudflare Worker Builds configured to deploy from `main`.

The production baseline remains 0.5.0 until a reviewed merge and deployment. Do not run `wrangler d1 migrations apply`, reset D1, replace the database ID, or recreate the OAuth KV namespace as part of this release.

## 0.6.0 candidate

The candidate is developed on `audit/oauth-e2e-20261125` and PR #5. CI uses Wrangler dry-run only; it does not deploy. Do not merge while PR checks are red, the dependency lockfile is missing, the npm audit gate reports high/critical findings, or live OAuth qualification is incomplete.

## Required release sequence

1. Review the final PR diff and all review threads.
2. Confirm the committed lockfile matches the pinned package manifest; use `npm ci` in CI.
3. Require all unit, integration, security, OAuth/workerd and Wrangler dry-run checks to pass.
4. Perform a real owner OAuth sign-in and refresh against the production host. CI simulations are not a substitute.
5. Merge only after explicit release approval.
6. Confirm Cloudflare Worker Builds deployed the exact main commit. If the deployment is not automatically triggered, use the authorized Cloudflare dashboard path; do not invent or substitute a deployment credential.
7. Verify public health reports version 0.6.0, database online and persistence probe verified.
8. Verify OAuth authorization-server metadata and registered client details.
9. Verify the private MCP endpoint rejects unauthenticated callers and accepts only the authenticated owner with the correct scope.
10. Submit a small multi-step workflow through protected MCP. Wait for the Cron Trigger, read each step, verify evidence and call `execution_finalize`.
11. Confirm the pre-existing legacy checkpoint and diagnostic task records remain readable.

## Recovery

If any post-deploy check fails, stop release qualification. Use the configured Cloudflare deployment history to roll back to the last verified Worker version. Do not reinitialize D1, rotate OAuth secrets without a reason, or disable owner verification as a workaround.

## Runtime boundaries

The 0.6.0 candidate uses D1 and the existing Cron Trigger for short bounded steps. It does not provision Cloudflare Queues, Durable Objects or Cloudflare Workflows, and it does not support arbitrary code/shell execution or long-running AI jobs. GitHub access is public read-only in this stage; private repositories and GitHub writes require a separately approved GitHub App integration.
