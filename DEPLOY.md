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

## Release recovery preflight (no production change)
- The Cloudflare check for `dc6fe17ff0aad2ce50539109a0359b5e7f0c1f78` reports failure, Build ID `51ad3d36-fdb3-4709-ad4e-945951c627bf`. GitHub Actions pass independently. The check has no log text or annotations. Obtain the actual log in the account dashboard or via the authenticated Workers Builds logs API (Workers CI Read); do not guess at root cause.
- Confirm Preview is isolated from production D1/KV, OAuth secrets, and Cron. Do not run an authenticated Preview against production state. The current hard-coded OAuth issuer/host makes a separate Preview OAuth configuration necessary before full Preview qualification.
- Before authorized production release: capture deployed Worker version ID, D1 Time Travel bookmark and a private D1 export; verify export by importing into isolated test D1 and comparing legacy rows. Preserve KV namespace and existing secret bindings; do not export OAuth secrets into CI/logs.
- Deploy only the reviewed SHA after explicit owner approval. Verify old checkpoint and task, candidate health, OAuth owner, refresh and new tools. Run a bounded DAG and compare independent result evidence.
- Rollback: select the recorded previous Worker version. A code rollback does not restore storage. The new tables are additive, so prefer code rollback, retaining data. Do not use D1 Time Travel restore except after separate approval, since it rewinds user data. Keep D1/KV identifiers unchanged.
- CI includes an isolated workerd 0.5.0 → candidate → 0.5.0 → candidate restart rehearsal using persisted local D1/KV, not a remote backup, deployment or production OAuth test.

## Preview build recovery — 2026-11-25
The owner supplied the complete build log for a246b632-0afd-4ff9-81d9-b8c1b7e0d42f (c6fdc7a). Node 22.23.5/npm 10.9.2 installed 86 packages, zero audit findings. Wrangler 4.168.0 failed at `npx wrangler preview` because the required `previews` block was absent. Official configuration: https://developers.cloudflare.com/workers/previews/configuration/ .
The suggested D1 binding in the error points at production: **do not copy it**. The initial Preview deliberately has no D1 or KV bindings and disables OAuth. Cloudflare Previews do not inherit production bindings. Public health/MCP are available for code smoke tests; database and persistence must report not_verified and private endpoints must fail closed. A passing build is not a passing full integration test.
Before full integration, provision a separate D1 database and KV namespace in the account, seed only the test probe, and configure their real IDs under previews. Never use the production IDs or secrets. The OAuth issuer is pinned to the production host; separate preview OAuth configuration and callback are needed before enabling private Preview access. No production deployment or resource provisioning is performed by this change.

## Isolated Preview qualification follow-up
Cloudflare confirmed build d82e89d8-f1a3-4185-9e87-28ad4850ef07 and deployment b9159ddf-d6f9-48c0-8e7b-90046df4528b for 4564b8b. CI probes the immutable URL, not an assumed URL. Stable Preview host: https://audit-oauth-e2e-20261125-execution-guard.19wolf-alone92.workers.dev .
The candidate supports a fixed, separate Preview OAuth issuer and resource, not request-derived hostnames. Provision test D1 `execution-guard-preview-db` and KV `execution-guard-preview-oauth`, seed only probe.sql, and bind exclusively in previews. Enable EG_PREVIEW_READY and EG_AUTH_ENABLED only after verifying distinct bindings and a separate GitHub OAuth app (callback at stable Preview host /callback). Use separate GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, EG_OWNER_GITHUB_ID and EG_PREVIEW_TICK_SECRET (32+ random chars) in Preview settings only; no secrets in Git.
Cloudflare Preview Cron is unsupported (https://developers.cloudflare.com/workers/previews/resources/). The candidate adds a POST /qualification/tick endpoint that only works on the exact stable Preview host with explicit preview configuration and separate secret. It provisions the registered client and executes one bounded scheduler batch. It is unavailable on production, and no arbitrary commands are accepted. This tests the same runner without pretending Preview Cron works. Production Cron still requires real production verification. Keep secrets local; do not transmit them through chat.
