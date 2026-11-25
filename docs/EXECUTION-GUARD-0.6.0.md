# Execution Guard Pro 0.6.0 — qualification candidate

**Release state: HOLD.** This branch is a qualification candidate, not a production deployment. The default branch remains the previously deployed 0.5.0 baseline until a separately reviewed merge and Cloudflare deployment.

## Implemented in this candidate

### Structured project memory

- Project records are isolated by authenticated GitHub owner and project slug.
- Updates use an expected revision (compare-and-swap); stale writers receive `revision_conflict`.
- Every accepted revision is written to `eg_project_history`; the latest 100 revisions per project are retained.
- Records support goal, rules, repository identity, branch/commit/PR, stage, completed/pending work, errors, tests, limitations, next action and evidence.
- Secret-like fields and common credential patterns are rejected. This is a guardrail, not a secret-scanning guarantee; never place credentials in project memory.
- The legacy `eg_checkpoints` tools and data remain available and are not overwritten by the new store.

### Durable DAG workflows

- `workflow_create` requires an owner-supplied idempotency key; reusing it with the same definition returns the existing workflow, while a different definition is rejected. It accepts 1–32 bounded steps and validates unique keys, references and cycles before persistence.
- Steps declare dependencies, a supported operation, maximum attempts (1–5) and timeout (1–30 seconds).
- A step becomes runnable only after all dependencies are verified as `SUCCEEDED`.
- The state model includes CREATED, QUEUED, BLOCKED, RUNNING, RETRYING, VERIFYING, SUCCEEDED, FAILED, CANCELLED, PAUSED and NEEDS_APPROVAL.
- D1-backed atomic claims use leases. Expired leases are recovered; retryable failures use bounded exponential delay, jitter and GitHub Retry-After when available.
- Concurrency is capped at 4 running steps per owner and 16 across the database. Each scheduled invocation claims at most 4 steps.
- Per owner, workflow creation is capped at 100 non-terminal and 5,000 total workflows.
- An exhausted retry budget moves the workflow to NEEDS_APPROVAL. A second explicit owner retry call authorizes a new bounded attempt window.

### Supported operations only

1. `health_probe` — read the existing D1 persistence probe.
2. `sha256_verify` — hash a bounded text value and compare it with an expected SHA-256.
3. `github_repository_status` — read public GitHub repository metadata.
4. `github_commit_status` — read public combined commit status.
5. `github_workflow_status` — read public GitHub Actions run status.

GitHub calls use a fixed `https://api.github.com` origin, GET only, bounded timeouts and redirect rejection. Private repositories, GitHub App credentials, workflow dispatch, reruns, commits, branch writes and PR writes are not enabled in this stage. No user GitHub token is copied to the Worker.

### Verification and audit

- A step is not successful unless its operation returns `verified: true`.
- The engine stores the result and a SHA-256 digest in step evidence.
- `execution_finalize` independently recomputes each result digest and checks the workflow terminal state.
- Project/workflow events are written to `eg_execution_audit`; the latest 10,000 events per owner are retained.
- A workflow becomes SUCCEEDED only when all steps are SUCCEEDED and every step has verified evidence.

## Runtime and resource boundaries

The existing Worker continues to use D1, KV and the five-minute Cron Trigger. New tables are created lazily and do not reinitialize or delete existing D1 data.

This candidate does **not** provision Cloudflare Queues, Durable Objects or Cloudflare Workflows. The D1/Cron executor is suitable only for short, bounded operations. It is not a general long-running process host and it does not run a ChatGPT model between messages. There is no arbitrary shell, code execution, arbitrary URL fetch or generic HTTP action.

Kaggle and Execution Bridge adapters are not implemented. They remain separate, permission-gated future integrations and do not modify those projects.

## Security model

- All private MCP operations require the existing owner verification and eg:read / eg:write scopes.
- Project and workflow queries are owner-scoped; workflow IDs are additionally scoped to project.
- Mutating tools require eg:write. Cancel is marked destructive; read tools are marked read-only.
- Legacy checkpoints and new project records reject common credential patterns; secrets must remain in Cloudflare Secrets/KV OAuth storage, never in ordinary project records.
- Public GitHub responses and external logs are untrusted data. They are stored as data and never interpreted as instructions or executable content.

## Qualification evidence and remaining gates

The OAuth/MCP runtime workflow uses the pinned Cloudflare OAuth provider in workerd with simulated upstream GitHub responses. The production smoke check verifies health, D1 persistence, OAuth discovery, registered client metadata and unauthenticated rejection of the private MCP endpoint. A real production owner sign-in and token refresh are not performed by that smoke test.

The production health probe submitted through the protected MCP has succeeded with `verified: true`, one attempt, and the existing D1 persistence probe. The previous `oauth-qualification` checkpoint at revision 2 and its original task evidence remain intact.

The candidate remains HOLD until all of the following are independently confirmed:

- All GitHub Actions checks pass on the final PR head.
- The generated lockfile is committed and `npm ci` is used.
- `npm audit` reports no high/critical findings, with the production dependency graph separately reviewed.
- A real authenticated owner OAuth sign-in and token refresh succeed against production.
- The candidate is deployed through the configured Cloudflare deployment path and the live server reports 0.6.0.
- A real multi-step workflow is submitted through protected MCP, executed by Cron, resumed after a lease/worker interruption, and finalized with verifiable evidence.

No merge or production deployment is authorized by this document.
