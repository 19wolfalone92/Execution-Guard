# Execution Guard Pro

**Current production baseline:** 0.5.0  
**Qualification candidate:** 0.6.0 — draft PR #5, not deployed.

Execution Guard is a protected MCP service built on Cloudflare Workers, OAuth, D1, KV and Cron. It provides owner-scoped diagnostic tasks and, in the 0.6.0 candidate, structured project memory, bounded DAG workflows, lease recovery, public GitHub read monitoring and evidence verification.

## Current capabilities

- OAuth authorization with PKCE and owner verification.
- Separate protected MCP endpoint with eg:read and eg:write scopes.
- Durable D1 diagnostic queue with idempotency, leases, bounded retries and evidence.
- Revisioned project memory with optimistic concurrency and history.
- Multi-step DAG workflows with explicit dependencies and state transitions.
- Bounded health, SHA-256 and public GitHub read operations.
- Result integrity evidence and audit history.

## Qualification and release status

The 0.6.0 code is being qualified on a separate branch. The PR is intentionally draft and is not merged. The production server is not updated by branch CI or Wrangler dry-run.

See [Execution Guard 0.6.0 architecture, safety boundaries and release gates](docs/EXECUTION-GUARD-0.6.0.md) and [deployment procedure](DEPLOY.md).

Never store OAuth tokens, passwords, private keys or other credentials in project memory, checkpoints, workflow inputs or audit records.
