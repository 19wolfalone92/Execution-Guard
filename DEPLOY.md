# Execution Guard 0.3.1

Read-only MCP and D1 probe baseline. No credentials, job execution or database write tools are included. The database UUID in Wrangler is a resource identifier, not an access token. Keep credentials in Cloudflare Secrets, never in Git.

Cloudflare Workers Builds for existing Worker:
- Production branch: main
- Build command: npm test
- Deploy command: npx wrangler deploy
- Preview builds: disabled
- Enable builds only after checking configuration and code.

The existing production probe is not modified by deployment. probe.sql is for initialization only. Tests use temporary SQLite with a D1-shaped adapter, not production D1. After deployment verify version 0.3.1, database online and persistence_probe verified via MCP.
