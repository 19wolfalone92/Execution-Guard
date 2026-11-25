# Execution-Guard
Autonomous Execution Engine

## Deployment verification

The Cloudflare Worker is deployed from the `main` branch with `npx wrangler deploy`.
After a Git integration reconnect, verify that a new commit triggers a successful production build and deployment. A successful build alone does not prove the protected MCP OAuth flow works; verify server health, OAuth discovery, and an authenticated MCP request separately.
