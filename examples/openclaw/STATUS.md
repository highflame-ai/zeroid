# What works
1. Working nginx forward auth with XAI provider
2. sidecar edits openclaw config to replace provider bearer tokens with ZeroID short-lived tokens (.openclaw/agents/<agent-name>/agent/auth-profiles.json)
3. sidecar maps the token scope to an allowed tools profile which goes into openclaw config. The config is checked before each tool call, so this is effectively realtime.
4. When nginx checks the forward-auth verify endpoint, if it passes, we swap the real api key as bearer token and forward to provider
5. demo-revoke.py works to revoke tokens in realtime, this severs connection between openclaw agents and their LLM provider effectively killing the agent
6. sub-agents tokens are delegated from main agent, and cascading revocation is verified
7. Nginx config can handle multiple providers

# What needs more work
1. Replace the demo-revoke.py script with CLI
2. Add more fine-grain tool mapping to show scope delegation. Potentially work with the clawhub skill to have the orchestrator delegate scopes as needed.
3. The first message is sometimes blocked with 401, I see it in ZeroID so likely it is Openclaw using cached tokens and not updating until it fails.
