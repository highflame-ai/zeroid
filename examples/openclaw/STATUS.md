# What works
1. Working nginx forward auth with XAI provider, copy config into /etc/nginx/conf.d/
2. sidecar edits openclaw config to replace provider bearer tokens with ZeroID short-lived tokens (.openclaw/agents/<agent-name>/agent/auth-profiles.json)
3. sidecar edits config to add provider bearer token as a X-REAL-APIKEY header
4. sidecar maps the token scope to an allowed tools profile which goes into openclaw config. The config is checked before each tool call, so this is effectively realtime.
5. When nginx checks the forward-auth verify endpoint, if it passes, we swap the real api key as bearer token and forward to provider
6. demo-revoke.py works to revoke tokens in realtime, this severs connection between openclaw agents and their LLM provider effectively killing the agent
7. sub-agents tokens are delegated from main agent, and cascading revocation is verified, previous check was due to chat in stale openclaw subagent session.
8. Nginx config can handle multiple providers

# What needs more work
1. Ideally replace the demo-revoke.py script with CLI
2. We ideally return a valid message so show why the message is blocked 
3. Add more fine-grain tool mapping to show scope delegation. Potentially work with the clawhub skill to have the orchestrator delegate scopes as needed.
4. The first message is usually blocked with 401, I see it in ZeroID so likely it is Openclaw using cached tokens and not updating until it fails.
