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
3. Openclaw not passing in env variables cleanly in headers only the env variable name. Currently only working when provider bearer token hard coded in nginx config.
4. Ideally replace the demo-revoke.py script with CLI
