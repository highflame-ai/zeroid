# What works
1. Working nginx forward auth with XAI provider, copy config into /etc/nginx/conf.d/
2. sidecar edits openclaw config to replace provider bearer tokens with ZeroID short-lived tokens (.openclaw/agents/<agent-name>/agent/auth-profiles.json)
3. sidecar edits config to add provider bearer token as a X-REAL-APIKEY header
4. sidecar maps the token scope to an allowed tools profile which goes into openclaw config. The config is checked before each tool call, so this is effectively realtime.
5. When nginx checks the forward-auth verify endpoint, if it passes, we swap the real api key as bearer token and forward to provider
5. demo-revoke.py works to revoke tokens in realtime, this severs connection between openclaw agents and their LLM provider effectively killing the agent

# What needs more work
1. Sub agent tokens are always failing to verify, the token is in the auth-profile. Possibly related to delegation depth. Further troubleshooting is needed.
2. Unable to verify the cascading revocation because sub-agents are always failing regardless
3. Works for my specific XAI implementation, need to make it more general
4. Ideally replace the demo-revoke.py script with CLI
