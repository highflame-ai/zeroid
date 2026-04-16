## Summary

Add MCP-aware scope vocabulary and JWT claims so that Firehog (the MCP gateway) can make tool-level access decisions from a ZeroID-issued token without calling back to ZeroID.

Replaces #65, which proposed a full MCP server registry in ZeroID. That responsibility belongs in Firehog — ZeroID only needs to speak the right scope language and embed the right claims.

## Scope vocabulary

New scope format:

- `mcp:<server_slug>` — access to all tools on an MCP server
- `mcp:<server_slug>:<tool_name>` — access to a specific tool

Examples: `mcp:github`, `mcp:github:create_issue`, `mcp:slack:post_message`

These participate in the existing 3-way scope intersection on token_exchange — a sub-agent can only get MCP scopes that the orchestrator has and the sub-agent is allowed.

## JWT claims

When MCP scopes are present, embed a structured `mcp_servers` claim for easy gateway consumption:

```json
{
  "scopes": ["mcp:github:create_issue", "mcp:github:list_repos", "mcp:slack"],
  "mcp_servers": [
    {"slug": "github", "tools": ["create_issue", "list_repos"]},
    {"slug": "slack", "tools": ["*"]}
  ]
}
```

Firehog reads this claim to enforce tool-level access without introspection.

## Implementation

- Add an `OnClaimsIssue` enricher (or built-in logic) that parses `mcp:*` scopes and builds the `mcp_servers` claim
- No new tables, no MCP server registry, no credential storage — that lives in Firehog
- Document the scope format so Firehog and SDK consumers can rely on it

## Integration points

- Credential policies can restrict `mcp:*` scopes via `allowed_scopes`
- CAE cascade revocation applies to tokens carrying MCP scopes (no changes needed)
- Firehog validates the `mcp_servers` claim at the gateway layer
