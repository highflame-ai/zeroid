/**
 * Local ZeroID literal types used by the CLI.
 *
 * The published @highflame/sdk package includes these unions internally, but
 * does not currently export them from its public surface. The CLI uses local
 * aliases so `tsc --noEmit` stays green while still constraining command input
 * to the known API values.
 */

export type IdentityType = "agent" | "application" | "mcp_server" | "service";

export type SubType =
  | "orchestrator"
  | "autonomous"
  | "tool_agent"
  | "human_proxy"
  | "evaluator"
  | "chatbot"
  | "assistant"
  | "api_service"
  | "custom"
  | "code_agent";

export type SignalType =
  | "credential_change"
  | "session_revoked"
  | "ip_change"
  | "anomalous_behavior"
  | "policy_violation"
  | "retirement"
  | "owner_change";

export type SignalSeverity = "low" | "medium" | "high" | "critical";
