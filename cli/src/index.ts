#!/usr/bin/env node
/**
 * zeroid — ZeroID CLI
 *
 * Entry point. Registers all commands and parses argv.
 */

import { Command } from "commander";
import { registerInit } from "./commands/init.js";
import { registerDecode } from "./commands/token/decode.js";
import { registerVerify } from "./commands/token/verify.js";
import { registerIssue } from "./commands/token/issue.js";
import { registerTokenRevoke } from "./commands/token/revoke.js";
import { registerList } from "./commands/agents/list.js";
import { registerGet } from "./commands/agents/get.js";
import { registerRotateKey } from "./commands/agents/rotate-key.js";
import { registerDeactivate } from "./commands/agents/deactivate.js";
import { registerCredsList } from "./commands/creds/list.js";
import { registerSignal } from "./commands/signal.js";
import { registerConfig } from "./commands/config.js";

const program = new Command();

program
  .name("zeroid")
  .description("ZeroID CLI — agent identity for AI systems")
  .version("0.1.0");

registerInit(program);
registerSignal(program);
registerConfig(program);

const tokenCmd = program.command("token").description("Token operations");
registerIssue(tokenCmd);
registerDecode(tokenCmd);
registerVerify(tokenCmd);
registerTokenRevoke(tokenCmd);

const agentsCmd = program.command("agents").description("Agent registry operations");
registerList(agentsCmd);
registerGet(agentsCmd);
registerRotateKey(agentsCmd);
registerDeactivate(agentsCmd);

const credsCmd = program.command("creds").description("Credential operations");
registerCredsList(credsCmd);

program.parseAsync(process.argv).catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
