/**
 * zeroid ciba — OpenID CIBA helper commands.
 */

import { Command } from "commander";
import { registerCibaApprove } from "./approve.js";
import { registerCibaDeny } from "./deny.js";
import { registerCibaInit } from "./init.js";
import { registerCibaListen } from "./listen.js";
import { registerCibaPoll } from "./poll.js";

export function registerCiba(program: Command): void {
  const cibaCmd = program
    .command("ciba")
    .description("OpenID CIBA backchannel authentication helpers");

  registerCibaInit(cibaCmd);
  registerCibaApprove(cibaCmd);
  registerCibaDeny(cibaCmd);
  registerCibaPoll(cibaCmd);
  registerCibaListen(cibaCmd);
}
