/**
 * zeroid ciba listen — local HTTPS capture endpoint for ping/push callbacks.
 */

import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import { createServer } from "node:https";
import { homedir } from "node:os";
import { join } from "node:path";
import { Command } from "commander";
import { handleError, printSuccess } from "../../lib/output.js";

interface ListenEvent {
  event: "listening" | "notification";
  url?: string;
  method?: string;
  path?: string;
  authorization?: string;
  headers?: Record<string, string | string[] | undefined>;
  body?: unknown;
  raw_body?: string;
  received_at?: string;
}

export function registerCibaListen(cibaCmd: Command): void {
  cibaCmd
    .command("listen")
    .description("Run a local HTTPS callback capture endpoint for CIBA ping/push")
    .option("--port <port>", "HTTPS port to listen on", "8888")
    .option("--host <host>", "Host to bind", "localhost")
    .option("--json", "Output newline-delimited JSON events")
    .addHelpText(
      "after",
      "\nCIBA Core references: §9 Client Notification Endpoint, §10.2 Ping Callback, §10.3 Push Callback.",
    )
    .action(async (opts) => {
      try {
        const port = parsePort(opts.port as string);
        const host = opts.host as string;
        const cert = ensureSelfSignedCert();
        const server = createServer(cert, (req, res) => {
          void handleNotification(req, res, Boolean(opts.json));
        });

        await new Promise<void>((resolve) => {
          server.listen(port, host, resolve);
        });

        const url = `https://${host}:${port}/cb`;
        printEvent({ event: "listening", url }, Boolean(opts.json));

        process.on("SIGINT", () => {
          server.close(() => process.exit(0));
        });
        process.on("SIGTERM", () => {
          server.close(() => process.exit(0));
        });
      } catch (err) {
        handleError(err);
      }
    });
}

async function handleNotification(
  req: IncomingMessage,
  res: ServerResponse,
  json: boolean,
): Promise<void> {
  const rawBody = await readRequestBody(req);
  let parsedBody: unknown;
  try {
    parsedBody = rawBody ? JSON.parse(rawBody) : undefined;
  } catch {
    parsedBody = undefined;
  }

  printEvent(
    {
      event: "notification",
      method: req.method,
      path: req.url,
      authorization: req.headers.authorization,
      headers: req.headers,
      body: parsedBody,
      raw_body: parsedBody === undefined ? rawBody : undefined,
      received_at: new Date().toISOString(),
    },
    json,
  );

  res.writeHead(200, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ ok: true }) + "\n");
}

function printEvent(event: ListenEvent, json: boolean): void {
  if (json) {
    console.log(JSON.stringify(event));
    return;
  }

  if (event.event === "listening") {
    printSuccess(`CIBA callback listener ready at ${event.url}`);
    console.log("  Use this as your client_notification_endpoint for local ping/push tests.");
    return;
  }

  console.log(`\n${event.received_at} ${event.method ?? ""} ${event.path ?? ""}`.trim());
  if (event.authorization) {
    console.log(`  authorization: ${event.authorization}`);
  }
  if (event.body !== undefined) {
    console.log(JSON.stringify(event.body, null, 2));
  } else if (event.raw_body) {
    console.log(event.raw_body);
  } else {
    console.log("{}");
  }
}

function ensureSelfSignedCert(): { key: Buffer; cert: Buffer } {
  const dir = join(homedir(), ".zid", "ciba-cert");
  const keyPath = join(dir, "localhost-key.pem");
  const certPath = join(dir, "localhost-cert.pem");

  if (!existsSync(keyPath) || !existsSync(certPath)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const result = spawnSync(
      "openssl",
      [
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-sha256",
        "-days",
        "365",
        "-subj",
        "/CN=localhost",
        "-addext",
        "subjectAltName=DNS:localhost,IP:127.0.0.1",
        "-keyout",
        keyPath,
        "-out",
        certPath,
      ],
      { encoding: "utf8" },
    );

    if (result.status !== 0) {
      throw new Error(
        "Failed to generate a self-signed certificate with openssl. Install openssl or create ~/.zid/ciba-cert/localhost-key.pem and localhost-cert.pem manually.",
      );
    }
  }

  return {
    key: readFileSync(keyPath),
    cert: readFileSync(certPath),
  };
}

function readRequestBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function parsePort(value: string): number {
  const port = Number.parseInt(value, 10);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("--port must be an integer between 1 and 65535");
  }
  return port;
}
