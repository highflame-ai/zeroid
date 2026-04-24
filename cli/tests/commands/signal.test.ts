/**
 * Tests for `zeroid signal`.
 */

import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { runCLI, BASE_URL } from "../helpers.js";
import type { CAESignal, CreateSignalRequest } from "@highflame/sdk";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const SIGNAL_RESPONSE: CAESignal = {
  id: "sig_abc123",
  account_id: "acct_test",
  project_id: "proj_test",
  identity_id: "agt_abc123",
  signal_type: "anomalous_behavior",
  severity: "high",
  source: "security-monitor",
  created_at: new Date().toISOString(),
};

describe("zeroid signal", () => {
  it("POST /api/v1/signals/ingest with all required fields", async () => {
    let captured: CreateSignalRequest = {} as CreateSignalRequest;
    server.use(
      http.post(`${BASE_URL}/api/v1/signals/ingest`, async ({ request }) => {
        captured = (await request.json()) as CreateSignalRequest;
        return HttpResponse.json(SIGNAL_RESPONSE);
      }),
    );

    await runCLI([
      "signal",
      "--agent", "agt_abc123",
      "--type", "anomalous_behavior",
      "--severity", "high",
      "--source", "security-monitor",
    ]);

    expect(captured.identity_id).toBe("agt_abc123");
    expect(captured.signal_type).toBe("anomalous_behavior");
    expect(captured.severity).toBe("high");
    expect(captured.source).toBe("security-monitor");
  });

  it("stores --reason in payload.reason", async () => {
    let captured: CreateSignalRequest = {} as CreateSignalRequest;
    server.use(
      http.post(`${BASE_URL}/api/v1/signals/ingest`, async ({ request }) => {
        captured = (await request.json()) as CreateSignalRequest;
        return HttpResponse.json(SIGNAL_RESPONSE);
      }),
    );

    await runCLI([
      "signal",
      "--agent", "agt_abc123",
      "--type", "policy_violation",
      "--severity", "critical",
      "--source", "siem",
      "--reason", "unexpected outbound call",
    ]);

    expect(captured.payload).toEqual({ reason: "unexpected outbound call" });
  });

  it("omits payload when --reason is not given", async () => {
    let captured: CreateSignalRequest = {} as CreateSignalRequest;
    server.use(
      http.post(`${BASE_URL}/api/v1/signals/ingest`, async ({ request }) => {
        captured = (await request.json()) as CreateSignalRequest;
        return HttpResponse.json(SIGNAL_RESPONSE);
      }),
    );

    await runCLI([
      "signal",
      "--agent", "agt_abc123",
      "--type", "ip_change",
      "--severity", "low",
      "--source", "monitor",
    ]);

    expect(captured.payload).toBeUndefined();
  });

  it("prints signal ID on success", async () => {
    server.use(
      http.post(`${BASE_URL}/api/v1/signals/ingest`, () => HttpResponse.json(SIGNAL_RESPONSE)),
    );
    const { stdout, exitCode } = await runCLI([
      "signal",
      "--agent", "agt_abc123",
      "--type", "anomalous_behavior",
      "--severity", "high",
      "--source", "monitor",
    ]);
    expect(exitCode).toBeUndefined();
    expect(stdout.join("\n")).toContain("sig_abc123");
  });

  it("outputs raw JSON with --json", async () => {
    server.use(
      http.post(`${BASE_URL}/api/v1/signals/ingest`, () => HttpResponse.json(SIGNAL_RESPONSE)),
    );
    const { stdout } = await runCLI([
      "signal",
      "--agent", "agt_abc123",
      "--type", "anomalous_behavior",
      "--severity", "high",
      "--source", "monitor",
      "--json",
    ]);
    const parsed = JSON.parse(stdout.join("")) as CAESignal;
    expect(parsed.id).toBe("sig_abc123");
    expect(parsed.signal_type).toBe("anomalous_behavior");
  });

  it("exits 1 when --agent is missing", async () => {
    const { exitCode } = await runCLI([
      "signal",
      "--type", "anomalous_behavior",
      "--severity", "high",
      "--source", "monitor",
    ]);
    expect(exitCode).toBe(1);
  });

  it("exits 1 when --source is missing", async () => {
    const { exitCode } = await runCLI([
      "signal",
      "--agent", "agt_abc123",
      "--type", "anomalous_behavior",
      "--severity", "high",
    ]);
    expect(exitCode).toBe(1);
  });

  it("exits 1 on API error", async () => {
    server.use(
      http.post(`${BASE_URL}/api/v1/signals/ingest`, () =>
        HttpResponse.json({ title: "Bad Request" }, { status: 400 }),
      ),
    );
    const { exitCode } = await runCLI([
      "signal",
      "--agent", "agt_abc123",
      "--type", "anomalous_behavior",
      "--severity", "high",
      "--source", "monitor",
    ]);
    expect(exitCode).toBe(1);
  });
});
