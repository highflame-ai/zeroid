import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    globals: false,
    restoreMocks: true,
    // Run test FILES strictly one at a time. The CLI tests capture output by
    // spying on the GLOBAL `console` and mutating `process.env` (see
    // tests/helpers.ts::runCLI) — process-global state with no per-call isolation.
    // Vitest interleaves multiple files' async `it` callbacks on a shared event
    // loop, so two files' runCLI calls race on those globals: one test's stdout
    // capture is hijacked (comes back empty / its exit code leaks) while another
    // command's parse error ("--name/--agent/--source required") bleeds through.
    // That was a ~1-in-5 flake on the agents `--json` tests. A separate pool
    // (forks/threads) does NOT fix it — the interleaving is at the file level
    // within a worker. Serial file execution removes the concurrency entirely.
    // (The suite is tiny, so the wall-clock cost is negligible.)
    fileParallelism: false,
  },
});
