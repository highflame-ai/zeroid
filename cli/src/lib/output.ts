/**
 * Output helpers — table and JSON rendering, consistent error formatting.
 */

import chalk from "chalk";
import Table from "cli-table3";

export function printTable(headers: string[], rows: string[][]): void {
  const table = new Table({
    head: headers.map((h) => chalk.bold(h)),
    style: { head: [], border: [] },
  });
  for (const row of rows) {
    table.push(row);
  }
  console.log(table.toString());
}

export function printJSON(data: unknown): void {
  console.log(JSON.stringify(data, null, 2));
}

export function printSuccess(message: string): void {
  console.log(chalk.green("✓") + "  " + message);
}

export function printWarning(message: string): void {
  console.warn(chalk.yellow("⚠") + "  " + message);
}

export function printError(message: string): void {
  console.error(chalk.red("✗") + "  " + message);
}

/**
 * Format an ISO timestamp as a short relative string for table display.
 * Handles both past ("2h ago") and future ("in 10m") timestamps.
 */
export function relativeTime(iso: string): string {
  const delta = Date.now() - new Date(iso).getTime();
  const abs = Math.abs(delta);
  const future = delta < 0;

  let rel: string;
  if (abs < 60_000) rel = `${Math.floor(abs / 1000)}s`;
  else if (abs < 3_600_000) rel = `${Math.floor(abs / 60_000)}m`;
  else if (abs < 86_400_000) rel = `${Math.floor(abs / 3_600_000)}h`;
  else rel = `${Math.floor(abs / 86_400_000)}d`;

  return future ? `in ${rel}` : `${rel} ago`;
}

/** Handle a CLI command error — print and exit 1. */
export function handleError(err: unknown): never {
  const msg = err instanceof Error ? err.message : String(err);
  printError(msg);
  process.exit(1);
}
