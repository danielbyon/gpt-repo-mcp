import { readFileSync } from "node:fs";
import { join } from "node:path";
import process from "node:process";
import { runSupervisorWithScanner } from "../../scripts/secure-process-supervisor.mjs";

const PROCESS_TABLE_PATH = join(process.cwd(), "process-table.json");
const PROCESS_TABLE_SCAN_TIMEOUT_MS = 150;
const PROCESS_TABLE_ARGUMENTS = ["-A", "-o", "pid=", "-o", "pgid="];

/** Reads a test-owned process table and returns a spawnSync-shaped result. */
function readTestProcessTable(command, args, options) {
  const response = JSON.parse(readFileSync(PROCESS_TABLE_PATH, "utf8"));
  if (command !== "ps" || JSON.stringify(args) !== JSON.stringify(PROCESS_TABLE_ARGUMENTS)
    || options?.encoding !== "utf8" || options?.timeout !== response.expectedTimeoutMs
    || response.expectedTimeoutMs !== PROCESS_TABLE_SCAN_TIMEOUT_MS || options?.windowsHide !== true
    || options?.env?.LC_ALL !== "C") {
    throw new Error("Supervisor process-table scan did not match the test fixture contract.");
  }

  const livePids = new Set(response.livePids ?? []);
  const rows = (response.rows ?? []).filter((row) => !livePids.has(row.pid) || isProcessAlive(row.pid));
  const stdout = typeof response.stdout === "string"
    ? response.stdout
    : rows.map((row) => `${row.pid} ${row.pgid}\n`).join("");
  const stderr = typeof response.stderr === "string" ? response.stderr : "";
  const result = {
    pid: process.pid,
    output: [null, stdout, stderr],
    stdout,
    stderr,
    status: Number.isInteger(response.status) ? response.status : 0,
    signal: typeof response.signal === "string" ? response.signal : null
  };
  if (typeof response.errorCode === "string") {
    result.error = Object.assign(new Error("Synthetic process-table scan failure."), { code: response.errorCode });
  }
  return result;
}

function isProcessAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error?.code === "EPERM";
  }
}

void runSupervisorWithScanner(readTestProcessTable);
