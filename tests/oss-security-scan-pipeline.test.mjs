import { spawnSync } from "node:child_process";
import process from "node:process";
import { URL, fileURLToPath } from "node:url";
import { expect, test } from "vitest";
import { runSecurityScan } from "../scripts/oss-security-scan.mjs";

test("rejects the retired diagnostic-only scanner option with migration guidance", async () => {
  await expect(runSecurityScan({ diagnostic: true })).rejects.toThrow(
    /diagnostic mode is no longer supported.*explicit candidate and target refs/i
  );
});

test("returns NOT_RUN when explicit scanner and source inputs are missing", async () => {
  await expect(runSecurityScan({})).resolves.toMatchObject({
    status: "NOT_RUN",
    scanner_invoked: false,
    publication_eligible: false,
    owner_approval_required: true
  });
});

test("CLI without an explicit request reports production policy scan NOT_RUN", () => {
  const script = fileURLToPath(new URL("../scripts/oss-security-scan.mjs", import.meta.url));
  const result = spawnSync(process.execPath, [script], {
    cwd: process.cwd(),
    encoding: "utf8"
  });

  expect(result.status).toBe(78);
  expect(JSON.parse(result.stdout)).toMatchObject({
    status: "NOT_RUN",
    code: "SCAN_REQUEST_REQUIRED",
    scanner_invoked: false,
    publication_eligible: false
  });
});
