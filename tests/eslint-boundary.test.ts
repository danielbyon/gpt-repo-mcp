import { ESLint } from "eslint";
import { describe, expect, test } from "vitest";

describe("ESLint private research boundary", () => {
  test("ignores private .scratch research globally", async () => {
    const eslint = new ESLint({ cwd: process.cwd(), warnIgnored: false });
    expect(await eslint.isPathIgnored(".scratch/linked-worktree-support/baseline/OWNER_CAPTURE.mjs")).toBe(true);
    const results = await eslint.lintText("const unused = 1;\n", {
      filePath: ".scratch/lint-boundary-fixture.mjs"
    });
    expect(results).toEqual([]);
  });

  test("still reports standard violations for a virtual non-ignored project file", async () => {
    const eslint = new ESLint({ cwd: process.cwd() });
    const [result] = await eslint.lintText("const unused = 1;\n", {
      filePath: "tests/eslint-boundary-fixture.mjs"
    });
    expect(result).toBeDefined();
    expect(result.messages.some(
      (message) => message.ruleId?.endsWith("no-unused-vars") === true && message.severity === 2
    )).toBe(true);
  });

  test("keeps project source, scripts, tests, and JavaScript modules under lint", async () => {
    const eslint = new ESLint({ cwd: process.cwd() });
    for (const path of [
      "src/adoption/adoption-service.ts",
      "scripts/check-public.mjs",
      "tests/adoption-slice-a.test.ts",
      "eslint.config.js"
    ]) {
      expect(await eslint.isPathIgnored(path), path).toBe(false);
    }
  });
});
