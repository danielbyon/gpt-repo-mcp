import { access, readFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, test } from "vitest";

describe("package startup scripts", () => {
  test("declares local startup shortcuts", async () => {
    const raw = await readFile(join(process.cwd(), "package.json"), "utf8");
    const pkg = JSON.parse(raw) as {
      bin?: Record<string, string>;
      engines?: Record<string, string>;
      scripts?: Record<string, string>;
    };

    expect(pkg.bin?.["gpt-repo"]).toBe("dist/cli/connect-gpt.js");
    expect(pkg.bin?.["connect-gpt"]).toBe("dist/cli/connect-gpt.js");
    expect(pkg.engines?.node).toBe(">=20");
    expect(pkg.scripts?.mcp).toBe("GPT_REPO_CONFIG=./config.local.json PORT=8787 npm run dev");
    expect(pkg.scripts?.tunnel).toContain("--log=stdout");
    expect(pkg.scripts?.connect).toBe("node scripts/connect-dev.mjs");
    expect(pkg.scripts?.["connect:cloudflare"]).toBe("PORT=8788 node scripts/connect-cloudflare.mjs");
    expect(pkg.scripts?.["connect:secure"]).toBe("node scripts/connect-secure.mjs");
    expect(pkg.scripts?.["check:public"]).toBe("node scripts/check-public.mjs");
    expect(pkg.scripts?.["security:scan"]).toBe("node scripts/oss-security-scan.mjs");
    expect(pkg.scripts?.add).toBe("node dist/cli/connect-gpt.js add");
    expect(pkg.scripts?.remove).toBe("node dist/cli/connect-gpt.js remove");
    expect(pkg.scripts?.list).toBe("node dist/cli/connect-gpt.js list");
    expect(pkg.scripts?.["check:config"]).toBe("node dist/cli/connect-gpt.js check");
  });

  test.each([
    "scripts/connect-dev.mjs",
    "scripts/connect-cloudflare.mjs",
    "scripts/connect-secure.mjs",
    "scripts/check-public.mjs",
    "scripts/oss-security-scan.mjs"
  ])("includes the %s entry point", async (script) => {
    await expect(access(join(process.cwd(), script))).resolves.toBeUndefined();
  });
});
