import { describe, expect, test, vi } from "vitest";
import type { SpawnOptions } from "node:child_process";

const spawnFault = vi.hoisted(() => ({ failNext: false }));

vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return {
    ...actual,
    spawn: (command: string, args: readonly string[] = [], options: SpawnOptions = {}) => {
      if (spawnFault.failNext) {
        spawnFault.failNext = false;
        return actual.spawn("Z:\\missing-issue-6-admin-helper.exe", args, options);
      }
      return actual.spawn(command, args, options);
    }
  };
});

import { startWindowsConfigurationAdminHost } from "../src/runtime/configuration-admin-windows.js";

describe("Windows administrative helper process errors", () => {
  test.skipIf(process.platform !== "win32")("classifies a real spawn failure without an unhandled process or stream error", async () => {
    vi.stubEnv("GPT_REPO_ADMIN_TEST_HELPER", "1");
    spawnFault.failNext = true;

    try {
      await expect(startWindowsConfigurationAdminHost({
        serverPid: process.pid,
        instanceId: "22222222-2222-4222-8222-222222222222",
        handle: async () => {
          throw new Error("A missing native executable must not dispatch requests.");
        }
      })).rejects.toMatchObject({
        code: "WINDOWS_HELPER_START_FAILED",
        phase: "pre-dispatch"
      });
      expect(spawnFault.failNext).toBe(false);
    } finally {
      spawnFault.failNext = false;
      vi.unstubAllEnvs();
    }
  });
});
