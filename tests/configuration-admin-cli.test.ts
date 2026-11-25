import { describe, expect, test, vi } from "vitest";
import { resolve } from "node:path";
import { runConnectGptCli } from "../src/cli/connect-gpt.js";
import { ConfigurationAdminIpcError } from "../src/runtime/configuration-admin-error.js";
import type { ConfigurationAdminReloadResponse } from "../src/runtime/configuration-admin-protocol.js";

const cwd = process.platform === "win32" ? "C:\\temp\\config-admin-cli-test" : "/tmp/config-admin-cli-test";
const platform = process.platform === "win32" ? "win32" : "posix";

describe("config reload CLI command", () => {
  test("uses existing source precedence and the explicit server PID", async () => {
    const stdout: string[] = [];
    const stderr: string[] = [];
    const adminReload = vi.fn(async () => publishedResponse());

    const code = await runConnectGptCli(["config", "reload", "--instance", "42"], {
      cwd,
      env: { GPT_REPO_CONFIG: "selected.json", REPO_READER_CONFIG: "ignored.json" },
      stdout: (line) => stdout.push(line),
      stderr: (line) => stderr.push(line),
      configurationAdminReload: adminReload
    });

    expect(code).toBe(0);
    expect(adminReload).toHaveBeenCalledWith({
      selectedSourceIdentity: {
        status: "available",
        platform,
        path: resolve(cwd, "selected.json")
      },
      instancePid: 42
    });
    expect(stdout.join("\n")).toContain("Reloaded configuration in server PID 42");
    expect(stderr).toEqual([]);
  });

  test("supports both global --config forms and the implicit default source", async () => {
    const identities: unknown[] = [];
    const adminReload = vi.fn(async (options: { selectedSourceIdentity: unknown }) => {
      identities.push(options.selectedSourceIdentity);
      return publishedResponse();
    });
    const io = {
      cwd,
      env: {},
      stdout: () => undefined,
      stderr: () => undefined,
      configurationAdminReload: adminReload
    };

    await runConnectGptCli(["--config", "first.json", "config", "reload"], io);
    await runConnectGptCli(["config", "reload", "--config=second.json"], io);
    await runConnectGptCli(["config", "reload"], io);

    expect(identities).toEqual([
      { status: "available", platform, path: resolve(cwd, "first.json") },
      { status: "available", platform, path: resolve(cwd, "second.json") },
      { status: "available", platform, path: resolve(cwd, "config.local.json") }
    ]);
  });

  test("rejects an empty higher-precedence source before contacting IPC", async () => {
    const stderr: string[] = [];
    const adminReload = vi.fn(async () => publishedResponse());

    const code = await runConnectGptCli(["config", "reload"], {
      cwd,
      env: { GPT_REPO_CONFIG: "", REPO_READER_CONFIG: "valid.json" },
      stdout: () => undefined,
      stderr: (line) => stderr.push(line),
      configurationAdminReload: adminReload
    });

    expect(code).toBe(1);
    expect(adminReload).not.toHaveBeenCalled();
    expect(stderr.join("\n")).toContain("cannot be compared safely");
  });

  test("rejects malformed or duplicate instance selectors", async () => {
    const adminReload = vi.fn(async () => publishedResponse());
    const io = {
      cwd,
      env: {},
      stdout: () => undefined,
      stderr: () => undefined,
      configurationAdminReload: adminReload
    };

    expect(await runConnectGptCli(["config", "reload", "--instance", "nope"], io)).toBe(1);
    expect(await runConnectGptCli(["config", "reload", "--instance", "41", "--instance", "42"], io)).toBe(1);
    expect(adminReload).not.toHaveBeenCalled();
  });

  test("reports a server rejection as confirmed rejection", async () => {
    const stderr: string[] = [];
    const code = await runConnectGptCli(["config", "reload"], {
      cwd,
      env: {},
      stdout: () => undefined,
      stderr: (line) => stderr.push(line),
      configurationAdminReload: async () => ({
        ...publishedResponse(),
        outcome: "rejected",
        rejection_code: "CANDIDATE_REJECTED",
        rejection_message: "The configuration candidate was rejected.",
        active_effective_generation: 3,
        active_source_sha256: "b".repeat(64)
      } as const)
    });

    expect(code).toBe(1);
    expect(stderr.join("\n")).toContain("rejected");
    expect(stderr.join("\n")).not.toContain("indeterminate");
  });

  test("explains when a reload may have published before its acknowledgement was lost", async () => {
    const stderr: string[] = [];
    const code = await runConnectGptCli(["config", "reload"], {
      cwd,
      env: {},
      stdout: () => undefined,
      stderr: (line) => stderr.push(line),
      configurationAdminReload: async () => {
        throw new ConfigurationAdminIpcError(
          "IPC_TIMEOUT",
          "indeterminate",
          "The administrative endpoint did not respond before the deadline."
        );
      }
    });

    expect(code).toBe(1);
    expect(stderr.join("\n")).toContain("Configuration reload outcome is indeterminate");
    expect(stderr.join("\n")).toContain("The server may have applied it");
  });

  test("states that a pre-dispatch reload failure was not sent", async () => {
    const stderr: string[] = [];
    const code = await runConnectGptCli(["config", "reload"], {
      cwd,
      env: {},
      stdout: () => undefined,
      stderr: (line) => stderr.push(line),
      configurationAdminReload: async () => {
        throw new ConfigurationAdminIpcError(
          "IPC_UNAVAILABLE",
          "pre-dispatch",
          "The administrative endpoint is unavailable."
        );
      }
    });

    expect(code).toBe(1);
    expect(stderr.join("\n")).toContain("Configuration reload was not dispatched");
  });
});

function publishedResponse(): ConfigurationAdminReloadResponse {
  return {
    protocol_version: 1,
    request_id: "11111111-1111-4111-8111-111111111111",
    server_pid: 42,
    instance_id: "22222222-2222-4222-8222-222222222222",
    source_identity: {
      status: "available",
      platform,
      path: resolve(cwd, "selected.json")
    },
    operation: "reload_result",
    outcome: "published",
    effective_generation: 3,
    accepted_source_sha256: "a".repeat(64),
    pending_restart: false
  };
}
