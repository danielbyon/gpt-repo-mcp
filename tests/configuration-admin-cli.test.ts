import { describe, expect, test, vi } from "vitest";
import { resolve } from "node:path";
import { runConnectGptCli } from "../src/cli/connect-gpt.js";
import { ConfigurationAdminIpcError } from "../src/runtime/configuration-admin-error.js";
import type {
  ConfigurationAdminReloadResponse,
  ConfigurationAdminStatusResponse
} from "../src/runtime/configuration-admin-protocol.js";

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

describe("config status CLI command", () => {
  test("uses the resolved source and permits no-source matches only for the default", async () => {
    const selections: unknown[] = [];
    const configurationAdminStatus = vi.fn(async (options: { allowNoSource: boolean; selectedSourceIdentity: unknown }) => {
      selections.push(options);
      return statusResponse();
    });
    const io = {
      cwd,
      env: {},
      stdout: () => undefined,
      stderr: () => undefined,
      configurationAdminStatus
    };

    await runConnectGptCli(["config", "status"], io);
    await runConnectGptCli(["--config", "explicit.json", "config", "status"], io);

    expect(selections).toEqual([
      {
        selectedSourceIdentity: { status: "available", platform, path: resolve(cwd, "config.local.json") },
        allowNoSource: true
      },
      {
        selectedSourceIdentity: { status: "available", platform, path: resolve(cwd, "explicit.json") },
        allowNoSource: false
      }
    ]);
  });

  test("prints runtime and saved-file observations while returning failure for invalid saved config", async () => {
    const stdout: string[] = [];
    const stderr: string[] = [];
    const code = await runConnectGptCli(["config", "status"], {
      cwd,
      env: {},
      stdout: (line) => stdout.push(line),
      stderr: (line) => stderr.push(line),
      configurationAdminStatus: async () => ({
        ...statusResponse(),
        saved_source: {
          status: "validation-failed",
          category: "repository-filesystem",
          source_sha256: "b".repeat(64),
          issue_codes: ["ROOT_MISSING"],
          issue_codes_truncated: false
        }
      })
    });

    expect(code).toBe(1);
    expect(stdout.join("\n")).toContain("Effective hot revision: generation=3 repositories=2");
    expect(stdout.join("\n")).toContain("Last reload outcome: rejected");
    expect(stdout.join("\n")).toContain("ROOT_MISSING");
    expect(stdout.join("\n")).not.toContain("private filesystem detail");
    expect(stderr).toEqual([]);
  });

  test("formats no-source, file-read, and JSON observations with the correct exit status", async () => {
    const cases = [
      {
        sourceIdentity: { status: "none" } as const,
        savedSource: { status: "no-source" } as const,
        exitCode: 0,
        expected: "Source: none (intentional no-source instance)"
      },
      {
        sourceIdentity: { status: "available", platform, path: resolve(cwd, "config.local.json") } as const,
        savedSource: { status: "read-failed", code: "FILE_NOT_FOUND" } as const,
        exitCode: 1,
        expected: "Saved file: read-failed code=FILE_NOT_FOUND"
      },
      {
        sourceIdentity: { status: "available", platform, path: resolve(cwd, "config.local.json") } as const,
        savedSource: { status: "invalid-json", source_sha256: "b".repeat(64) } as const,
        exitCode: 1,
        expected: `Saved file: invalid-json sha256=${"b".repeat(64)}`
      }
    ];

    for (const entry of cases) {
      const stdout: string[] = [];
      const response = {
        ...statusResponse(),
        source_identity: entry.sourceIdentity,
        saved_source: entry.savedSource
      };
      const code = await runConnectGptCli(["config", "status"], {
        cwd,
        env: {},
        stdout: (line) => stdout.push(line),
        stderr: () => undefined,
        configurationAdminStatus: async () => response
      });

      expect(code).toBe(entry.exitCode);
      expect(stdout.join("\n")).toContain(entry.expected);
    }
  });

  test("does not dispatch status when the selected source identity is unavailable", async () => {
    const stderr: string[] = [];
    const configurationAdminStatus = vi.fn(async () => statusResponse());

    const code = await runConnectGptCli(["config", "status"], {
      cwd,
      env: { GPT_REPO_CONFIG: "" },
      stdout: () => undefined,
      stderr: (line) => stderr.push(line),
      configurationAdminStatus
    });

    expect(code).toBe(1);
    expect(configurationAdminStatus).not.toHaveBeenCalled();
    expect(stderr.join("\n")).toContain("status was not requested");
    expect(stderr.join("\n")).not.toContain("reload");
  });

  test("formats status IPC failure without reload wording", async () => {
    const stderr: string[] = [];
    const code = await runConnectGptCli(["config", "status"], {
      cwd,
      env: {},
      stdout: () => undefined,
      stderr: (line) => stderr.push(line),
      configurationAdminStatus: async () => {
        throw new ConfigurationAdminIpcError(
          "IPC_TIMEOUT",
          "pre-dispatch",
          "The administrative endpoint did not provide a status snapshot before the deadline."
        );
      }
    });

    expect(code).toBe(1);
    expect(stderr.join("\n")).toContain("Configuration status could not be verified");
    expect(stderr.join("\n")).not.toContain("reload");
    expect(stderr.join("\n")).not.toContain("server stopped");
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

function statusResponse(): ConfigurationAdminStatusResponse {
  return {
    protocol_version: 1,
    request_id: "11111111-1111-4111-8111-111111111111",
    server_pid: 42,
    instance_id: "22222222-2222-4222-8222-222222222222",
    source_identity: {
      status: "available",
      platform,
      path: resolve(cwd, "config.local.json")
    },
    operation: "status_result",
    accepted_candidate: {
      source_sha256: "a".repeat(64),
      repository_count: 2,
      restart_fields: ["provider"]
    },
    saved_source: {
      status: "valid",
      source_sha256: "a".repeat(64),
      matches_accepted: true,
      repository_count: 2,
      restart_fields: ["provider"]
    },
    active_hot_revision: { generation: 3, repository_count: 2 },
    initialized_restart_fields: ["provider"],
    pending_restart_fields: ["query_timeout_ms"],
    last_reload_outcome: "rejected"
  };
}
