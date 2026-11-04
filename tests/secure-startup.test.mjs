import { EventEmitter } from "node:events";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import process from "node:process";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { afterEach, describe, expect, test, vi } from "vitest";
import {
  buildMcpProbeUrl,
  classifyTunnelHealthCommand,
  DEFAULT_MCP_STARTUP_WAIT_TIMEOUT,
  DEFAULT_TUNNEL_STARTUP_WAIT_TIMEOUT,
  hasSuccessfulControlPlanePoll,
  isHealthEndpointOwnedByProcess,
  isFreshHealthUrlSnapshot,
  parseDurationMs,
  probeMcp,
  probeTunnelHttp,
  readHealthUrlSnapshot,
  runCancellableCommand,
  selectTunnelHealthMode,
  validateTunnelHealthUrl,
  waitForFreshHealthUrl,
  waitForMcpListener,
  waitForMcpReadiness,
  waitForTunnelReadiness
} from "../scripts/secure-startup.mjs";

const servers = new Set();
const fixtures = new Set();

afterEach(async () => {
  await Promise.all([...servers].map((server) => new Promise((resolve) => server.close(resolve))));
  servers.clear();
  await Promise.all([...fixtures].map((path) => rm(path, { recursive: true, force: true })));
  fixtures.clear();
  vi.useRealTimers();
});

describe("secure startup timeouts", () => {
  test("accepts Go duration syntax and preserves the caller's original value", () => {
    expect(parseDurationMs("1.5m", "MCP_STARTUP_WAIT_TIMEOUT")).toEqual({
      value: "1.5m",
      timeoutMs: 90_000
    });
    expect(parseDurationMs("2m45s", "MCP_STARTUP_WAIT_TIMEOUT", { maxMs: 600_000 })).toEqual({
      value: "2m45s",
      timeoutMs: 165000
    });
    expect(parseDurationMs("2µs", "MCP_STARTUP_WAIT_TIMEOUT").timeoutMs).toBe(1);
    expect(parseDurationMs("2μs", "MCP_STARTUP_WAIT_TIMEOUT").timeoutMs).toBe(1);
    const longFraction = `1.${"0".repeat(300)}s`;
    expect(parseDurationMs(longFraction, "MCP_STARTUP_WAIT_TIMEOUT").value).toBe(longFraction);
  });

  test.each(["", "0", "-1s", "1", "30 seconds", "1e3s", "9223372036854775808h", "11m"])(
    "rejects invalid, nonpositive, overflowing, or unreasonable duration %j",
    (value) => {
      expect(() => parseDurationMs(value, "MCP_STARTUP_WAIT_TIMEOUT", { maxMs: 600_000 })).toThrow(
        "MCP_STARTUP_WAIT_TIMEOUT"
      );
    }
  );

  test("keeps the MCP and tunnel defaults independently configurable", () => {
    expect(DEFAULT_MCP_STARTUP_WAIT_TIMEOUT).toBe("30s");
    expect(DEFAULT_TUNNEL_STARTUP_WAIT_TIMEOUT).toBe("60s");
    expect(parseDurationMs(DEFAULT_MCP_STARTUP_WAIT_TIMEOUT, "MCP_STARTUP_WAIT_TIMEOUT").timeoutMs).toBe(30_000);
    expect(parseDurationMs(DEFAULT_TUNNEL_STARTUP_WAIT_TIMEOUT, "TUNNEL_STARTUP_WAIT_TIMEOUT").timeoutMs).toBe(60_000);
  });
});

describe("MCP startup readiness", () => {
  test("builds the configured endpoint, including an encoded public path token", () => {
    expect(buildMcpProbeUrl({ host: "127.0.0.1", port: 9123, publicPathToken: "alpha/beta" })).toBe(
      "http://127.0.0.1:9123/t/alpha%2Fbeta/mcp"
    );
    expect(buildMcpProbeUrl({ host: "0.0.0.0", port: 9123 })).toBe("http://127.0.0.1:9123/mcp");
    expect(buildMcpProbeUrl({ host: "::", port: 9123 })).toBe("http://[::1]:9123/mcp");
  });

  test("waits for its own listener announcement and rejects a port collision before probing", async () => {
    const child = new EventEmitter();
    child.exitCode = null;
    child.signalCode = null;
    const waiting = waitForMcpListener({
      child,
      port: 9123,
      timeoutMs: 30_000,
      wait: async () => undefined
    });
    child.emit("exit", 1, null);
    await expect(waiting).rejects.toThrow(/MCP process exited before binding/);
  });

  test("accepts a listener announced after startup begins without a test delay", async () => {
    const child = new EventEmitter();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.exitCode = null;
    child.signalCode = null;
    const waiting = waitForMcpListener({ child, port: 9123, timeoutMs: 30_000 });
    child.stderr.write("gpt-repo-mcp listening on http://127.0.0.1:9123/mcp\n");
    await expect(waiting).resolves.toMatchObject({ boundPort: 9123 });
  });

  test("performs a fresh initialize, initialized notification, and required tools-list probe", async () => {
    const requests = [];
    const server = await startHttpServer(async (request, response) => {
      const body = await readRequestBody(request);
      requests.push({ method: request.method, path: request.url, rpc: body.method, session: request.headers["mcp-session-id"] });
      if (request.method === "DELETE") {
        response.writeHead(200).end();
        return;
      }
      if (body.method === "initialize") {
        response.writeHead(200, { "content-type": "application/json", "mcp-session-id": "probe-session" });
        response.end(JSON.stringify({ jsonrpc: "2.0", id: body.id, result: { protocolVersion: "2025-03-26" } }));
        return;
      }
      if (body.method === "notifications/initialized") {
        response.writeHead(202).end();
        return;
      }
      if (body.method === "tools/list") {
        response.writeHead(200, { "content-type": "application/json", "mcp-session-id": "probe-session" });
        response.end(JSON.stringify({ jsonrpc: "2.0", id: body.id, result: { tools: [{ name: "repo_list_roots" }] } }));
        return;
      }
      response.writeHead(400).end();
    });
    const endpoint = `http://127.0.0.1:${server.port}/t/public-token/mcp`;

    await expect(probeMcp({ url: endpoint })).resolves.toMatchObject({ state: "ready" });

    expect(requests.map(({ rpc }) => rpc)).toEqual([
      "initialize",
      "notifications/initialized",
      "tools/list",
      undefined
    ]);
    expect(requests.every(({ path }) => path === "/t/public-token/mcp")).toBe(true);
    expect(requests.at(-1)).toMatchObject({ method: "DELETE", session: "probe-session" });
  });

  test("treats protocol and authorization errors as permanent instead of pending", async () => {
    const server = await startHttpServer((_request, response) => response.writeHead(404).end());
    await expect(probeMcp({ url: `http://127.0.0.1:${server.port}/mcp` })).resolves.toMatchObject({
      state: "failed",
      reason: "http_404"
    });
  });

  test("fails an uncertain initialize response instead of retrying and leaking an unknown session", async () => {
    const fetchImpl = async () => {
      throw Object.assign(new TypeError("fetch failed"), { cause: { code: "ECONNRESET" } });
    };
    await expect(probeMcp({ url: "http://127.0.0.1:9123/mcp", fetchImpl })).resolves.toMatchObject({
      state: "failed",
      reason: "initialize_response_uncertain"
    });
  });

  test("retries pending MCP readiness and fails permanent errors without retrying", async () => {
    let clock = 0;
    let attempts = 0;
    await expect(waitForMcpReadiness({
      url: "http://127.0.0.1:9123/mcp",
      timeoutMs: 100,
      now: () => clock,
      retryIntervalMs: 25,
      sleep: async (duration) => { clock += duration; },
      probe: async () => (++attempts === 1 ? { state: "pending", reason: "connection_pending" } : { state: "ready" })
    })).resolves.toMatchObject({ state: "ready" });
    expect(attempts).toBe(2);

    attempts = 0;
    await expect(waitForMcpReadiness({
      url: "http://127.0.0.1:9123/mcp",
      timeoutMs: 100,
      probe: async () => { attempts += 1; return { state: "failed", reason: "http_404" }; }
    })).rejects.toThrow("MCP startup failed (http_404)");
    expect(attempts).toBe(1);
  });

  test("bounds pending MCP readiness with the independent MCP deadline", async () => {
    let clock = 0;
    let attempts = 0;
    await expect(waitForMcpReadiness({
      url: "http://127.0.0.1:9123/mcp",
      timeoutMs: 500,
      now: () => clock,
      sleep: async (duration) => { clock += duration; },
      probe: async () => { attempts += 1; return { state: "pending", reason: "connection_pending" }; }
    })).rejects.toThrow("MCP startup timed out (connection_pending)");
    expect(attempts).toBeGreaterThan(1);
  });

  test("accepts MCP readiness only before its deadline", async () => {
    for (const [startTime, completionTime, expected] of [
      [0, 99, "ready"],
      [0, 100, "timeout"],
      [0, 101, "timeout"],
      [101, 101, "timeout"]
    ]) {
      let clock = startTime;
      let attempts = 0;
      const wait = waitForMcpReadiness({
        url: "http://127.0.0.1:9123/mcp",
        timeoutMs: 100,
        deadline: 100,
        now: () => clock,
        probe: async () => {
          attempts += 1;
          clock = completionTime;
          return { state: "ready" };
        }
      });

      if (expected === "ready") {
        await expect(wait).resolves.toMatchObject({ state: "ready" });
      } else {
        await expect(wait).rejects.toThrow("MCP startup timed out");
      }
      expect(attempts).toBe(startTime >= 100 ? 0 : 1);
    }
  });

  test("aborts an MCP probe that is still active at the deadline", async () => {
    vi.useFakeTimers();
    let attempts = 0;
    let probeCancelled = false;
    const waiting = waitForMcpReadiness({
      url: "http://127.0.0.1:9123/mcp",
      timeoutMs: 100,
      now: () => 0,
      probe: async ({ signal }) => {
        attempts += 1;
        return new Promise((resolve) => signal.addEventListener("abort", () => {
          probeCancelled = true;
          resolve({ state: "ready" });
        }, { once: true }));
      }
    });

    try {
      const timeoutAssertion = expect(waiting).rejects.toThrow("MCP startup timed out");
      await vi.advanceTimersByTimeAsync(100);
      await timeoutAssertion;
      expect(attempts).toBe(1);
      expect(probeCancelled).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("tunnel health identity and readiness", () => {
  test("does not treat an unchanged stale URL file as a new tunnel instance", async () => {
    const fixture = await makeFixture();
    const urlFile = join(fixture, "health.url");
    await writeFile(urlFile, "http://127.0.0.1:8080\n", { mode: 0o600 });
    const before = await readHealthUrlSnapshot(urlFile);
    const after = await readHealthUrlSnapshot(urlFile);

    expect(after.content).toBe("http://127.0.0.1:8080");
    expect(after.identity).toEqual(before.identity);
    expect(isFreshHealthUrlSnapshot(before, after)).toBe(false);
  });

  test("rejects a health URL file that changes while its contents are being read", async () => {
    const first = { dev: 1n, ino: 2n, size: 24n, mtimeNs: 10n, ctimeNs: 10n };
    const changed = { ...first, mtimeNs: 11n, ctimeNs: 11n };
    const handle = {
      stat: vi.fn().mockResolvedValueOnce(first).mockResolvedValueOnce(changed),
      readFile: vi.fn().mockResolvedValue("http://127.0.0.1:8080"),
      close: vi.fn().mockResolvedValue(undefined)
    };

    await expect(readHealthUrlSnapshot("health.url", {
      openFileImpl: async () => handle,
      lstatImpl: async () => changed
    })).rejects.toThrow(/changed while reading/);
    expect(handle.close).toHaveBeenCalledOnce();
  });

  test("times out on a stale URL file without probing its endpoint", async () => {
    const stale = { content: "http://127.0.0.1:8080", identity: { ino: "1", mtimeNs: "1" } };
    let clock = 0;
    await expect(waitForFreshHealthUrl({
      path: "unused",
      before: stale,
      timeoutMs: 500,
      readSnapshot: async () => stale,
      now: () => clock,
      sleep: async (duration) => { clock += duration; }
    })).rejects.toThrow(/did not publish a fresh health URL/);
  });

  test("fails when the tunnel exits before publishing a fresh health URL", async () => {
    await expect(waitForFreshHealthUrl({
      path: "unused",
      before: null,
      timeoutMs: 500,
      isProcessAlive: () => false,
      readSnapshot: async () => null
    })).rejects.toThrow(/Tunnel process exited before publishing/);
  });

  test("rejects a health URL that does not match the configured listener endpoint", () => {
    expect(() => validateTunnelHealthUrl("http://127.0.0.1:9001", { listenAddr: "127.0.0.1:9000" })).toThrow(
      /does not match the configured health listener/
    );
  });

  test("rejects a health URL on another loopback host even when its port matches", () => {
    expect(() => validateTunnelHealthUrl("http://[::1]:9000", {
      listenAddr: "127.0.0.1:9000"
    })).toThrow(/does not match the configured health listener/);
    expect(() => validateTunnelHealthUrl("http://127.0.0.1:9000", {
      listenAddr: "[::]:9000"
    })).toThrow(/does not match the configured health listener/);
  });

  test("requires matching endpoint and PID evidence when the health response provides them", () => {
    expect(() => validateTunnelHealthUrl("http://127.0.0.1:9000", {
      listenAddr: "127.0.0.1:9000",
      tunnelPid: 123,
      report: { pid: 456, url: "http://127.0.0.1:9000" }
    })).toThrow(/PID mismatch/);
    expect(() => validateTunnelHealthUrl("http://127.0.0.1:9000", {
      listenAddr: "127.0.0.1:9000",
      tunnelPid: 123,
      report: { pid: 123, url: "http://127.0.0.1:9001" }
    })).toThrow(/endpoint mismatch/);
  });

  test("confirms the launched process owns the exact caller-configured TCP listener", async () => {
    const runLsof = vi.fn(async () => ({ stdout: "p123\ntIPv4\nn127.0.0.1:9000\n" }));
    await expect(isHealthEndpointOwnedByProcess({
      tunnelPid: 123,
      healthUrl: "http://127.0.0.1:9000",
      execFileImpl: runLsof,
      platform: "linux"
    })).resolves.toBe(true);
    expect(runLsof).toHaveBeenCalledWith("lsof", expect.arrayContaining([
      "-p", "123", "-iTCP:9000", "-sTCP:LISTEN", "-Fptn"
    ]), expect.objectContaining({ timeout: 3_000 }));

    await expect(isHealthEndpointOwnedByProcess({
      tunnelPid: 123,
      healthUrl: "http://127.0.0.1:9001",
      execFileImpl: async () => ({ stdout: "p123\ntIPv4\nn127.0.0.1:9000\n" }),
      platform: "linux"
    })).resolves.toBe(false);
  });

  test("cancels an active endpoint ownership helper when startup is cancelled", async () => {
    const controller = new globalThis.AbortController();
    let helperCancelled = false;
    const check = isHealthEndpointOwnedByProcess({
      tunnelPid: 123,
      healthUrl: "http://127.0.0.1:9000",
      signal: controller.signal,
      platform: "linux",
      execFileImpl: async (_command, _args, options) => new Promise((resolve, reject) => {
        options.signal.addEventListener("abort", () => {
          helperCancelled = true;
          reject(options.signal.reason);
        }, { once: true });
      })
    });

    controller.abort(new Error("startup cancelled"));
    await expect(check).rejects.toThrow("startup cancelled");
    expect(helperCancelled).toBe(true);
  });

  test("checks caller-configured Unix socket ownership by the launched process", async () => {
    const socketPath = "/tmp/secure-tunnel-health.sock";
    const runLsof = vi.fn(async () => ({ stdout: `p123\ntunix\nn${socketPath}\n` }));
    await expect(isHealthEndpointOwnedByProcess({
      tunnelPid: 123,
      healthUrl: "http://127.0.0.1",
      socketPath,
      execFileImpl: runLsof,
      platform: "linux"
    })).resolves.toBe(true);
    expect(runLsof.mock.calls[0][1]).toContain("-U");

    await expect(isHealthEndpointOwnedByProcess({
      tunnelPid: 123,
      healthUrl: "http://127.0.0.1",
      socketPath,
      execFileImpl: async () => ({ stdout: "p123\ntunix\nn/tmp/another.sock\n" }),
      platform: "linux"
    })).resolves.toBe(false);
  });

  test("fails closed when local process ownership cannot be inspected", async () => {
    const unavailable = Object.assign(new Error("not installed"), { code: "ENOENT" });
    await expect(isHealthEndpointOwnedByProcess({
      tunnelPid: 123,
      healthUrl: "http://127.0.0.1:9000",
      execFileImpl: async () => { throw unavailable; },
      platform: "linux"
    })).rejects.toThrow(/cannot verify caller-configured tunnel health endpoint ownership with lsof/i);

    const noListener = Object.assign(new Error("no listener"), { code: 1, stderr: "" });
    await expect(isHealthEndpointOwnedByProcess({
      tunnelPid: 123,
      healthUrl: "http://127.0.0.1:9000",
      execFileImpl: async () => { throw noListener; },
      platform: "linux"
    })).resolves.toBe(false);
  });

  test("checks caller-configured TCP listener ownership on Windows", async () => {
    const runPowerShell = vi.fn(async () => ({ stdout: JSON.stringify({
      LocalAddress: "127.0.0.1",
      LocalPort: 9000,
      OwningProcess: 123
    }) }));
    await expect(isHealthEndpointOwnedByProcess({
      tunnelPid: 123,
      healthUrl: "http://127.0.0.1:9000",
      execFileImpl: runPowerShell,
      platform: "win32"
    })).resolves.toBe(true);
    expect(runPowerShell).toHaveBeenCalledWith("powershell.exe", expect.arrayContaining([
      "-NoProfile", "-NonInteractive", "-Command"
    ]), expect.objectContaining({ timeout: 3_000 }));

    await expect(isHealthEndpointOwnedByProcess({
      tunnelPid: 123,
      healthUrl: "http://127.0.0.1:9000",
      execFileImpl: async () => ({ stdout: JSON.stringify({
        LocalAddress: "127.0.0.1",
        LocalPort: 9000,
        OwningProcess: 456
      }) }),
      platform: "win32"
    })).resolves.toBe(false);
  });

  test("accepts only versioned control-plane poll success evidence", () => {
    expect(hasSuccessfulControlPlanePoll({
      control_plane_poll: { state: "idle", last_success: "2026-11-02T12:00:00Z" }
    })).toBe(false);
    expect(hasSuccessfulControlPlanePoll({
      schema_version: 2,
      components: {
        "control-plane": {
          status: "ok",
          state: "idle",
          details: { last_success: "2026-11-02T12:00:00Z" }
        }
      }
    })).toBe(false);
    expect(hasSuccessfulControlPlanePoll({
      schema_version: 1,
      components: {
        "control-plane": {
          status: "ok",
          state: "idle",
          details: { last_success: "2026-11-02T12:00:00Z" }
        }
      }
    })).toBe(true);
    expect(hasSuccessfulControlPlanePoll({
      schema_version: 1,
      components: {
        "control-plane": {
          status: "ok",
          state: "idle",
          details: { last_success: "" }
        }
      }
    })).toBe(false);
    expect(hasSuccessfulControlPlanePoll({
      schema_version: 1,
      components: {
        "control-plane": {
          status: "degraded",
          state: "retrying",
          details: { last_success: "2026-11-02T12:00:00Z", consecutive_failures: 1 }
        }
      }
    })).toBe(false);
  });

  test("rejects zero-time and pre-epoch poll markers", () => {
    for (const timestamp of ["0001-01-01T00:00:00Z", "1970-01-01T00:00:00Z", "0"]) {
      expect(hasSuccessfulControlPlanePoll({
        schema_version: 1,
        components: {
          "control-plane": {
            status: "ok",
            state: "idle",
            details: { last_success: timestamp }
          }
        }
      })).toBe(false);
    }
  });

  test("selects HTTP fallback only when the reduced binary can publish a fresh URL file", () => {
    const runHelp = "HEALTH_LISTEN_ADDR HEALTH_URL_FILE";
    expect(selectTunnelHealthMode({ healthHelp: "unknown command", runHelp })).toBe("http");
    expect(selectTunnelHealthMode({
      healthHelp: "Usage:\\n  tunnel-client health [flags]\\n--json --require-control-plane-poll --pid --url-file",
      runHelp
    })).toBe("command");
    expect(() => selectTunnelHealthMode({ healthHelp: "unknown command", runHelp: "HEALTH_LISTEN_ADDR" })).toThrow(
      /cannot publish an instance-specific health URL/
    );
  });

  test("classifies a missing first poll as pending and an idle successful poll as ready", () => {
    const pending = {
      process: { pid: 123, running: true },
      base_url: "http://127.0.0.1:9000",
      control_plane_poll: { ok: false, error: "missing commands_poll_last_successful_timestamp_seconds metric" },
      result: "fail"
    };
    const ready = {
      process: { pid: 123, running: true },
      base_url: "http://127.0.0.1:9000",
      healthz: { ok: true },
      readyz: { ok: true },
      control_plane_poll: { ok: true, value: 1 },
      result: "ok"
    };
    expect(classifyTunnelHealthCommand({
      exitCode: 2,
      stdout: JSON.stringify(pending),
      stderr: "",
      healthUrl: "http://127.0.0.1:9000",
      tunnelPid: 123
    })).toMatchObject({ state: "pending", reason: "control_plane_poll_pending" });
    expect(classifyTunnelHealthCommand({
      exitCode: 0,
      stdout: JSON.stringify(ready),
      stderr: "",
      healthUrl: "http://127.0.0.1:9000",
      tunnelPid: 123,
      processIdentityVerified: true
    })).toMatchObject({ state: "ready" });
  });

  test("classifies the actual v0.0.18 omitted zero-poll value as pending", () => {
    const report = {
      healthz: { ok: true, status: 200, body: "live" },
      readyz: { ok: true, status: 200, body: "ready" },
      control_plane_poll: {
        ok: false,
        error: "no successful control-plane poll observed"
      },
      result: "fail"
    };

    expect(classifyTunnelHealthCommand({
      exitCode: 2,
      stdout: JSON.stringify(report),
      stderr: "",
      healthUrl: "http://127.0.0.1:9000",
      tunnelPid: 123,
      processIdentityVerified: true
    })).toEqual({ state: "pending", reason: "control_plane_poll_pending" });
  });

  test("keeps unrelated failed health reports out of first-poll pending", () => {
    const report = {
      healthz: { ok: true, status: 200, body: "live" },
      readyz: { ok: true, status: 200, body: "ready" },
      control_plane_poll: { ok: false, value: 0, error: "unexpected poll failure" },
      result: "fail"
    };

    expect(classifyTunnelHealthCommand({
      exitCode: 2,
      stdout: JSON.stringify(report),
      stderr: "",
      healthUrl: "http://127.0.0.1:9000",
      tunnelPid: 123,
      processIdentityVerified: true
    })).toMatchObject({ state: "failed" });
  });

  test("continues accepting an explicit zero in the first-poll report", () => {
    const report = {
      healthz: { ok: true, status: 200, body: "live" },
      readyz: { ok: true, status: 200, body: "ready" },
      control_plane_poll: {
        ok: false,
        value: 0,
        error: "no successful control-plane poll observed"
      },
      result: "fail"
    };

    expect(classifyTunnelHealthCommand({
      exitCode: 2,
      stdout: JSON.stringify(report),
      stderr: "",
      healthUrl: "http://127.0.0.1:9000",
      tunnelPid: 123,
      processIdentityVerified: true
    })).toEqual({ state: "pending", reason: "control_plane_poll_pending" });
  });

  test("rejects an unexpected nonzero value with the first-poll error", () => {
    const report = {
      healthz: { ok: true, status: 200, body: "live" },
      readyz: { ok: true, status: 200, body: "ready" },
      control_plane_poll: {
        ok: false,
        value: 1,
        error: "no successful control-plane poll observed"
      },
      result: "fail"
    };

    expect(classifyTunnelHealthCommand({
      exitCode: 2,
      stdout: JSON.stringify(report),
      stderr: "",
      healthUrl: "http://127.0.0.1:9000",
      tunnelPid: 123,
      processIdentityVerified: true
    })).toMatchObject({ state: "failed" });
  });

  test("requires both health endpoints to succeed for first-poll pending", () => {
    for (const endpoints of [
      {
        healthz: { ok: false, status: 503, body: "unavailable" },
        readyz: { ok: true, status: 200, body: "ready" }
      },
      {
        healthz: { ok: true, status: 200, body: "live" },
        readyz: { ok: false, status: 503, body: "starting" }
      }
    ]) {
      const report = {
        ...endpoints,
        control_plane_poll: {
          ok: false,
          error: "no successful control-plane poll observed"
        },
        result: "fail"
      };

      const classification = classifyTunnelHealthCommand({
        exitCode: 2,
        stdout: JSON.stringify(report),
        stderr: "",
        healthUrl: "http://127.0.0.1:9000",
        tunnelPid: 123,
        processIdentityVerified: true
      });
      expect(classification.reason).not.toBe("control_plane_poll_pending");
    }
  });

  test.each([
    ["OAuth", "OAuth discovery failed", "oauth_discovery_failed"],
    ["catalog", "catalog failed", "catalog_failed"]
  ])("keeps permanent %s errors ahead of omitted-value first-poll pending", (_label, reason, expectedReason) => {
    const report = {
      reason,
      healthz: { ok: true, status: 200, body: "live" },
      readyz: { ok: true, status: 200, body: "ready" },
      control_plane_poll: {
        ok: false,
        error: "no successful control-plane poll observed"
      },
      result: "fail"
    };

    expect(classifyTunnelHealthCommand({
      exitCode: 2,
      stdout: JSON.stringify(report),
      stderr: "",
      healthUrl: "http://127.0.0.1:9000",
      tunnelPid: 123,
      processIdentityVerified: true
    })).toEqual({ state: "failed", reason: expectedReason });
  });

  test("rejects incomplete full health command success reports", () => {
    for (const [report, processIdentityVerified] of [
      [{ ready: true }, true],
      [{ status: "ready" }, true],
      [{
        result: "ok",
        process: { pid: 123, running: true },
        healthz: { ok: true },
        readyz: { ok: true },
        control_plane_poll: { ok: true, value: 1 }
      }, false],
      [{
        result: "ok",
        process: { pid: 123, running: true },
        healthz: { ok: true },
        readyz: { ok: true },
        control_plane_poll: { ok: false, value: 1 }
      }, true],
      [{
        result: "ok",
        process: { pid: 123, running: true },
        healthz: { ok: true },
        readyz: { ok: true },
        control_plane_poll: { ok: true, value: 1 }
      }, false]
    ]) {
      expect(classifyTunnelHealthCommand({
        exitCode: 0,
        stdout: JSON.stringify(report),
        stderr: "",
        healthUrl: "http://127.0.0.1:9000",
        tunnelPid: 123,
        processIdentityVerified
      })).toMatchObject({ state: "failed" });
    }
  });

  test("treats a permanent catalog failure as an immediate tunnel failure", () => {
    const report = {
      readyz: { ok: false, status: 503, body: "catalog_failed" },
      control_plane_poll: { ok: false, error: "not polled" },
      result: "fail"
    };
    expect(classifyTunnelHealthCommand({
      exitCode: 2,
      stdout: JSON.stringify(report),
      stderr: "",
      healthUrl: "http://127.0.0.1:9000",
      tunnelPid: 123
    })).toMatchObject({ state: "failed", reason: "catalog_failed" });
  });

  test("permanent catalog failure outranks a missing poll in full health output", () => {
    const report = {
      readyz: { ok: false, status: 503, body: "startup catalog failed" },
      control_plane_poll: { ok: false, error: "missing commands_poll_last_successful_timestamp_seconds metric" },
      result: "fail"
    };
    expect(classifyTunnelHealthCommand({
      exitCode: 2,
      stdout: JSON.stringify(report),
      stderr: "",
      healthUrl: "http://127.0.0.1:9000",
      tunnelPid: 123
    })).toMatchObject({ state: "failed", reason: "catalog_failed" });
  });

  test.each([
    ["OAuth discovery failed", "oauth_discovery_failed"],
    ["invalid profile", "profile_invalid"],
    ["configuration validation failed", "config_invalid"]
  ])("classifies permanent full-command startup failure %s before missing-poll pending", (message, reason) => {
    const report = {
      readyz: { ok: false, status: 503, body: message },
      control_plane_poll: { ok: false, error: "missing commands_poll_last_successful_timestamp_seconds metric" },
      result: "fail"
    };
    expect(classifyTunnelHealthCommand({
      exitCode: 2,
      stdout: JSON.stringify(report),
      stderr: "",
      healthUrl: "http://127.0.0.1:9000",
      tunnelPid: 123
    })).toMatchObject({ state: "failed", reason });
  });

  test("retries pending tunnel health while allowing the process to remain idle after a successful poll", async () => {
    let attempts = 0;
    let clock = 0;
    await expect(waitForTunnelReadiness({
      tunnelPid: 42,
      timeoutMs: 60_000,
      now: () => clock,
      sleep: async (duration) => { clock += duration; },
      probe: async () => (++attempts === 1
        ? { state: "pending", reason: "control_plane_poll_pending" }
        : { state: "ready", reason: "tunnel_health_ready" })
    })).resolves.toMatchObject({ state: "ready" });
    expect(attempts).toBe(2);
  });

  test("fails permanent tunnel readiness errors without waiting out the tunnel deadline", async () => {
    let attempts = 0;
    await expect(waitForTunnelReadiness({
      tunnelPid: 42,
      timeoutMs: 60_000,
      probe: async () => { attempts += 1; return { state: "failed", reason: "catalog_failed" }; }
    })).rejects.toThrow("Tunnel startup failed (catalog_failed)");
    expect(attempts).toBe(1);

    await expect(waitForTunnelReadiness({
      tunnelPid: 42,
      timeoutMs: 60_000,
      isProcessAlive: () => false,
      probe: async () => { throw new Error("must not probe a dead tunnel"); }
    })).rejects.toThrow("Tunnel process exited before readiness");
  });

  test("accepts tunnel readiness only before its deadline", async () => {
    for (const [startTime, completionTime, expected] of [
      [0, 99, "ready"],
      [0, 100, "timeout"],
      [0, 101, "timeout"],
      [101, 101, "timeout"]
    ]) {
      let clock = startTime;
      let attempts = 0;
      const wait = waitForTunnelReadiness({
        tunnelPid: 42,
        timeoutMs: 100,
        deadline: 100,
        now: () => clock,
        probe: async () => {
          attempts += 1;
          clock = completionTime;
          return { state: "ready" };
        }
      });

      if (expected === "ready") {
        await expect(wait).resolves.toMatchObject({ state: "ready" });
      } else {
        await expect(wait).rejects.toThrow("Tunnel readiness timed out");
      }
      expect(attempts).toBe(startTime >= 100 ? 0 : 1);
    }
  });

  test("cancels an in-flight tunnel probe when startup is cancelled", async () => {
    const controller = new globalThis.AbortController();
    let probeAttempts = 0;
    let probeCancelled = false;
    const waiting = waitForTunnelReadiness({
      tunnelPid: 42,
      timeoutMs: 1_000,
      signal: controller.signal,
      probe: async ({ signal }) => {
        probeAttempts += 1;
        signal.addEventListener("abort", () => { probeCancelled = true; }, { once: true });
        return new Promise((resolve) => {
          signal.addEventListener("abort", () => resolve({ state: "ready" }), { once: true });
          controller.abort(new Error("startup cancelled"));
        });
      }
    });

    await expect(waiting).rejects.toThrow("startup cancelled");
    expect(probeAttempts).toBe(1);
    expect(probeCancelled).toBe(true);
  });

  test("aborts a tunnel probe that is still active at the deadline", async () => {
    vi.useFakeTimers();
    let attempts = 0;
    let probeCancelled = false;
    const waiting = waitForTunnelReadiness({
      tunnelPid: 42,
      timeoutMs: 100,
      now: () => 0,
      probe: async ({ signal }) => {
        attempts += 1;
        return new Promise((resolve) => signal.addEventListener("abort", () => {
          probeCancelled = true;
          resolve({ state: "ready" });
        }, { once: true }));
      }
    });

    try {
      const timeoutAssertion = expect(waiting).rejects.toThrow("Tunnel readiness timed out");
      await vi.advanceTimersByTimeAsync(100);
      await timeoutAssertion;
      expect(attempts).toBe(1);
      expect(probeCancelled).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  test("reports a non-cooperative probe when bounded cancellation cannot stop it", async () => {
    vi.useFakeTimers();
    let attempts = 0;
    let probeSignal;
    const waiting = waitForTunnelReadiness({
      tunnelPid: 42,
      timeoutMs: 10,
      probe: ({ signal }) => {
        attempts += 1;
        probeSignal = signal;
        return new Promise(() => {});
      }
    });
    try {
      const assertion = expect(waiting).rejects.toThrow(/probe did not stop within.*cleanup grace/i);
      await vi.advanceTimersByTimeAsync(3_000);
      await assertion;
      expect(attempts).toBe(1);
      expect(probeSignal.aborted).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  test("requires readyz and the versioned upstream control-plane success evidence", async () => {
    const paths = [];
    const server = await startHttpServer((request, response) => {
      paths.push(request.url);
      if (request.url === "/readyz") {
        response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ ready: true }));
        return;
      }
      response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({
        schema_version: 1,
        ready: true,
        components: {
          "control-plane": {
            status: "ok",
            state: "idle",
            details: { last_success: "2026-11-02T12:00:00Z" }
          }
        }
      }));
    });
    const result = await probeTunnelHttp(`http://127.0.0.1:${server.port}`);

    expect(result.state).toBe("ready");
    expect(paths).toEqual(["/readyz", "/health?details=true"]);
  });

  test("accepts a successful empty poll from the documented metrics endpoint", async () => {
    const paths = [];
    const server = await startHttpServer((request, response) => {
      paths.push(request.url);
      if (request.url === "/readyz") {
        response.writeHead(200).end("ready");
        return;
      }
      if (request.url === "/health?details=true") {
        response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({
          schema_version: 1,
          components: {
            "control-plane": { status: "ok", state: "idle", details: {} }
          }
        }));
        return;
      }
      response.writeHead(200, { "content-type": "text/plain; version=0.0.4" }).end([
        "# TYPE commands_poll_last_successful_timestamp_seconds gauge",
        "commands_poll_last_successful_timestamp_seconds 1783070400",
        "commands_polled_total 0"
      ].join("\n"));
    });

    await expect(probeTunnelHttp(`http://127.0.0.1:${server.port}`)).resolves.toMatchObject({ state: "ready" });
    expect(paths).toEqual(["/readyz", "/health?details=true", "/metrics"]);
  });

  test.each(["0", "-1"])("keeps a nonpositive successful-poll metric %s pending", async (sample) => {
    const server = await startHttpServer((request, response) => {
      if (request.url === "/readyz") {
        response.writeHead(200).end("ready");
        return;
      }
      if (request.url === "/health?details=true") {
        response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({
          schema_version: 1,
          components: { "control-plane": { status: "ok", state: "idle", details: {} } }
        }));
        return;
      }
      response.writeHead(200, { "content-type": "text/plain" }).end(
        `commands_poll_last_successful_timestamp_seconds ${sample}\n`
      );
    });

    await expect(probeTunnelHttp(`http://127.0.0.1:${server.port}`)).resolves.toMatchObject({ state: "pending" });
  });

  test("keeps a 200 liveness response pending when no control-plane poll has succeeded", async () => {
    const server = await startHttpServer((request, response) => {
      if (request.url === "/readyz") {
        response.writeHead(200).end("ready");
        return;
      }
      response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({
        control_plane_poll: { state: "idle", last_success: "" }
      }));
    });

    await expect(probeTunnelHttp(`http://127.0.0.1:${server.port}`)).resolves.toMatchObject({ state: "pending" });
  });

  test("does not let unsupported poll records or stale metrics satisfy readiness", async () => {
    const paths = [];
    let details;
    const server = await startHttpServer((request, response) => {
      paths.push(request.url);
      if (request.url === "/readyz") {
        response.writeHead(200).end("ready");
        return;
      }
      if (request.url === "/health?details=true") {
        response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(details));
        return;
      }
      response.writeHead(200, { "content-type": "text/plain" }).end(
        "commands_poll_last_successful_timestamp_seconds 1783070400\n"
      );
    });

    for (const [nextDetails, expectedState] of [
      [{ control_plane_poll: { state: "failed", last_success: "2026-11-02T12:00:00Z" } }, "failed"],
      [{ control_plane_poll: { state: "degraded", last_success: "2026-11-02T12:00:00Z" } }, "pending"],
      [{ control_plane_poll: { state: "unknown", last_success: "2026-11-02T12:00:00Z" } }, "pending"],
      [{
        schema_version: 2,
        components: {
          "control-plane": {
            status: "ok",
            state: "idle",
            details: { last_success: "2026-11-02T12:00:00Z" }
          }
        }
      }, "pending"],
      [{
        schema_version: 1,
        components: {
          "control-plane": {
            status: "ok",
            state: "idle",
            details: { last_success: "2026-11-02T12:00:00Z" }
          }
        },
        control_plane_poll: { state: "failed", last_success: "2026-11-02T12:00:00Z" }
      }, "failed"]
    ]) {
      details = nextDetails;
      paths.length = 0;
      await expect(probeTunnelHttp(`http://127.0.0.1:${server.port}`)).resolves.toMatchObject({ state: expectedState });
      expect(paths).toEqual(["/readyz", "/health?details=true"]);
    }
  });

  test("fails permanent readiness errors from the documented HTTP fallback", async () => {
    const server = await startHttpServer((request, response) => {
      if (request.url === "/readyz") {
        response.writeHead(503, { "content-type": "application/json" }).end(JSON.stringify({ reason_code: "catalog_failed" }));
        return;
      }
      response.writeHead(200).end("{}");
    });
    await expect(probeTunnelHttp(`http://127.0.0.1:${server.port}`)).resolves.toMatchObject({
      state: "failed",
      reason: "catalog_failed"
    });
  });

  test("classifies human-readable permanent startup catalog failures on HTTP 503", async () => {
    const paths = [];
    const server = await startHttpServer((request, response) => {
      paths.push(request.url);
      if (request.url === "/readyz") {
        response.writeHead(503, { "content-type": "text/plain" }).end("startup catalog failed");
        return;
      }
      response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({
        schema_version: 1,
        components: {
          "control-plane": { status: "ok", state: "idle", details: {} }
        }
      }));
    });

    await expect(probeTunnelHttp(`http://127.0.0.1:${server.port}`)).resolves.toMatchObject({
      state: "failed",
      reason: "catalog_failed"
    });
    expect(paths).toEqual(["/readyz"]);
  });

  test.each([
    ["OAuth discovery failed", "oauth_discovery_failed"],
    ["invalid profile", "profile_invalid"],
    ["configuration validation failed", "config_invalid"]
  ])("classifies HTTP permanent startup failure %s", async (message, reason) => {
    const server = await startHttpServer((request, response) => {
      if (request.url === "/readyz") {
        response.writeHead(503, { "content-type": "text/plain" }).end(message);
        return;
      }
      response.writeHead(200).end("{}");
    });

    await expect(probeTunnelHttp(`http://127.0.0.1:${server.port}`)).resolves.toMatchObject({ state: "failed", reason });
  });

  test("checks detailed health after an ambiguous readyz 503 for permanent failures", async () => {
    const paths = [];
    const server = await startHttpServer((request, response) => {
      paths.push(request.url);
      if (request.url === "/readyz") {
        response.writeHead(503, { "content-type": "application/json" }).end(JSON.stringify({ status: "starting" }));
        return;
      }
      response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({
        schema_version: 1,
        components: {
          "control-plane": {
            status: "degraded",
            state: "failed",
            reason_code: "catalog_failed",
            details: { last_success: "" }
          }
        }
      }));
    });

    await expect(probeTunnelHttp(`http://127.0.0.1:${server.port}`)).resolves.toMatchObject({
      state: "failed",
      reason: "catalog_failed"
    });
    expect(paths).toEqual(["/readyz", "/health?details=true"]);
  });

  test("does not retry a permanent poll error hidden behind readyz", async () => {
    const server = await startHttpServer((request, response) => {
      if (request.url === "/readyz") {
        response.writeHead(200).end("ready");
        return;
      }
      response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({
        schema_version: 1,
        components: {
          "control-plane": {
            status: "degraded",
            state: "failed",
            reason_code: "unauthorized",
            details: { last_success: "" }
          }
        }
      }));
    });
    await expect(probeTunnelHttp(`http://127.0.0.1:${server.port}`)).resolves.toMatchObject({
      state: "failed",
      reason: "unauthorized"
    });
  });

  test("does not let a stale metrics timestamp override current control-plane failures", async () => {
    const paths = [];
    let component;
    const server = await startHttpServer((request, response) => {
      paths.push(request.url);
      if (request.url === "/readyz") {
        response.writeHead(200).end("ready");
        return;
      }
      if (request.url === "/health?details=true") {
        response.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({
          schema_version: 1,
          components: { "control-plane": component }
        }));
        return;
      }
      response.writeHead(200, { "content-type": "text/plain" }).end(
        "commands_poll_last_successful_timestamp_seconds 1783070400\n"
      );
    });

    for (const [nextComponent, expectedState] of [
      [{ status: "failed", state: "error", details: { last_success: "2026-11-02T12:00:00Z" } }, "failed"],
      [{ status: "degraded", state: "retrying", details: { last_success: "2026-11-02T12:00:00Z", consecutive_failures: 1 } }, "pending"],
      [{ status: "ok", state: "unknown", details: { last_success: "2026-11-02T12:00:00Z" } }, "pending"]
    ]) {
      component = nextComponent;
      paths.length = 0;
      await expect(probeTunnelHttp(`http://127.0.0.1:${server.port}`)).resolves.toMatchObject({ state: expectedState });
      expect(paths).toEqual(["/readyz", "/health?details=true"]);
    }
  });

  test("accepts the documented ephemeral wildcard health listener only through a local URL", () => {
    expect(() => validateTunnelHealthUrl("http://127.0.0.1:9345", {
      tunnelPid: 123,
      listenAddr: ":0"
    })).not.toThrow();
    expect(() => validateTunnelHealthUrl("http://192.168.1.10:9345", {
      tunnelPid: 123,
      listenAddr: ":0"
    })).toThrow(/loopback HTTP endpoint/);
  });
});

describe("Windows startup helper process trees", () => {
  test("accepts a successful helper exit when tree completion is unknown", async () => {
    await withPlatform("win32", async () => {
      const result = await runCancellableCommand(process.execPath, ["-e", "process.exit(0)"], { timeout: 5_000 });

      expect(result).toMatchObject({ code: 0, processTreeStatus: "unknown" });
    });
  });

  test("reports observable descendants after a helper parent exits", async () => {
    await withPlatform("win32", async () => {
      vi.useFakeTimers();
      const child = fakeCommandChild();
      const signals = [];
      const command = runCancellableCommand(process.execPath, ["-e", "process.exit(0)"], {
        platform: "win32",
        spawnProcess: () => child,
        processTreeStatus: () => "active",
        signalProcessTree: (target, signal) => signals.push([target, signal])
      });
      const rejection = expect(command).rejects.toMatchObject({ code: "ERR_PROCESS_TREE_CLEANUP" });

      closeFakeCommandChild(child, 0, null);
      await vi.advanceTimersByTimeAsync(HELPER_CLEANUP_BOUND_MS);

      await rejection;
      expect(signals.map(([, signal]) => signal)).toEqual(["SIGTERM", "SIGKILL"]);
      vi.useRealTimers();
    });
  });

  test("waits for force-termination evidence when the Windows helper closes first", async () => {
    await withPlatform("win32", async () => {
      vi.useFakeTimers();
      const child = fakeCommandChild();
      const controller = new globalThis.AbortController();
      const events = [];
      let treeStatus = "active";
      const command = runCancellableCommand(process.execPath, ["-e", "setInterval(() => {}, 1000)"], {
        signal: controller.signal,
        platform: "win32",
        spawnProcess: () => child,
        processTreeStatus: () => treeStatus,
        signalProcessTree: (target, signal) => {
          events.push(signal);
          if (signal !== "SIGKILL") return;
          globalThis.queueMicrotask(() => {
            events.push("close");
            closeFakeCommandChild(target, null, "SIGKILL");
            globalThis.queueMicrotask(() => {
              treeStatus = "verified-complete";
              events.push("verified");
            });
          });
        }
      });
      controller.abort(new Error("owner shutdown"));
      const rejection = expect(command).rejects.toMatchObject({ message: "owner shutdown" });

      await vi.advanceTimersByTimeAsync(HELPER_CLEANUP_BOUND_MS);
      await rejection;

      expect(events).toEqual(["SIGTERM", "SIGKILL", "close", "verified"]);
      vi.useRealTimers();
    });
  });

  test("fails closed when a cancelled Windows helper closes with unknown tree state", async () => {
    await withPlatform("win32", async () => {
      vi.useFakeTimers();
      const child = fakeCommandChild();
      const controller = new globalThis.AbortController();
      const signals = [];
      let treeStatus = "active";
      const command = runCancellableCommand(process.execPath, ["-e", "setInterval(() => {}, 1000)"], {
        signal: controller.signal,
        platform: "win32",
        spawnProcess: () => child,
        processTreeStatus: () => treeStatus,
        signalProcessTree: (_target, signal) => signals.push(signal)
      });
      controller.abort(new Error("owner shutdown"));
      globalThis.queueMicrotask(() => {
        treeStatus = "unknown";
        closeFakeCommandChild(child, null, "SIGTERM");
      });
      const rejection = expect(command).rejects.toMatchObject({ code: "ERR_PROCESS_TREE_CLEANUP" });

      await vi.advanceTimersByTimeAsync(HELPER_CLEANUP_BOUND_MS);
      await rejection;

      expect(signals).toEqual(["SIGTERM", "SIGKILL"]);
      vi.useRealTimers();
    });
  });

  test("fails bounded cleanup when Windows tree termination cannot be verified", async () => {
    await withPlatform("win32", async () => {
      vi.useFakeTimers();
      const child = fakeCommandChild();
      const controller = new globalThis.AbortController();
      const signals = [];
      const command = runCancellableCommand(process.execPath, ["-e", "setInterval(() => {}, 1000)"], {
        signal: controller.signal,
        platform: "win32",
        spawnProcess: () => child,
        processTreeStatus: () => "active",
        signalProcessTree: (target, signal) => signals.push(signal)
      });
      controller.abort(new Error("startup cancelled"));
      const rejection = expect(command).rejects.toMatchObject({ code: "ERR_PROCESS_TREE_CLEANUP" });
      await vi.advanceTimersByTimeAsync(HELPER_CLEANUP_BOUND_MS);

      await rejection;
      expect(signals).toEqual(["SIGTERM", "SIGKILL"]);
      vi.useRealTimers();
    });
  });
});

describe("POSIX startup helper process trees", () => {
  test("returns cleanup failure when forced termination has no completion evidence", async () => {
    vi.useFakeTimers();
    const child = fakeCommandChild();
    const controller = new globalThis.AbortController();
    const signals = [];
    let treeStatus = "active";
    const command = runCancellableCommand(process.execPath, ["-e", "setInterval(() => {}, 1000)"], {
      signal: controller.signal,
      platform: "linux",
      spawnProcess: () => child,
      processTreeStatus: () => treeStatus,
      signalProcessTree: (target, signal) => {
        signals.push(signal);
        if (signal !== "SIGKILL") return;
        treeStatus = "unknown";
        closeFakeCommandChild(target, null, "SIGKILL");
      }
    });
    controller.abort(new Error("owner shutdown"));
    const rejection = expect(command).rejects.toMatchObject({
      code: "ERR_PROCESS_TREE_CLEANUP",
      processTreeStatus: "unknown"
    });

    await vi.advanceTimersByTimeAsync(HELPER_CLEANUP_BOUND_MS);
    await rejection;

    expect(signals).toEqual(["SIGTERM", "SIGKILL"]);
    vi.useRealTimers();
  });

});

const HELPER_CLEANUP_BOUND_MS = 1_250;

function fakeCommandChild() {
  const child = new EventEmitter();
  child.pid = 4242;
  child.exitCode = null;
  child.signalCode = null;
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.kill = vi.fn();
  return child;
}

function closeFakeCommandChild(child, code, signal) {
  child.exitCode = code;
  child.signalCode = signal;
  child.stdout.end();
  child.stderr.end();
  child.emit("close", code, signal);
}

async function withPlatform(platform, operation) {
  const descriptor = Object.getOwnPropertyDescriptor(process, "platform");
  Object.defineProperty(process, "platform", { ...descriptor, value: platform });
  try {
    return await operation();
  } finally {
    Object.defineProperty(process, "platform", descriptor);
  }
}

async function makeFixture() {
  const path = await mkdtemp(join(tmpdir(), "secure-startup-test-"));
  fixtures.add(path);
  return path;
}

async function startHttpServer(handler) {
  const server = createServer((request, response) => {
    void handler(request, response);
  });
  servers.add(server);
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  return { server, port: server.address().port };
}

async function readRequestBody(request) {
  let raw = "";
  for await (const chunk of request) raw += chunk.toString();
  return raw ? JSON.parse(raw) : {};
}
