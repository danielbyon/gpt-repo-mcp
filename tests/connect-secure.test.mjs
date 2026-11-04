import { EventEmitter, once } from "node:events";
import { spawn } from "node:child_process";
import process from "node:process";
import { existsSync, watch } from "node:fs";
import { chmod, mkdir, mkdtemp, readFile, rm, stat, symlink, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, test } from "vitest";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const connectScript = join(repoRoot, "scripts", "connect-secure.mjs");
const fixtures = new Set();
const launchers = new Set();
const reservedServers = new Set();

afterEach(async () => {
  for (const launcher of launchers) await stopLauncher(launcher);
  launchers.clear();
  await Promise.all([...reservedServers].map((server) => new Promise((resolveClose) => server.close(resolveClose))));
  reservedServers.clear();
  await Promise.all([...fixtures].map((path) => rm(path, { recursive: true, force: true })));
  fixtures.clear();
});

describe("secure connector startup order", () => {
  test("waits for complete marker contents after observing an empty file", async () => {
    const fixture = await createFixture();
    const markerPath = join(fixture.root, "complete-marker");
    await writeFile(markerPath, "", "utf8");
    const child = new EventEmitter();
    child.exitCode = null;
    child.signalCode = null;
    let reads = 0;
    let resolveFirstRead;
    const firstRead = new Promise((resolveRead) => { resolveFirstRead = resolveRead; });
    const contents = ["", "ready"];
    const markerRead = async () => {
      const value = contents[reads++];
      if (reads === 1) resolveFirstRead(value);
      return value;
    };
    let notifyChange;
    let closeCount = 0;
    let watcher;
    const launcher = { child, output: () => "" };
    const waiting = waitForFile(markerPath, launcher, "ready", {
      readFile: markerRead,
      watch: (_directory, listener) => {
        notifyChange = listener;
        watcher = new EventEmitter();
        watcher.close = () => { closeCount += 1; };
        return watcher;
      }
    });

    const firstObservation = await Promise.race([
      firstRead.then((value) => ({ kind: "read", value })),
      waiting.then((value) => ({ kind: "resolved", value }))
    ]);
    expect(firstObservation).toEqual({ kind: "read", value: "" });

    notifyChange("change", "complete-marker");
    await expect(waiting).resolves.toBe("ready");
    expect(closeCount).toBe(1);
    expect(watcher.listenerCount("error")).toBe(0);
    expect(child.listenerCount("exit")).toBe(0);
  });

  test("rejects an incomplete marker if the launcher exits and cleans up the watcher", async () => {
    const fixture = await createFixture();
    const markerPath = join(fixture.root, "incomplete-marker");
    await writeFile(markerPath, "", "utf8");
    const child = new EventEmitter();
    child.exitCode = null;
    child.signalCode = null;
    let resolveRead;
    const firstRead = new Promise((resolveMarkerRead) => { resolveRead = resolveMarkerRead; });
    let closeCount = 0;
    let watcher;
    const launcher = { child, output: () => "launcher output" };
    const waiting = waitForFile(markerPath, launcher, "ready", {
      readFile: async () => {
        resolveRead("");
        return "";
      },
      watch: () => {
        watcher = new EventEmitter();
        watcher.close = () => { closeCount += 1; };
        return watcher;
      }
    });
    await firstRead;

    child.emit("exit", 7, null);

    await expect(waiting).rejects.toThrow(/exited before .* was complete[\s\S]*launcher output/);
    expect(closeCount).toBe(1);
    expect(watcher.listenerCount("error")).toBe(0);
    expect(child.listenerCount("exit")).toBe(0);
  });

  test("waits for fresh MCP discovery before launching the tunnel and reaps both managed children", async () => {
    const fixture = await createFixture();
    const launcher = startLauncher(fixture);
    try {
      await waitForFile(fixture.paths.mcpProbeMarker, launcher, "probe-seen");
      expect(existsSync(fixture.paths.tunnelStartedMarker)).toBe(false);

      await writeFile(fixture.paths.mcpReadyFile, "ready", "utf8");
      await waitForFile(fixture.paths.tunnelStartedMarker, launcher, isCompleteJsonObject);
      await waitForFile(fixture.paths.tunnelReadyMarker, launcher, "ready");
      await waitForOutput(launcher, "Secure MCP Tunnel passed readiness");

      const tunnelStart = JSON.parse(await readFile(fixture.paths.tunnelStartedMarker, "utf8"));
      expect(tunnelStart).toMatchObject({
        profile: "issue-42-test-profile",
        mcpTimeout: "2.25s",
        tunnelTimeout: "4s",
        listenAddr: "127.0.0.1:0"
      });
      expect(tunnelStart.urlFile).toContain("gpt-repo-tunnel-health-");
      expect(tunnelStart.urlFile).not.toBe(fixture.paths.mcpReadyFile);
      expect((await stat(dirname(tunnelStart.urlFile))).mode & 0o777).toBe(0o700);

      const launcherExit = once(launcher.child, "exit");
      const mcpStopped = waitForFile(fixture.paths.mcpStoppedMarker, launcher, "stopped");
      const tunnelStopped = waitForFile(fixture.paths.tunnelStoppedMarker, launcher, "stopped");
      launcher.child.kill("SIGTERM");
      const [code, signal] = await launcherExit;
      expect(code, launcher.output()).toBe(0);
      expect(signal).toBeNull();
      await expect(mcpStopped).resolves.toBe("stopped");
      await expect(tunnelStopped).resolves.toBe("stopped");
    } finally {
      await stopLauncher(launcher);
    }
  });

  test("does not let completed Windows startup helpers poison owner-requested shutdown", async () => {
    const fixture = await createFixture();
    await writeFile(fixture.paths.mcpReadyFile, "ready", "utf8");
    const nodeOptions = [process.env.NODE_OPTIONS, `--import=${fixture.paths.windowsPlatformPreload}`]
      .filter(Boolean)
      .join(" ");
    const launcher = startLauncher(fixture, {
      NODE_OPTIONS: nodeOptions,
      TEMP: tmpdir(),
      TMP: tmpdir()
    });
    try {
      await waitForOutput(launcher, "Secure MCP Tunnel passed readiness");
      const helperCalls = (await readFile(fixture.paths.tunnelHelperLog, "utf8")).trim().split("\n");
      expect(helperCalls.length).toBeGreaterThanOrEqual(3);

      const launcherExit = once(launcher.child, "exit");
      launcher.child.kill("SIGTERM");
      const [code] = await launcherExit;

      expect(code, launcher.output()).toBe(0);
      expect(launcher.output()).not.toContain("process-tree completion could not be verified after SIGKILL");
      const helperPids = helperCalls.map((line) => Number(line.split("\t").at(-1)));
      const taskkillTargets = (await readFile(fixture.paths.taskkillLog, "utf8"))
        .trim()
        .split("\n")
        .map(Number);
      expect(taskkillTargets.some((pid) => helperPids.includes(pid))).toBe(false);
    } finally {
      await stopLauncher(launcher);
    }
  }, 10_000);

  test("waits for bounded Windows helper cancellation before owner shutdown exits", async () => {
    const fixture = await createFixture();
    await writeFile(fixture.paths.mcpReadyFile, "ready", "utf8");
    const nodeOptions = [process.env.NODE_OPTIONS, `--import=${fixture.paths.windowsPlatformPreload}`]
      .filter(Boolean)
      .join(" ");
    const launcher = startLauncher(fixture, {
      NODE_OPTIONS: nodeOptions,
      TEMP: tmpdir(),
      TMP: tmpdir(),
      TUNNEL_TEST_HELP_MODE: null,
      TUNNEL_TEST_HEALTH_MODE: "hang"
    });
    try {
      const helperPid = Number(await waitForFile(fixture.paths.tunnelHelperPidMarker, launcher, isPositiveIntegerText));
      const launcherExit = once(launcher.child, "exit");
      launcher.child.kill("SIGTERM");
      const [code] = await launcherExit;

      expect(code, launcher.output()).toBe(0);
      expect(isPidRunning(helperPid)).toBe(false);
    } finally {
      await stopLauncher(launcher);
    }
  }, 10_000);

  test("probes the tokenized MCP route when only the legacy token variable is set", async () => {
    const fixture = await createFixture();
    await writeFile(fixture.paths.mcpReadyFile, "ready", "utf8");
    const launcher = startLauncher(fixture, {
      GPT_REPO_PUBLIC_PATH_TOKEN: null,
      REPO_READER_PUBLIC_PATH_TOKEN: "legacy token/42"
    });
    try {
      await waitForOutput(launcher, "Secure MCP Tunnel passed readiness");
      expect(await readFile(fixture.paths.mcpRouteMarker, "utf8")).toBe("/t/legacy%20token%2F42/mcp");
      const launcherExit = once(launcher.child, "exit");
      launcher.child.kill("SIGTERM");
      await expect(launcherExit).resolves.toEqual([0, null]);
    } finally {
      await stopLauncher(launcher);
    }
  });

  test("fails startup when the MCP child exits cleanly before binding", async () => {
    const fixture = await createFixture();
    const launcher = startLauncher(fixture, { MCP_TEST_EXIT_EARLY: "0" });
    try {
      const [code] = await waitForLauncherExit(launcher);
      expect(code, launcher.output()).not.toBe(0);
      expect(existsSync(fixture.paths.tunnelStartedMarker)).toBe(false);
      expect(launcher.output()).toContain("[mcp] exited (code=0, signal=null)");
    } finally {
      await stopLauncher(launcher);
    }
  });

  test("fails startup when the tunnel child exits cleanly before readiness", async () => {
    const fixture = await createFixture();
    await writeFile(fixture.paths.mcpReadyFile, "ready", "utf8");
    const launcher = startLauncher(fixture, { TUNNEL_TEST_EXIT_EARLY: "0" });
    try {
      await waitForFile(fixture.paths.tunnelStartedMarker, launcher, isCompleteJsonObject);
      const [code] = await waitForLauncherExit(launcher);
      expect(code, launcher.output()).not.toBe(0);
      expect(existsSync(fixture.paths.tunnelReadyMarker)).toBe(false);
      expect(launcher.output()).toContain("[tunnel] exited (code=0, signal=null)");
    } finally {
      await stopLauncher(launcher);
    }
  });

  test("accepts HEALTH_LISTEN_ADDR=:0 only after local endpoint ownership is verified", async () => {
    const fixture = await createFixture();
    await writeFile(fixture.paths.mcpReadyFile, "ready", "utf8");
    const launcher = startLauncher(fixture, { HEALTH_LISTEN_ADDR: ":0" });
    try {
      await waitForOutput(launcher, "Secure MCP Tunnel passed readiness");
      expect(JSON.parse(await readFile(fixture.paths.tunnelStartedMarker, "utf8")).listenAddr).toBe(":0");
      expect(existsSync(fixture.paths.tunnelReadyMarker)).toBe(true);
      const launcherExit = once(launcher.child, "exit");
      launcher.child.kill("SIGTERM");
      await expect(launcherExit).resolves.toEqual([0, null]);
    } finally {
      await stopLauncher(launcher);
    }
  });

  test("preserves a YAML-only fixed TCP health listener", async () => {
    const fixture = await createFixture();
    await writeFile(fixture.paths.mcpReadyFile, "ready", "utf8");
    const configuredPort = await reservePort();
    await writeFile(fixture.paths.profileFile, `health:\n  listen_addr: 127.0.0.1:${configuredPort}\n`, "utf8");
    const launcher = startLauncher(fixture, {
      HEALTH_LISTEN_ADDR: null,
      HEALTH_UNIX_SOCKET: null
    });
    try {
      await waitForOutput(launcher, "Secure MCP Tunnel passed readiness");
      expect(JSON.parse(await readFile(fixture.paths.tunnelStartedMarker, "utf8")).listenAddr)
        .toBe(`127.0.0.1:${configuredPort}`);
      const launcherExit = once(launcher.child, "exit");
      launcher.child.kill("SIGTERM");
      await expect(launcherExit).resolves.toEqual([0, null]);
    } finally {
      await stopLauncher(launcher);
    }
  });

  test("preserves a YAML-only health Unix socket", async () => {
    const fixture = await createFixture();
    await writeFile(fixture.paths.mcpReadyFile, "ready", "utf8");
    await writeFile(fixture.paths.profileFile, `health:\n  unix_socket: ${fixture.paths.healthSocket}\n`, "utf8");
    const launcher = startLauncher(fixture, {
      HEALTH_LISTEN_ADDR: null,
      HEALTH_UNIX_SOCKET: null
    });
    try {
      await waitForOutput(launcher, "Secure MCP Tunnel passed readiness");
      const tunnelStart = JSON.parse(await readFile(fixture.paths.tunnelStartedMarker, "utf8"));
      expect(tunnelStart).not.toHaveProperty("listenAddr");
      expect(tunnelStart.unixSocket).toBe(fixture.paths.healthSocket);
      const launcherExit = once(launcher.child, "exit");
      launcher.child.kill("SIGTERM");
      await expect(launcherExit).resolves.toEqual([0, null]);
    } finally {
      await stopLauncher(launcher);
    }
  });

  test("lets an explicit health environment override win over the profile YAML listener", async () => {
    const fixture = await createFixture();
    await writeFile(fixture.paths.mcpReadyFile, "ready", "utf8");
    const configuredPort = await reservePort();
    await writeFile(fixture.paths.profileFile, `health:\n  listen_addr: 127.0.0.1:${configuredPort}\n`, "utf8");
    const launcher = startLauncher(fixture, { HEALTH_LISTEN_ADDR: "127.0.0.1:0" });
    try {
      await waitForOutput(launcher, "Secure MCP Tunnel passed readiness");
      expect(JSON.parse(await readFile(fixture.paths.tunnelStartedMarker, "utf8")).listenAddr).toBe("127.0.0.1:0");
      const launcherExit = once(launcher.child, "exit");
      launcher.child.kill("SIGTERM");
      await expect(launcherExit).resolves.toEqual([0, null]);
    } finally {
      await stopLauncher(launcher);
    }
  });

  test("uses APPDATA for a Windows named profile when no higher-precedence directory is set", async () => {
    const fixture = await createFixture();
    const [appDataPort, userProfileDecoyPort] = await reservePorts(2);
    const appData = join(fixture.root, "roaming");
    const userProfile = join(fixture.root, "user-profile");
    const selectedDir = join(appData, "tunnel-client");
    const decoyDir = join(userProfile, ".config", "tunnel-client");
    const selectedProfile = await writeProfileHealth(selectedDir, appDataPort);
    await writeProfileHealth(decoyDir, userProfileDecoyPort);

    await assertProfileDirectorySelection(fixture, {
      platform: "win32",
      selectedDir,
      selectedProfile,
      port: appDataPort,
      overrides: { APPDATA: appData, USERPROFILE: userProfile }
    });
  });

  test("keeps an explicit Windows profile directory above XDG, HOME, and APPDATA", async () => {
    const fixture = await createFixture();
    const [selectedPort, xdgPort, homePort, appDataPort] = await reservePorts(4);
    const explicitDir = join(fixture.root, "explicit-profiles");
    const xdgHome = join(fixture.root, "xdg");
    const home = join(fixture.root, "home");
    const appData = join(fixture.root, "roaming");
    const selectedProfile = await writeProfileHealth(explicitDir, selectedPort);
    await writeProfileHealth(join(xdgHome, "tunnel-client"), xdgPort);
    await writeProfileHealth(join(home, ".config", "tunnel-client"), homePort);
    await writeProfileHealth(join(appData, "tunnel-client"), appDataPort);

    await assertProfileDirectorySelection(fixture, {
      platform: "win32",
      selectedDir: explicitDir,
      selectedProfile,
      port: selectedPort,
      overrides: {
        TUNNEL_CLIENT_PROFILE_DIR: explicitDir,
        XDG_CONFIG_HOME: xdgHome,
        HOME: home,
        APPDATA: appData
      }
    });
  });

  test("uses XDG_CONFIG_HOME ahead of HOME and the Windows config directory", async () => {
    const fixture = await createFixture();
    const [xdgPort, homePort, appDataPort] = await reservePorts(3);
    const xdgHome = join(fixture.root, "xdg");
    const home = join(fixture.root, "home");
    const appData = join(fixture.root, "roaming");
    const selectedDir = join(xdgHome, "tunnel-client");
    const selectedProfile = await writeProfileHealth(selectedDir, xdgPort);
    await writeProfileHealth(join(home, ".config", "tunnel-client"), homePort);
    await writeProfileHealth(join(appData, "tunnel-client"), appDataPort);

    await assertProfileDirectorySelection(fixture, {
      platform: "win32",
      selectedDir,
      selectedProfile,
      port: xdgPort,
      overrides: { XDG_CONFIG_HOME: xdgHome, HOME: home, APPDATA: appData }
    });
  });

  test("uses HOME ahead of the Windows UserConfigDir fallback", async () => {
    const fixture = await createFixture();
    const [homePort, appDataPort] = await reservePorts(2);
    const home = join(fixture.root, "home");
    const appData = join(fixture.root, "roaming");
    const selectedDir = join(home, ".config", "tunnel-client");
    const selectedProfile = await writeProfileHealth(selectedDir, homePort);
    await writeProfileHealth(join(appData, "tunnel-client"), appDataPort);

    await assertProfileDirectorySelection(fixture, {
      platform: "win32",
      selectedDir,
      selectedProfile,
      port: homePort,
      overrides: { HOME: home, APPDATA: appData }
    });
  });

  test.each(["darwin", "linux"])("preserves HOME-based profile lookup on %s", async (platform) => {
    const fixture = await createFixture();
    const [homePort, appDataPort] = await reservePorts(2);
    const home = join(fixture.root, "home");
    const appData = join(fixture.root, "roaming");
    const selectedDir = join(home, ".config", "tunnel-client");
    const selectedProfile = await writeProfileHealth(selectedDir, homePort);
    await writeProfileHealth(join(appData, "tunnel-client"), appDataPort);

    await assertProfileDirectorySelection(fixture, {
      platform,
      selectedDir,
      selectedProfile,
      port: homePort,
      overrides: { HOME: home, APPDATA: appData }
    });
  });

  test("cancels and reaps an in-flight tunnel health helper on shutdown", async () => {
    const fixture = await createFixture();
    await writeFile(fixture.paths.mcpReadyFile, "ready", "utf8");
    const launcher = startLauncher(fixture, { TUNNEL_TEST_HEALTH_MODE: "hang" });
    try {
      const helperPid = Number(await waitForFile(fixture.paths.tunnelHelperPidMarker, launcher, isPositiveIntegerText));
      const launcherExit = once(launcher.child, "exit");
      launcher.child.kill("SIGTERM");
      const [code] = await launcherExit;
      expect(code, launcher.output()).toBe(0);
      expect(isPidRunning(helperPid)).toBe(false);
    } finally {
      await stopLauncher(launcher);
    }
  });

  test("does not launch the tunnel when the configured MCP port is already occupied", async () => {
    const fixture = await createFixture();
    const occupied = createServer();
    reservedServers.add(occupied);
    await new Promise((resolveListen, reject) => {
      occupied.once("error", reject);
      occupied.listen(0, "127.0.0.1", resolveListen);
    });
    const port = occupied.address().port;
    const launcher = startLauncher(fixture, { PORT: String(port) });
    try {
      const launcherExit = once(launcher.child, "exit");
      await waitForFile(fixture.paths.mcpBindErrorMarker, launcher, isCompleteJsonObject);
      const [code] = await launcherExit;
      expect(code).not.toBe(0);
      expect(existsSync(fixture.paths.tunnelStartedMarker)).toBe(false);
    } finally {
      await stopLauncher(launcher);
    }
  });

  test("preserves caller health settings and requires its stale URL file to be refreshed", async () => {
    const fixture = await createFixture();
    const callerUrlFile = fixture.paths.callerHealthUrlFile;
    await writeFile(callerUrlFile, "http://127.0.0.1:1\n", { mode: 0o600 });
    await writeFile(fixture.paths.mcpReadyFile, "ready", "utf8");
    const launcher = startLauncher(fixture, {
      HEALTH_LISTEN_ADDR: "127.0.0.1:0",
      HEALTH_URL_FILE: callerUrlFile
    });
    try {
      await waitForFile(fixture.paths.tunnelStartedMarker, launcher, isCompleteJsonObject);
      const tunnelStart = JSON.parse(await readFile(fixture.paths.tunnelStartedMarker, "utf8"));
      expect(tunnelStart.listenAddr).toBe("127.0.0.1:0");
      expect(tunnelStart.urlFile).toBe(callerUrlFile);
      await waitForFile(fixture.paths.tunnelReadyMarker, launcher, "ready");
      expect(await readFile(callerUrlFile, "utf8")).not.toBe("http://127.0.0.1:1\n");
      await waitForOutput(launcher, "Secure MCP Tunnel passed readiness");
      const launcherExit = once(launcher.child, "exit");
      const mcpStopped = waitForFile(fixture.paths.mcpStoppedMarker, launcher, "stopped");
      const tunnelStopped = waitForFile(fixture.paths.tunnelStoppedMarker, launcher, "stopped");
      launcher.child.kill("SIGTERM");
      const [code] = await launcherExit;
      expect(code).toBe(0);
      await expect(mcpStopped).resolves.toBe("stopped");
      await expect(tunnelStopped).resolves.toBe("stopped");
    } finally {
      await stopLauncher(launcher);
    }
  });

  test("rejects a refreshed caller URL file when another process owns its endpoint", async () => {
    const fixture = await createFixture();
    await writeFile(fixture.paths.callerHealthUrlFile, "http://127.0.0.1:1\n", { mode: 0o600 });
    await writeFile(fixture.paths.mcpReadyFile, "ready", "utf8");
    const launcher = startLauncher(fixture, {
      HEALTH_LISTEN_ADDR: "127.0.0.1:0",
      HEALTH_URL_FILE: fixture.paths.callerHealthUrlFile,
      MCP_TEST_HEALTH_OWNER_MODE: "different-process"
    });
    try {
      const outcome = await Promise.race([
        waitForOutput(launcher, "Secure MCP Tunnel passed readiness").then(() => "ready"),
        once(launcher.child, "exit").then(() => "exited")
      ]);

      expect(outcome).toBe("exited");
      expect(launcher.child.exitCode).not.toBe(0);
      expect(launcher.output()).toContain("health endpoint is not owned by the newly launched tunnel process");
    } finally {
      await stopLauncher(launcher);
    }
  });

  test("rejects a different process owning the private default health endpoint", async () => {
    const fixture = await createFixture();
    await writeFile(fixture.paths.mcpReadyFile, "ready", "utf8");
    const launcher = startLauncher(fixture, { MCP_TEST_HEALTH_OWNER_MODE: "different-process" });
    try {
      const outcome = await Promise.race([
        waitForOutput(launcher, "Secure MCP Tunnel passed readiness").then(() => "ready"),
        once(launcher.child, "exit").then(() => "exited")
      ]);

      expect(outcome).toBe("exited");
      expect(launcher.child.exitCode).not.toBe(0);
      expect(launcher.output()).toContain("Tunnel health endpoint is not owned by the newly launched tunnel process.");
      expect(existsSync(fixture.paths.tunnelReadyMarker)).toBe(false);
    } finally {
      await stopLauncher(launcher);
    }
  });

  test("rejects an invalid Go duration before starting either component", async () => {
    const fixture = await createFixture();
    const launcher = startLauncher(fixture, { MCP_STARTUP_WAIT_TIMEOUT: "30 seconds" });
    const [code] = await once(launcher.child, "exit");

    expect(code).not.toBe(0);
    expect(launcher.output()).toContain("MCP_STARTUP_WAIT_TIMEOUT must use Go time.Duration syntax");
    expect(existsSync(fixture.paths.mcpBoundMarker)).toBe(false);
    expect(existsSync(fixture.paths.tunnelStartedMarker)).toBe(false);
  });

  test("resolves an env reference for the selected TCP health listener", async () => {
    const fixture = await createFixture();
    const port = await reservePort();

    const marker = await assertHealthProfileReady(
      fixture,
      "health:\n  listen_addr: EnV:ISSUE42_PROFILE_HEALTH_ADDR\n",
      {
        HEALTH_LISTEN_ADDR: null,
        HEALTH_UNIX_SOCKET: null,
        ISSUE42_PROFILE_HEALTH_ADDR: `127.0.0.1:${port}`
      },
      { listenAddr: `127.0.0.1:${port}` }
    );

    expect(marker.listenAddr).toBe(`127.0.0.1:${port}`);
  });

  test("resolves a file reference for the selected TCP health listener", async () => {
    const fixture = await createFixture();
    const port = await reservePort();
    const valueFile = join(fixture.root, "health-listen-address");
    await writeFile(valueFile, `127.0.0.1:${port}\n`, "utf8");

    const marker = await assertHealthProfileReady(
      fixture,
      `health:\n  listen_addr: file:${valueFile}\n`,
      { HEALTH_LISTEN_ADDR: null, HEALTH_UNIX_SOCKET: null },
      { listenAddr: `127.0.0.1:${port}` }
    );

    expect(marker.listenAddr).toBe(`127.0.0.1:${port}`);
  });

  test("resolves an env reference for the selected Unix health socket", async () => {
    const fixture = await createFixture();

    const marker = await assertHealthProfileReady(
      fixture,
      "health:\n  unix_socket: env:ISSUE42_PROFILE_HEALTH_SOCKET\n",
      {
        HEALTH_LISTEN_ADDR: null,
        HEALTH_UNIX_SOCKET: null,
        ISSUE42_PROFILE_HEALTH_SOCKET: fixture.paths.healthSocket
      },
      { unixSocket: fixture.paths.healthSocket }
    );

    expect(marker.unixSocket).toBe(fixture.paths.healthSocket);
  });

  test("resolves a file reference for the selected Unix health socket", async () => {
    const fixture = await createFixture();
    const valueFile = join(fixture.root, "health-unix-socket");
    await writeFile(valueFile, `${fixture.paths.healthSocket}\n`, "utf8");

    const marker = await assertHealthProfileReady(
      fixture,
      `health:\n  unix_socket: FiLe:${valueFile}\n`,
      { HEALTH_LISTEN_ADDR: null, HEALTH_UNIX_SOCKET: null },
      { unixSocket: fixture.paths.healthSocket }
    );

    expect(marker.unixSocket).toBe(fixture.paths.healthSocket);
  });

  test("keeps the direct health environment override above a valid profile reference", async () => {
    const fixture = await createFixture();
    const profilePort = await reservePort();
    const overridePort = await reservePort();

    const marker = await assertHealthProfileReady(
      fixture,
      "health:\n  listen_addr: env:ISSUE42_PROFILE_HEALTH_ADDR\n",
      {
        HEALTH_LISTEN_ADDR: `127.0.0.1:${overridePort}`,
        HEALTH_UNIX_SOCKET: null,
        ISSUE42_PROFILE_HEALTH_ADDR: `127.0.0.1:${profilePort}`
      },
      { listenAddr: `127.0.0.1:${overridePort}` }
    );

    expect(marker.listenAddr).toBe(`127.0.0.1:${overridePort}`);
  });

  test("rejects a missing TCP profile reference before applying an environment override", async () => {
    const fixture = await createFixture();
    await expectHealthProfileRejected(
      fixture,
      "health:\n  listen_addr: env:ISSUE42_MISSING_HEALTH_ADDR\n",
      { HEALTH_LISTEN_ADDR: "127.0.0.1:0", HEALTH_UNIX_SOCKET: null },
      "health.listen_addr",
      "ISSUE42_MISSING_HEALTH_ADDR"
    );
  });

  test("rejects an unreadable Unix socket file reference without exposing its path", async () => {
    const fixture = await createFixture();
    const missingValueFile = join(fixture.root, "private-health-value");
    await expectHealthProfileRejected(
      fixture,
      `health:\n  unix_socket: file:${missingValueFile}\n`,
      { HEALTH_LISTEN_ADDR: null, HEALTH_UNIX_SOCKET: fixture.paths.healthSocket },
      "health.unix_socket",
      missingValueFile
    );
  });

  test("rejects a missing Unix socket environment reference before applying an override", async () => {
    const fixture = await createFixture();
    const variableName = "ISSUE42_MISSING_HEALTH_SOCKET";
    await expectHealthProfileRejected(
      fixture,
      `health:\n  unix_socket: env:${variableName}\n`,
      { HEALTH_LISTEN_ADDR: null, HEALTH_UNIX_SOCKET: fixture.paths.healthSocket, [variableName]: null },
      "health.unix_socket",
      variableName
    );
  });

  test("rejects an invalid referenced TCP address without logging its resolved value", async () => {
    const fixture = await createFixture();
    const privateValue = "private-health-address";
    await expectHealthProfileRejected(
      fixture,
      "health:\n  listen_addr: env:ISSUE42_INVALID_HEALTH_ADDR\n",
      {
        HEALTH_LISTEN_ADDR: null,
        HEALTH_UNIX_SOCKET: null,
        ISSUE42_INVALID_HEALTH_ADDR: `${privateValue}\ninvalid`
      },
      "health.listen_addr",
      privateValue
    );
  });
});

async function assertHealthProfileReady(fixture, profile, overrides, expected) {
  await writeFile(fixture.paths.mcpReadyFile, "ready", "utf8");
  await writeFile(fixture.paths.profileFile, profile, "utf8");
  const launcher = startLauncher(fixture, overrides);
  try {
    const outcome = await Promise.race([
      waitForOutput(launcher, "Secure MCP Tunnel passed readiness").then(() => "ready"),
      once(launcher.child, "exit").then(() => "exited")
    ]);
    expect(outcome).toBe("ready");
    const marker = JSON.parse(await readFile(fixture.paths.tunnelStartedMarker, "utf8"));
    expect(marker).toMatchObject(expected);
    return marker;
  } finally {
    await stopLauncher(launcher);
  }
}

async function expectHealthProfileRejected(fixture, profile, overrides, field, hiddenValue) {
  await writeFile(fixture.paths.mcpReadyFile, "ready", "utf8");
  await writeFile(fixture.paths.profileFile, profile, "utf8");
  const launcher = startLauncher(fixture, overrides);
  try {
    const [code] = await once(launcher.child, "close");
    expect(code).not.toBe(0);
    expect(launcher.output()).toContain(field);
    expect(launcher.output()).not.toContain(hiddenValue);
    expect(existsSync(fixture.paths.tunnelStartedMarker)).toBe(false);
  } finally {
    await stopLauncher(launcher);
  }
}

async function createFixture() {
  const root = await mkdtemp(join(tmpdir(), "connect-secure-startup-"));
  fixtures.add(root);
  const bin = join(root, "bin");
  await mkdir(bin);
  await mkdir(join(root, "profiles"));
  const paths = {
    config: join(root, "config.json"),
    mcpReadyFile: join(root, "mcp-ready"),
    mcpBoundMarker: join(root, "mcp-bound.json"),
    mcpProbeMarker: join(root, "mcp-probe"),
    mcpRouteMarker: join(root, "mcp-route"),
    mcpBindErrorMarker: join(root, "mcp-bind-error.json"),
    mcpStoppedMarker: join(root, "mcp-stopped"),
    callerHealthUrlFile: join(root, "caller-health.url"),
    profileDir: join(root, "profiles"),
    profileFile: join(root, "profiles", "issue-42-test-profile.yaml"),
    healthSocket: join(root, "health.sock"),
    tunnelStartedMarker: join(root, "tunnel-started.json"),
    tunnelReadyMarker: join(root, "tunnel-ready"),
    tunnelHelperLog: join(root, "tunnel-helper-calls.log"),
    taskkillLog: join(root, "taskkill-targets.log"),
    tunnelHelperPidMarker: join(root, "tunnel-health-helper.pid"),
    tunnelStoppedMarker: join(root, "tunnel-stopped"),
    windowsPlatformPreload: join(root, "simulate-windows-platform.mjs")
  };
  await writeFile(paths.config, JSON.stringify({ repos: [], limits: {} }), "utf8");
  const npmScript = join(bin, "npm.mjs");
  const lsofScript = join(bin, "lsof.mjs");
  const taskkillScript = join(bin, "taskkill.mjs");
  const powershellScript = join(bin, "powershell.mjs");
  const tunnelClient = join(root, "tunnel-client.mjs");
  await writeFile(npmScript, fakeNpmSource(), { mode: 0o755 });
  await writeFile(lsofScript, fakeLsofSource(), { mode: 0o755 });
  await writeFile(taskkillScript, fakeTaskkillSource(), { mode: 0o755 });
  await writeFile(powershellScript, fakePowershellSource(), { mode: 0o755 });
  await writeFile(paths.windowsPlatformPreload, windowsPlatformPreloadSource(), "utf8");
  await writeFile(tunnelClient, fakeTunnelClientSource(), { mode: 0o755 });
  await chmod(npmScript, 0o755);
  await chmod(lsofScript, 0o755);
  await chmod(taskkillScript, 0o755);
  await chmod(powershellScript, 0o755);
  await chmod(tunnelClient, 0o755);
  await symlink(npmScript, join(bin, "npm"));
  await symlink(lsofScript, join(bin, "lsof"));
  await symlink(taskkillScript, join(bin, "taskkill.exe"));
  await symlink(powershellScript, join(bin, "powershell.exe"));
  return { root, bin, paths, tunnelClient };
}

function startLauncher(fixture, overrides = {}) {
  let output = "";
  const env = {
    ...process.env,
    PATH: `${fixture.bin}:${process.env.PATH ?? ""}`,
    CONTROL_PLANE_API_KEY: "synthetic-test-key",
    GPT_REPO_CONFIG: fixture.paths.config,
    GPT_REPO_PUBLIC_PATH_TOKEN: "route token/42",
    PORT: "0",
    MCP_STARTUP_WAIT_TIMEOUT: "2.25s",
    TUNNEL_STARTUP_WAIT_TIMEOUT: "4s",
    TUNNEL_CLIENT_PROFILE: "issue-42-test-profile",
    TUNNEL_CLIENT_PROFILE_DIR: fixture.paths.profileDir,
    TUNNEL_CLIENT_BIN: fixture.tunnelClient,
    MCP_TEST_READY_FILE: fixture.paths.mcpReadyFile,
    MCP_TEST_BOUND_MARKER: fixture.paths.mcpBoundMarker,
    MCP_TEST_PROBE_MARKER: fixture.paths.mcpProbeMarker,
    MCP_TEST_ROUTE_MARKER: fixture.paths.mcpRouteMarker,
    MCP_TEST_BIND_ERROR_MARKER: fixture.paths.mcpBindErrorMarker,
    MCP_TEST_STOP_MARKER: fixture.paths.mcpStoppedMarker,
    TUNNEL_TEST_START_MARKER: fixture.paths.tunnelStartedMarker,
    TUNNEL_TEST_HELPER_LOG: fixture.paths.tunnelHelperLog,
    TUNNEL_TEST_TASKKILL_LOG: fixture.paths.taskkillLog,
    TUNNEL_TEST_READY_MARKER: fixture.paths.tunnelReadyMarker,
    TUNNEL_TEST_HELPER_PID_MARKER: fixture.paths.tunnelHelperPidMarker,
    TUNNEL_TEST_STOP_MARKER: fixture.paths.tunnelStoppedMarker,
    ...overrides
  };
  for (const [key, value] of Object.entries(overrides)) {
    if (value === null) delete env[key];
  }
  const child = spawn(process.execPath, [connectScript], {
    cwd: fixture.root,
    env,
    stdio: ["ignore", "pipe", "pipe"]
  });
  child.stdout.on("data", (chunk) => { output += chunk.toString(); });
  child.stderr.on("data", (chunk) => { output += chunk.toString(); });
  const launcher = { child, output: () => output, fixture };
  launchers.add(launcher);
  return launcher;
}

function fakeNpmSource() {
  return `#!/usr/bin/env node
import { existsSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";

const host = process.env.GPT_REPO_HOST || "127.0.0.1";
const port = Number(process.env.PORT);
const readyFile = process.env.MCP_TEST_READY_FILE;
if (process.env.MCP_TEST_EXIT_EARLY === "0") process.exit(0);
const effectiveToken = process.env.GPT_REPO_PUBLIC_PATH_TOKEN ?? process.env.REPO_READER_PUBLIC_PATH_TOKEN;
const route = effectiveToken ? "/t/" + encodeURIComponent(effectiveToken) + "/mcp" : "/mcp";
const sessionId = "isolated-startup-probe-session";
const server = createServer(async (request, response) => {
  writeFileSync(process.env.MCP_TEST_ROUTE_MARKER, request.url);
  let raw = "";
  for await (const chunk of request) raw += chunk.toString();
  if (request.url !== route) { response.writeHead(404).end(); return; }
  if (request.method === "DELETE") { response.writeHead(200).end(); return; }
  const body = raw ? JSON.parse(raw) : {};
  if (body.method === "initialize") {
    if (!existsSync(readyFile)) {
      writeFileSync(process.env.MCP_TEST_PROBE_MARKER, "probe-seen");
      response.writeHead(503).end();
      return;
    }
    response.writeHead(200, { "content-type": "application/json", "mcp-session-id": sessionId });
    response.end(JSON.stringify({ jsonrpc: "2.0", id: body.id, result: { protocolVersion: "2025-03-26" } }));
    return;
  }
  if (body.method === "notifications/initialized") { response.writeHead(202).end(); return; }
  if (body.method === "tools/list") {
    response.writeHead(200, { "content-type": "application/json", "mcp-session-id": sessionId });
    response.end(JSON.stringify({ jsonrpc: "2.0", id: body.id, result: { tools: [{ name: "repo_list_roots" }] } }));
    return;
  }
  response.writeHead(400).end();
});
process.on("SIGTERM", () => {
  writeFileSync(process.env.MCP_TEST_STOP_MARKER, "stopped");
  server.close(() => process.exit(0));
});
server.once("error", (error) => {
  writeFileSync(process.env.MCP_TEST_BIND_ERROR_MARKER, JSON.stringify({ pid: process.pid, code: error.code }));
  process.exit(1);
});
server.listen(port, host, () => {
  const address = server.address();
  const actualPort = typeof address === "object" ? address.port : port;
  const urlHost = host.includes(":") ? "[" + host + "]" : host;
  const displayRoute = effectiveToken ? "/t/[token]/mcp" : "/mcp";
  writeFileSync(process.env.MCP_TEST_BOUND_MARKER, JSON.stringify({ pid: process.pid, port: actualPort }));
  process.stderr.write("gpt-repo-mcp listening on http://" + urlHost + ":" + actualPort + displayRoute + "\\n");
});
`;
}

function fakeTunnelClientSource() {
  return `#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { existsSync } from "node:fs";
import { join, resolve } from "node:path";

const args = process.argv.slice(2);
if (args[0] !== "run") writeFileSync(process.env.TUNNEL_TEST_HELPER_LOG, args.slice(0, 2).join(" ") + "\\t" + process.pid + "\\n", { flag: "a" });
if (args[0] === "health" && args[1] === "--help") {
  if (process.env.TUNNEL_TEST_HELP_MODE === "hang") {
    writeFileSync(process.env.TUNNEL_TEST_HELPER_PID_MARKER, String(process.pid));
    process.on("SIGTERM", () => {});
    setInterval(() => {}, 1000);
    await new Promise(() => {});
  }
  process.stdout.write("Usage:\\n  tunnel-client health [flags]\\n--json --require-control-plane-poll --pid --url-file\\n");
  process.exit(0);
}

if (args[0] === "run" && args[1] === "--help") {
  process.stdout.write("HEALTH_LISTEN_ADDR HEALTH_URL_FILE\\n");
  process.exit(0);
}
if (args[0] === "health") {
  if (process.env.TUNNEL_TEST_HEALTH_MODE === "hang") {
    writeFileSync(process.env.TUNNEL_TEST_HELPER_PID_MARKER, String(process.pid));
    process.on("SIGTERM", () => {});
    setInterval(() => {}, 1000);
    await new Promise(() => {});
  }
  const pid = Number(args[args.indexOf("--pid") + 1]);
  const urlFile = args[args.indexOf("--url-file") + 1];
  const baseUrl = readFileSync(urlFile, "utf8").trim();
  const result = { process: { pid, running: true }, base_url: baseUrl, healthz: { ok: true }, readyz: { ok: true }, control_plane_poll: { ok: true, value: 1 }, result: "ok" };
  writeFileSync(process.env.TUNNEL_TEST_READY_MARKER, "ready");
  process.stdout.write(JSON.stringify(result));
  process.exit(0);
}
if (args[0] !== "run") process.exit(64);
if (process.env.TUNNEL_TEST_EXIT_EARLY === "0") {
  writeFileSync(process.env.TUNNEL_TEST_START_MARKER, JSON.stringify({ pid: process.pid }));
  process.exit(0);
}

const profile = args[args.indexOf("--profile") + 1];
const explicitProfileDir = process.env.TUNNEL_CLIENT_PROFILE_DIR?.trim();
const xdgConfigHome = process.env.XDG_CONFIG_HOME?.trim();
const home = process.env.HOME?.trim();
const configHome = xdgConfigHome || (home ? join(home, ".config") : process.platform === "win32" ? process.env.APPDATA : undefined);
if (!explicitProfileDir && !configHome) throw new Error("Test tunnel profile directory is not configured.");
const profileDir = explicitProfileDir || join(configHome, "tunnel-client");
const profilePath = process.env.TUNNEL_CLIENT_PROFILE_FILE || process.env.TUNNEL_CLIENT_CONFIG || join(profileDir, profile + ".yaml");
const yaml = existsSync(profilePath) ? readFileSync(profilePath, "utf8") : "";
const yamlSetting = (name) => yaml.match(new RegExp("^\\\\s*" + name + ":\\\\s*([^\\\\r\\\\n#]+)", "m"))?.[1]?.trim();
const resolveYamlSetting = (raw) => {
 if (!raw) return undefined;
 const value = raw.trim();
 const lower = value.toLowerCase();
 let resolved = value;
 if (lower.startsWith("env:")) {
  const name = value.slice(4).trim();
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name) || !process.env[name]?.trim()) throw new Error("Invalid test health reference.");
  resolved = process.env[name].trim();
 } else if (lower.startsWith("file:")) {
  const path = value.slice(5).trim();
  try { resolved = readFileSync(path, "utf8").trim(); } catch { throw new Error("Invalid test health reference."); }
 }
 if (!resolved || resolved.includes(String.fromCharCode(10)) || resolved.includes(String.fromCharCode(13))) throw new Error("Invalid test health reference.");
 return resolved;
};
const profileListener = resolveYamlSetting(yamlSetting("listen_addr"));
const profileSocket = resolveYamlSetting(yamlSetting("unix_socket"));
const listener = process.env.HEALTH_LISTEN_ADDR || profileListener;
const socket = process.env.HEALTH_UNIX_SOCKET || profileSocket;
const effectiveListener = listener || (!socket ? "127.0.0.1:0" : undefined);
const separator = effectiveListener?.lastIndexOf(":") ?? -1;
const host = effectiveListener?.slice(0, separator).replace(/^\\\\[|\\\\]$/g, "") || "127.0.0.1";
const port = effectiveListener ? Number(effectiveListener.slice(separator + 1)) : undefined;
const server = createServer((request, response) => {
  if (request.url === "/healthz") { response.writeHead(200).end("live"); return; }
  if (request.url === "/readyz") { response.writeHead(200).end("ready"); return; }
  if (request.url === "/metrics") {
    const newline = String.fromCharCode(10);
    response.writeHead(200, { "content-type": "text/plain" });
    response.end(["# TYPE commands_poll_last_successful_timestamp_seconds gauge", "commands_poll_last_successful_timestamp_seconds 1"].join(newline) + newline);
    return;
  }
  response.writeHead(404).end();
});
process.on("SIGTERM", () => {
  writeFileSync(process.env.TUNNEL_TEST_STOP_MARKER, "stopped");
  server.close(() => process.exit(0));
});
writeFileSync(process.env.TUNNEL_TEST_START_MARKER, JSON.stringify({
  pid: process.pid,
  profile: args[args.indexOf("--profile") + 1],
  profilePath: resolve(profilePath),
  mcpTimeout: process.env.MCP_STARTUP_WAIT_TIMEOUT,
  tunnelTimeout: process.env.TUNNEL_STARTUP_WAIT_TIMEOUT,
  listenAddr: listener,
  unixSocket: socket,
  urlFile: process.env.HEALTH_URL_FILE
}));
server.once("error", () => process.exit(2));
server.listen(socket || port, socket ? undefined : host, () => {
  const address = server.address();
  const resolvedUrl = socket ? "http://127.0.0.1" : "http://127.0.0.1:" + (typeof address === "object" ? address.port : port);
  writeFileSync(process.env.HEALTH_URL_FILE, resolvedUrl + "\\n", { mode: 0o600 });
});
`;
}

function fakeLsofSource() {
  return `#!/usr/bin/env node
import { readFileSync } from "node:fs";
const args = process.argv.slice(2);
const pidIndex = args.indexOf("-p");
const requestedPid = Number(args[pidIndex + 1]);
const pid = process.env.MCP_TEST_HEALTH_OWNER_MODE === "different-process" ? requestedPid + 1 : requestedPid;
const name = args.includes("-U")
  ? JSON.parse(readFileSync(process.env.TUNNEL_TEST_START_MARKER, "utf8")).unixSocket
  : "127.0.0.1:" + Number(args.find((argument) => argument.startsWith("-iTCP:"))?.slice("-iTCP:".length));
process.stdout.write("p" + pid + "\\ntIPv4\\nn" + name + "\\n");
`;
}

function windowsPlatformPreloadSource(platform = "win32") {
  return `const descriptor = Object.getOwnPropertyDescriptor(process, "platform");
Object.defineProperty(process, "platform", { ...descriptor, value: ${JSON.stringify(platform)} });
`;
}

function fakeTaskkillSource() {
  return `#!/bin/sh
pid=
forced=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    /PID) shift; pid="$1" ;;
    /F) forced=true ;;
  esac
  shift
done
printf '%s\\n' "$pid" >> "$TUNNEL_TEST_TASKKILL_LOG"
if [ "$forced" = true ] && kill -0 "$pid" 2>/dev/null; then
  kill -KILL "$pid" 2>/dev/null || exit 1
fi
`;
}

function fakePowershellSource() {
  return `#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
const start = JSON.parse(readFileSync(process.env.TUNNEL_TEST_START_MARKER, "utf8"));
const url = new URL(readFileSync(start.urlFile, "utf8").trim());
const pid = start.pid;
writeFileSync(process.env.TUNNEL_TEST_HELPER_LOG, "powershell\\t" + process.pid + "\\n", { flag: "a" });
process.stdout.write(JSON.stringify({ LocalAddress: url.hostname, LocalPort: Number(url.port), OwningProcess: pid }));
`;
}

async function reservePort() {
  const server = createServer();
  await new Promise((resolveListen, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolveListen);
  });
  const port = server.address().port;
  await new Promise((resolveClose, reject) => server.close((error) => error ? reject(error) : resolveClose()));
  return port;
}

async function reservePorts(count) {
  const servers = Array.from({ length: count }, () => createServer());
  await Promise.all(servers.map((server) => new Promise((resolveListen, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolveListen);
  })));
  const ports = servers.map((server) => server.address().port);
  await Promise.all(servers.map((server) => new Promise((resolveClose, reject) => {
    server.close((error) => error ? reject(error) : resolveClose());
  })));
  return ports;
}

async function writeProfileHealth(profileDir, port) {
  await mkdir(profileDir, { recursive: true });
  const profilePath = join(profileDir, "issue-42-test-profile.yaml");
  await writeFile(profilePath, `health:\n  listen_addr: 127.0.0.1:${port}\n`, "utf8");
  return profilePath;
}

async function assertProfileDirectorySelection(fixture, { platform, selectedDir, selectedProfile, port, overrides }) {
  await writeFile(fixture.paths.mcpReadyFile, "ready", "utf8");
  let preloadPath = fixture.paths.windowsPlatformPreload;
  if (platform !== "win32") {
    preloadPath = join(fixture.root, `simulate-${platform}-platform.mjs`);
    await writeFile(preloadPath, windowsPlatformPreloadSource(platform), "utf8");
  }
  const nodeOptions = [process.env.NODE_OPTIONS, `--import=${preloadPath}`].filter(Boolean).join(" ");
  const launcher = startLauncher(fixture, {
    NODE_OPTIONS: nodeOptions,
    TEMP: tmpdir(),
    TMP: tmpdir(),
    TUNNEL_CLIENT_PROFILE_DIR: null,
    TUNNEL_CLIENT_PROFILE_FILE: null,
    TUNNEL_CLIENT_CONFIG: null,
    XDG_CONFIG_HOME: null,
    HOME: null,
    HEALTH_LISTEN_ADDR: null,
    HEALTH_UNIX_SOCKET: null,
    ...overrides
  });
  try {
    await waitForOutput(launcher, "Secure MCP Tunnel passed readiness");
    const tunnelStart = JSON.parse(await readFile(fixture.paths.tunnelStartedMarker, "utf8"));
    expect(tunnelStart.profile).toBe("issue-42-test-profile");
    expect(tunnelStart.profilePath).toBe(selectedProfile);
    expect(tunnelStart.listenAddr).toBe(`127.0.0.1:${port}`);
    expect(tunnelStart.listenAddr).not.toBe("127.0.0.1:0");
    expect(selectedDir).toBe(dirname(selectedProfile));
    const launcherExit = once(launcher.child, "exit");
    launcher.child.kill("SIGTERM");
    await expect(launcherExit).resolves.toEqual([0, null]);
  } finally {
    await stopLauncher(launcher);
  }
}

function waitForLauncherExit(launcher) {
  if (launcher.child.exitCode !== null) return Promise.resolve([launcher.child.exitCode, null]);
  if (launcher.child.signalCode !== null) return Promise.resolve([null, launcher.child.signalCode]);
  return once(launcher.child, "exit");
}

function isCompleteJsonObject(contents) {
  try {
    const value = JSON.parse(contents);
    return value !== null && typeof value === "object" && !Array.isArray(value);
  } catch {
    return false;
  }
}

function isPositiveIntegerText(contents) {
  return /^[1-9]\d*$/.test(contents.trim());
}

async function waitForFile(path, launcher, expected, dependencies = {}) {
  if (typeof expected !== "string" && typeof expected !== "function") {
    throw new TypeError("waitForFile requires expected marker contents or a predicate");
  }
  const matchesExpected = typeof expected === "function" ? expected : (contents) => contents === expected;
  const readMarker = dependencies.readFile ?? readFile;
  const watchMarker = dependencies.watch ?? watch;

  return new Promise((resolveRead, reject) => {
    let settled = false;
    let reading = false;
    let readAgain = false;
    let exitDetails;
    let watcher;
    let onWatcherError;

    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      launcher?.child.off("exit", onExit);
      let finalError = error;
      try {
        watcher?.off("error", onWatcherError);
        watcher?.close();
      } catch (closeError) {
        finalError ??= closeError;
      }
      if (finalError) reject(finalError);
      else resolveRead(value);
    };

    const incompleteError = () => new Error(
      `Launcher exited before ${path} was complete (code=${exitDetails.code}, signal=${exitDetails.signal}).\n${launcher.output()}`
    );

    const readAndCheck = async () => {
      try {
        const contents = await readMarker(path, "utf8");
        if (matchesExpected(contents)) {
          finish(undefined, contents);
        } else if (exitDetails && !readAgain) {
          finish(incompleteError());
        }
      } catch (error) {
        if (error?.code === "ENOENT") {
          if (exitDetails && !readAgain) finish(incompleteError());
        } else {
          finish(error);
        }
      }
    };

    const runRequestedReads = async () => {
      try {
        do {
          readAgain = false;
          await readAndCheck();
        } while (readAgain && !settled);
      } finally {
        reading = false;
        if (readAgain && !settled) requestRead();
      }
    };

    const requestRead = () => {
      if (settled) return;
      if (reading) {
        readAgain = true;
        return;
      }
      reading = true;
      void runRequestedReads();
    };

    const onExit = (code, signal) => {
      exitDetails = { code, signal };
      requestRead();
    };
    onWatcherError = (error) => finish(error);

    try {
      watcher = watchMarker(dirname(path), () => requestRead());
      watcher.on("error", onWatcherError);
      launcher?.child.once("exit", onExit);
      if (launcher?.child.exitCode !== null || launcher?.child.signalCode !== null) {
        onExit(launcher.child.exitCode, launcher.child.signalCode);
      }
      requestRead();
    } catch (error) {
      finish(error);
    }
  });
}

async function waitForOutput(launcher, fragment) {
  if (launcher.output().includes(fragment)) return;
  await new Promise((resolveOutput) => {
    const check = () => {
      if (!launcher.output().includes(fragment)) return;
      launcher.child.stdout.off("data", check);
      launcher.child.stderr.off("data", check);
      resolveOutput();
    };
    launcher.child.stdout.on("data", check);
    launcher.child.stderr.on("data", check);
    check();
  });
}

async function stopLauncher(launcher) {
  const { child, fixture } = launcher;
  if (child.exitCode === null && child.signalCode === null) {
    const exited = once(child, "exit");
    child.kill("SIGTERM");
    await exited;
  }
  for (const markerPath of [fixture.paths.mcpBoundMarker, fixture.paths.tunnelStartedMarker]) {
    try {
      const marker = JSON.parse(await readFile(markerPath, "utf8"));
      if (process.platform !== "win32") {
        try { process.kill(-marker.pid, "SIGKILL"); } catch (error) { if (error?.code !== "ESRCH") throw error; }
      }
    } catch (error) {
      if (error?.code !== "ENOENT" && !(error instanceof SyntaxError)) throw error;
    }
  }
}

function isPidRunning(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if (error?.code === "ESRCH") return false;
    throw error;
  }
}
