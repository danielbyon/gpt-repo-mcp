import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { describe, expect, test } from "vitest";
import { runProcessWithTail } from "../src/services/process-exec.js";
import { runWindowsProcessWithTail } from "../src/services/windows-process-host.js";

const READY_TIMEOUT_MS = 3_000;
const PROCESS_GONE_TIMEOUT_MS = 2_000;
const baseInput = {
  env: process.env,
  tail_bytes: 1_024
};

type Invocation = {
  controller: AbortController;
  execution: ReturnType<typeof runProcessWithTail>;
};

const posixTest = process.platform === "win32" ? test.skip : test;
const windowsTest = process.platform === "win32" ? test : test.skip;

describe("runProcessWithTail", () => {
  test("captures bounded output from a normal exit", async () => {
    const result = await runProcessWithTail({
      ...baseInput,
      executable: process.execPath,
      args: ["-e", "process.stdout.write('before-after'); process.stderr.write('warning');"],
      cwd: process.cwd(),
      timeout_ms: 2_000,
      tail_bytes: 5
    });

    expect(result).toMatchObject({
      exit_code: 0,
      timed_out: false,
      cancelled: false,
      stdout_tail: "after",
      stderr_tail: "rning"
    });
  });

  test("preserves argument boundaries for spaces, quotes, backslashes, and Unicode", async () => {
    const argumentsWithSpecialCharacters = ["two words", "quote\"inside", "C:\\work path\\tail\\", "snowman ☃"];
    const result = await runProcessWithTail({
      ...baseInput,
      executable: process.execPath,
      args: ["-e", "process.stdout.write(JSON.stringify(process.argv.slice(1)))", ...argumentsWithSpecialCharacters],
      cwd: process.cwd(),
      timeout_ms: 2_000
    });

    expect(result.exit_code).toBe(0);
    expect(JSON.parse(result.stdout_tail)).toEqual(argumentsWithSpecialCharacters);
  });

  windowsTest("runs the npm command shim through the managed host", async () => {
    const result = await runProcessWithTail({
      ...baseInput,
      executable: "npm",
      args: ["--version"],
      cwd: process.cwd(),
      timeout_ms: 5_000
    });

    expect(result).toMatchObject({
      timed_out: false,
      cancelled: false,
      cleanup_confirmed: true
    });
    expect(result.exit_code).toBe(0);
    expect(result.stdout_tail.trim()).toMatch(/^\d+\.\d+\.\d+/);
  }, 7_000);

  windowsTest("keeps completed command status when abort arrives after the host result", async () => {
    const controller = new AbortController();
    const sourceSignal = controller.signal;
    let abortIssued = false;
    const signal = {
      get aborted() { return sourceSignal.aborted; },
      throwIfAborted: sourceSignal.throwIfAborted.bind(sourceSignal),
      addEventListener: sourceSignal.addEventListener.bind(sourceSignal),
      removeEventListener(type: string, listener: EventListenerOrEventListenerObject, options?: boolean | EventListenerOptions) {
        sourceSignal.removeEventListener(type, listener, options);
        if (type === "abort" && !abortIssued) {
          abortIssued = true;
          controller.abort();
        }
      }
    } as AbortSignal;

    const result = await runProcessWithTail({
      ...baseInput,
      executable: process.execPath,
      args: ["-e", "process.stdout.write('finished')"],
      cwd: process.cwd(),
      timeout_ms: 2_000,
      signal
    });

    expect(abortIssued).toBe(true);
    expect(result).toMatchObject({
      exit_code: 0,
      cancelled: false,
      timed_out: false,
      cleanup_confirmed: true,
      stdout_tail: "finished"
    });
  }, 5_000);

  windowsTest("preserves backslashes in quoted Windows target arguments", async () => {
    const root = await mkdtemp(join(tmpdir(), "gpt-windows-argv-"));
    const pathArgument = join(root, "nested folder", "file.txt");
    const trailingBackslashArgument = `${root}\\nested folder\\`;
    try {
      const result = await runTestWindowsHost({
        executable: process.execPath,
        args: ["-e", "process.stdout.write(JSON.stringify(process.argv.slice(1)))", pathArgument, trailingBackslashArgument],
        cwd: root,
        env: process.env,
        timeout_ms: 2_000,
        tail_bytes: 1_024
      });

      expect(result).toMatchObject({ exit_code: 0, cleanup_confirmed: true });
      expect(JSON.parse(result.stdout_tail)).toEqual([pathArgument, trailingBackslashArgument]);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 5_000);

  test("does not retroactively cancel command completion accepted first", async () => {
    const controller = new AbortController();
    const result = await runProcessWithTail({
      ...baseInput,
      executable: process.execPath,
      args: ["-e", "process.stdout.write('complete');"],
      cwd: process.cwd(),
      timeout_ms: 2_000,
      signal: controller.signal
    });
    controller.abort();

    expect(result).toMatchObject({ exit_code: 0, cancelled: false, timed_out: false, stdout_tail: "complete" });
  });

  posixTest("reaps a process-group descendant after command completion when it closes its pipes", async () => {
    const root = await mkdtemp(join(tmpdir(), "gpt-process-completion-child-"));
    const pidPath = join(root, "descendant.pid");
    const readyPath = join(root, "descendant.ready");
    const cleanupPath = join(root, "cleanup");
    const descendantScript = [
      "const { existsSync, writeFileSync } = require('node:fs');",
      `writeFileSync(${JSON.stringify(readyPath)}, String(process.pid));`,
      `setInterval(() => { if (existsSync(${JSON.stringify(cleanupPath)})) process.exit(0); }, 20);`
    ].join(" ");
    const parentScript = [
      "const { spawn } = require('node:child_process');",
      "const { existsSync, writeFileSync } = require('node:fs');",
      `const descendant = spawn(process.execPath, ['-e', ${JSON.stringify(descendantScript)}], { stdio: 'ignore' });`,
      "descendant.unref();",
      `const timer = setInterval(() => { if (existsSync(${JSON.stringify(readyPath)})) { clearInterval(timer); writeFileSync(${JSON.stringify(pidPath)}, String(descendant.pid)); process.exit(0); } }, 10);`
    ].join(" ");
    const execution = runProcessWithTail({
      ...baseInput,
      executable: process.execPath,
      args: ["-e", parentScript],
      cwd: root,
      timeout_ms: 20_000
    });
    let descendantPid: number | undefined;

    try {
      descendantPid = Number(await waitForFile(pidPath, 15_000));
      await waitForFile(readyPath, 15_000);
      const result = await execution;

      expect(result).toMatchObject({ exit_code: 0, cancelled: false, timed_out: false });
      await expectProcessGone(descendantPid);
      expect(result.cleanup_confirmed).toBe(true);
    } finally {
      await writeFile(cleanupPath, "stop").catch(() => undefined);
      if (descendantPid) {
        await expectProcessGone(descendantPid).catch(() => {
          try { process.kill(descendantPid!, "SIGKILL"); } catch { /* The child may already have exited. */ }
        });
      }
      await execution.catch(() => undefined);
      await rm(root, { recursive: true, force: true });
    }
  }, 30_000);

  posixTest("marks cleanup unconfirmed when the process-group anchor exits unexpectedly", async () => {
    const root = await mkdtemp(join(tmpdir(), "gpt-process-anchor-exit-"));
    const pidPath = join(root, "command.pid");
    const pidTempPath = join(root, "command.pid.tmp");
    const cleanupPath = join(root, "cleanup");
    const script = [
      "const { existsSync, renameSync, writeFileSync } = require('node:fs');",
      `writeFileSync(${JSON.stringify(pidTempPath)}, JSON.stringify({ pid: process.pid, parent: process.ppid }));`,
      `renameSync(${JSON.stringify(pidTempPath)}, ${JSON.stringify(pidPath)});`,
      `setInterval(() => { if (existsSync(${JSON.stringify(cleanupPath)})) process.exit(0); }, 20);`
    ].join(" ");
    const execution = runProcessWithTail({
      ...baseInput,
      executable: process.execPath,
      args: ["-e", script],
      cwd: root,
      timeout_ms: 12_000
    });
    let commandPid: number | undefined;

    try {
      const identity = JSON.parse(await waitForFile(pidPath, 10_000)) as { pid: number; parent: number };
      commandPid = identity.pid;
      process.kill(identity.parent, "SIGKILL");
      const result = await execution;

      expect(result.cleanup_confirmed).toBe(false);
      expect(result.timed_out).toBe(false);
      expect(result.cancelled).toBe(false);
    } finally {
      await writeFile(cleanupPath, "stop").catch(() => undefined);
      if (commandPid) {
        await expectProcessGone(commandPid).catch(() => {
          try { process.kill(commandPid!, "SIGKILL"); } catch { /* The command may already have exited. */ }
        });
      }
      await execution.catch(() => undefined);
      await rm(root, { recursive: true, force: true });
    }
  }, 15_000);

  test("returns spawn failures without waiting for the timeout", async () => {
    const result = await runProcessWithTail({
      ...baseInput,
      executable: join(process.cwd(), "__missing_process_executable__"),
      args: [],
      cwd: process.cwd(),
      timeout_ms: 2_000
    });

    expect(result.timed_out).toBe(false);
    expect(result.duration_ms).toBeLessThan(1_000);
    expect(result.stderr_tail).toMatch(/ENOENT|not found|not recognized as an internal or external command|could not start the command/i);
  });

  test("starts the timeout at spawn and bounds command output", async () => {
    const result = await runProcessWithTail({
      ...baseInput,
      executable: process.execPath,
      args: ["-e", "setTimeout(() => process.stdout.write('too-late'), 1_000); setInterval(() => {}, 1_000);"],
      cwd: process.cwd(),
      timeout_ms: 100
    });

    expect(result.timed_out).toBe(true);
    expect(result.cleanup_confirmed).toBe(true);
    expect(result.stdout_tail).not.toContain("too-late");
    expect(result.duration_ms).toBeLessThan(900);
  }, 3_000);

  posixTest("accepts command completion during the termination grace period", async () => {
    const root = await mkdtemp(join(tmpdir(), "gpt-process-graceful-stop-"));
    const readyPath = join(root, "ready");
    const controller = new AbortController();
    const execution = runProcessWithTail({
      ...baseInput,
      executable: process.execPath,
      args: ["-e", [
        "const { writeFileSync } = require('node:fs');",
        "process.on('SIGTERM', () => { process.stderr.write('terminated'); process.exit(0); });",
        `writeFileSync(${JSON.stringify(readyPath)}, 'ready');`,
        "process.stdout.write('started');",
        "setInterval(() => {}, 1_000);"
      ].join(" ")],
      cwd: root,
      timeout_ms: 2_000,
      signal: controller.signal
    });
    try {
      await waitForFile(readyPath);
      controller.abort();
      const result = await execution;

      expect(result).toMatchObject({
        cancelled: true,
        timed_out: false,
        exit_code: 0,
        cleanup_confirmed: true,
        stdout_tail: "started",
        stderr_tail: "terminated"
      });
    } finally {
      controller.abort();
      await execution.catch(() => undefined);
      await rm(root, { recursive: true, force: true });
    }
  }, 5_000);

  posixTest("escalates after the command leader exits and preserves its group identity", async () => {
    const root = await mkdtemp(join(tmpdir(), "gpt-process-group-anchor-"));
    const parentPath = join(root, "parent.cjs");
    const pidPath = join(root, "pids.json");
    const cleanupPath = join(root, "cleanup");
    const grandchildScript = [
      "const { existsSync } = require('node:fs');",
      "process.on('SIGTERM', () => {});",
      "process.send({ pid: process.pid });",
      `setInterval(() => { if (existsSync(${JSON.stringify(cleanupPath)})) process.exit(0); }, 20);`
    ].join(" ");
    const parentScript = [
      "const { spawn } = require('node:child_process');",
      "const { writeFileSync } = require('node:fs');",
      `const grandchild = spawn(${JSON.stringify(process.execPath)}, ['-e', ${JSON.stringify(grandchildScript)}], { stdio: ['ignore', 'ignore', 'ignore', 'ipc'] });`,
      `grandchild.on('message', (message) => writeFileSync(${JSON.stringify(pidPath)}, JSON.stringify({ parent: process.pid, grandchild: message.pid })));`,
      "process.on('SIGTERM', () => process.exit(0));",
      "setInterval(() => {}, 1_000);"
    ].join(" ");
    await writeFile(parentPath, parentScript);
    const controller = new AbortController();
    const execution = runProcessWithTail({
      ...baseInput,
      executable: process.execPath,
      args: [parentPath],
      cwd: root,
      timeout_ms: 5_000,
      signal: controller.signal
    });
    let pids: number[] = [];
    try {
      const identity = JSON.parse(await waitForFile(pidPath)) as { parent: number; grandchild: number };
      pids = [identity.parent, identity.grandchild];
      controller.abort();
      const result = await execution;

      expect(result).toMatchObject({ cancelled: true, signal: "SIGKILL", cleanup_confirmed: true });
      await Promise.all(pids.map(expectProcessGone));
    } finally {
      await writeFile(cleanupPath, "stop").catch(() => undefined);
      controller.abort();
      await execution.catch(() => undefined);
      await rm(root, { recursive: true, force: true });
    }
  }, 7_000);

  posixTest("keeps the group anchor while a descendant retains captured output pipes", async () => {
    const root = await mkdtemp(join(tmpdir(), "gpt-process-inherited-pipes-"));
    const pidPath = join(root, "pids.json");
    const cleanupPath = join(root, "cleanup");
    const grandchildScript = [
      "const { existsSync, writeFileSync } = require('node:fs');",
      "process.on('SIGTERM', () => {});",
      `writeFileSync(${JSON.stringify(join(root, "grandchild.ready"))}, String(process.pid));`,
      "process.send({ pid: process.pid });",
      `setInterval(() => { if (existsSync(${JSON.stringify(cleanupPath)})) process.exit(0); }, 20);`
    ].join(" ");
    const parentScript = [
      "const { spawn } = require('node:child_process');",
      "const { writeFileSync } = require('node:fs');",
      `const grandchild = spawn(${JSON.stringify(process.execPath)}, ['-e', ${JSON.stringify(grandchildScript)}], { stdio: ['ignore', 'inherit', 'inherit', 'ipc'] });`,
      `grandchild.on('message', (message) => { writeFileSync(${JSON.stringify(pidPath)}, JSON.stringify({ parent: process.pid, grandchild: message.pid })); process.exit(0); });`
    ].join(" ");
    const controller = new AbortController();
    const execution = runProcessWithTail({
      ...baseInput,
      executable: process.execPath,
      args: ["-e", parentScript],
      cwd: root,
      timeout_ms: 5_000,
      signal: controller.signal
    });
    try {
      const identity = JSON.parse(await waitForFile(pidPath)) as { parent: number; grandchild: number };
      await waitForFile(join(root, "grandchild.ready"));
      await expectProcessGone(identity.parent);
      controller.abort();
      const result = await execution;

      expect(result).toMatchObject({ cancelled: true, signal: "SIGKILL", cleanup_confirmed: true });
      await expectProcessGone(identity.grandchild);
    } finally {
      await writeFile(cleanupPath, "stop").catch(() => undefined);
      controller.abort();
      await execution.catch(() => undefined);
      await rm(root, { recursive: true, force: true });
    }
  }, 7_000);

  windowsTest("cancels an invocation after its leader exits and its descendant closes output pipes", async () => {
    const root = await mkdtemp(join(tmpdir(), "gpt-windows-job-closed-pipes-"));
    const pidPath = join(root, "pids.json");
    const readyPath = join(root, "descendant.ready");
    const invocation = startWindowsLeaderExitTree(root, pidPath, readyPath, "ignore");
    let pids: { leader: number; descendant: number } | undefined;
    try {
      pids = await waitForWindowsDescendantSpawn(invocation, pidPath);
      await waitForWindowsDescendantReady(invocation, pids, readyPath);
      await expectProcessGone(pids.leader);
      expect(isProcessAlive(pids.descendant)).toBe(true);

      invocation.controller.abort();
      const result = await invocation.execution;

      expect(result).toMatchObject({ cancelled: true, cleanup_confirmed: true, signal: "SIGKILL" });
      await expectProcessGone(pids.descendant);
    } finally {
      try {
        await cleanupWindowsInvocation(invocation, pidPath, readyPath, pids);
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    }
  }, 7_000);

  windowsTest("does not treat inherited-pipe closure as proof that the job is empty", async () => {
    const root = await mkdtemp(join(tmpdir(), "gpt-windows-job-inherited-pipes-"));
    const pidPath = join(root, "pids.json");
    const readyPath = join(root, "descendant.ready");
    const invocation = startWindowsLeaderExitTree(root, pidPath, readyPath, "inherit");
    let pids: { leader: number; descendant: number } | undefined;
    try {
      pids = await waitForWindowsDescendantSpawn(invocation, pidPath);
      await waitForWindowsDescendantReady(invocation, pids, readyPath);
      await expectProcessGone(pids.leader);
      expect(isProcessAlive(pids.descendant)).toBe(true);

      invocation.controller.abort();
      const result = await invocation.execution;

      expect(result).toMatchObject({ cancelled: true, cleanup_confirmed: true, signal: "SIGKILL" });
      await expectProcessGone(pids.descendant);
    } finally {
      try {
        await cleanupWindowsInvocation(invocation, pidPath, readyPath, pids);
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    }
  }, 7_000);

  windowsTest("applies the original timeout after the leader exits but a descendant remains", async () => {
    const root = await mkdtemp(join(tmpdir(), "gpt-windows-job-timeout-"));
    const pidPath = join(root, "pids.json");
    const readyPath = join(root, "descendant.ready");
    const invocation = startWindowsLeaderExitTree(root, pidPath, readyPath, "ignore", 1_000);
    let pids: { leader: number; descendant: number } | undefined;
    try {
      pids = await waitForWindowsDescendantSpawn(invocation, pidPath);
      await waitForWindowsDescendantReady(invocation, pids, readyPath);
      await expectProcessGone(pids.leader);
      const result = await invocation.execution;

      expect(result).toMatchObject({ timed_out: true, cancelled: false, cleanup_confirmed: true, signal: "SIGKILL" });
      await expectProcessGone(pids.descendant);
    } finally {
      try {
        await cleanupWindowsInvocation(invocation, pidPath, readyPath, pids);
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    }
  }, 5_000);

  windowsTest("isolates simultaneous Job Objects from each other and an unrelated process", async () => {
    const root = await mkdtemp(join(tmpdir(), "gpt-windows-job-isolation-"));
    const first = startWindowsLeaderExitTree(root, join(root, "first.json"), join(root, "first.ready"), "ignore");
    const second = startWindowsLeaderExitTree(root, join(root, "second.json"), join(root, "second.ready"), "ignore");
    const outsiderReady = join(root, "outsider.pid");
    const outsider = spawn(process.execPath, ["-e", [
      "const { writeFileSync } = require('node:fs');",
      `writeFileSync(${JSON.stringify(outsiderReady)}, String(process.pid));`,
      "setInterval(() => {}, 1_000);"
    ].join(" ")], { stdio: "ignore" });
    let firstPids: { leader: number; descendant: number } | undefined;
    let secondPids: { leader: number; descendant: number } | undefined;
    let outsiderPid: number | undefined;
    let cleanupFailure: unknown;
    try {
      firstPids = await waitForWindowsDescendantSpawn(first, join(root, "first.json"));
      secondPids = await waitForWindowsDescendantSpawn(second, join(root, "second.json"));
      await Promise.all([
        waitForWindowsDescendantReady(first, firstPids, join(root, "first.ready")),
        waitForWindowsDescendantReady(second, secondPids, join(root, "second.ready"))
      ]);
      outsiderPid = Number(await waitForFile(outsiderReady));

      first.controller.abort();
      const firstResult = await first.execution;
      expect(firstResult).toMatchObject({ cancelled: true, cleanup_confirmed: true });
      await expectProcessGone(firstPids.descendant);
      expect(isProcessAlive(secondPids.descendant)).toBe(true);
      expect(isProcessAlive(outsiderPid)).toBe(true);

      second.controller.abort();
      const secondResult = await second.execution;
      expect(secondResult).toMatchObject({ cancelled: true, cleanup_confirmed: true });
      await expectProcessGone(secondPids.descendant);
      expect(isProcessAlive(outsiderPid)).toBe(true);
    } finally {
      try {
        const cleanup = await Promise.allSettled([
          cleanupWindowsInvocation(first, join(root, "first.json"), join(root, "first.ready"), firstPids),
          cleanupWindowsInvocation(second, join(root, "second.json"), join(root, "second.ready"), secondPids)
        ]);
        if (outsider.pid) outsider.kill("SIGKILL");
        const failure = cleanup.find((result) => result.status === "rejected");
        if (failure?.status === "rejected") cleanupFailure = failure.reason;
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    }
    if (cleanupFailure) throw cleanupFailure;
  }, 10_000);

  windowsTest("fails before command launch when Job initialization fails", async () => {
    const root = await mkdtemp(join(tmpdir(), "gpt-windows-job-init-failure-"));
    try {
      const markerPath = join(root, "command-started");
      const result = await runTestWindowsHost({
        executable: process.execPath,
        args: ["-e", `require('node:fs').writeFileSync(${JSON.stringify(markerPath)}, 'started')`],
        cwd: root,
        env: { ...process.env, GPT_REPO_PROCESS_HOST_TEST_FAULT: "job-init" },
        timeout_ms: 2_000,
        tail_bytes: 1_024
      });

      expect(result).toMatchObject({ cleanup_confirmed: true, cancelled: false, timed_out: false });
      expect(result.exit_code).toBeUndefined();
      await expect(readFile(markerPath, "utf8")).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 5_000);

  windowsTest("reports cleanup unconfirmed when Job membership cannot be queried", async () => {
    const root = await mkdtemp(join(tmpdir(), "gpt-windows-job-query-failure-"));
    try {
      const result = await runTestWindowsHost({
        executable: process.execPath,
        args: ["-e", "setInterval(() => {}, 1_000)"],
        cwd: root,
        env: { ...process.env, GPT_REPO_PROCESS_HOST_TEST_FAULT: "job-query" },
        timeout_ms: 2_000,
        tail_bytes: 1_024
      });

      expect(result).toMatchObject({ cleanup_confirmed: false, cancelled: false, timed_out: false });
      expect(result.exit_code).toBeUndefined();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }, 5_000);

  windowsTest("reports cleanup unconfirmed when Job termination cannot be verified", async () => {
    const root = await mkdtemp(join(tmpdir(), "gpt-windows-job-termination-failure-"));
    const pidPath = join(root, "pids.json");
    const readyPath = join(root, "descendant.ready");
    const invocation = startWindowsLeaderExitTree(root, pidPath, readyPath, "ignore", 5_000, {
      ...process.env,
      GPT_REPO_PROCESS_HOST_TEST_FAULT: "job-terminate"
    }, true);
    let pids: { leader: number; descendant: number } | undefined;
    try {
      pids = await waitForWindowsDescendantSpawn(invocation, pidPath);
      await waitForWindowsDescendantReady(invocation, pids, readyPath);
      await expectProcessGone(pids.leader);
      invocation.controller.abort();
      const result = await invocation.execution;

      expect(result).toMatchObject({ cancelled: true, cleanup_confirmed: false, signal: "SIGKILL" });
      await expectProcessGone(pids.descendant);
    } finally {
      try {
        await cleanupWindowsInvocation(invocation, pidPath, readyPath, pids);
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    }
  }, 7_000);

  posixTest("kills only the process group belonging to the cancelled invocation", async () => {
    const root = await mkdtemp(join(tmpdir(), "gpt-process-group-isolation-"));
    const firstPidPath = join(root, "first.pid");
    const secondPidPath = join(root, "second.pid");
    const firstCleanupPath = join(root, "first.cleanup");
    const secondCleanupPath = join(root, "second.cleanup");
    const first = startStubbornCommand(root, firstPidPath, firstCleanupPath);
    let second: Invocation | undefined;
    try {
      const firstPid = Number(await waitForFile(firstPidPath));
      second = startStubbornCommand(root, secondPidPath, secondCleanupPath);
      const secondPid = Number(await waitForFile(secondPidPath));

      first.controller.abort();
      const firstResult = await first.execution;
      expect(firstResult).toMatchObject({ cancelled: true, cleanup_confirmed: true });
      await expectProcessGone(firstPid);
      expect(isProcessAlive(secondPid)).toBe(true);

      second.controller.abort();
      const secondResult = await second.execution;
      expect(secondResult).toMatchObject({ cancelled: true, cleanup_confirmed: true });
      await expectProcessGone(secondPid);
    } finally {
      await Promise.all([
        writeFile(firstCleanupPath, "stop").catch(() => undefined),
        writeFile(secondCleanupPath, "stop").catch(() => undefined)
      ]);
      first.controller.abort();
      second?.controller.abort();
      await Promise.all([first.execution.catch(() => undefined), second?.execution.catch(() => undefined)]);
      await rm(root, { recursive: true, force: true });
    }
  }, 8_000);
});

function startStubbornCommand(root: string, readyPath: string, cleanupPath: string): Invocation {
  const controller = new AbortController();
  const execution = runProcessWithTail({
    ...baseInput,
    executable: process.execPath,
    args: ["-e", [
      "const { existsSync, writeFileSync } = require('node:fs');",
      "process.on('SIGTERM', () => {});",
      `writeFileSync(${JSON.stringify(readyPath)}, String(process.pid));`,
      `setInterval(() => { if (existsSync(${JSON.stringify(cleanupPath)})) process.exit(0); }, 20);`
    ].join(" ")],
    cwd: root,
    timeout_ms: 5_000,
    signal: controller.signal
  });
  return { controller, execution };
}

function startWindowsLeaderExitTree(
  root: string,
  pidPath: string,
  readyPath: string,
  stdio: "ignore" | "inherit",
  timeoutMs = 5_000,
  env: NodeJS.ProcessEnv = process.env,
  testHost = false
): Invocation {
  const controller = new AbortController();
  const descendantScript = [
    "const { existsSync, writeFileSync } = require('node:fs');",
    "process.on('SIGTERM', () => {});",
    `writeFileSync(${JSON.stringify(readyPath)}, String(process.pid));`,
    `setInterval(() => { if (existsSync(${JSON.stringify(cleanupPathFor(readyPath))})) { writeFileSync(${JSON.stringify(exitPathFor(readyPath))}, String(process.pid)); process.exit(0); } }, 20);`
  ].join(" ");
  const leaderScript = [
    "const { spawn } = require('node:child_process');",
    "const { existsSync, writeFileSync } = require('node:fs');",
    "let readinessPoll;",
    `const descendant = spawn(process.execPath, ['-e', ${JSON.stringify(descendantScript)}], { stdio: ${JSON.stringify(stdio)} });`,
    "descendant.once('error', (error) => { if (readinessPoll) clearInterval(readinessPoll); console.error('Descendant spawn failed:', error); process.exitCode = 1; });",
    `descendant.once('spawn', () => { writeFileSync(${JSON.stringify(pidPath)}, JSON.stringify({ leader: process.pid, descendant: descendant.pid })); readinessPoll = setInterval(() => { if (existsSync(${JSON.stringify(readyPath)}) || existsSync(${JSON.stringify(cleanupPathFor(readyPath))})) { clearInterval(readinessPoll); descendant.unref(); } }, 10); });`,
    `descendant.once('exit', (code, signal) => { if (!existsSync(${JSON.stringify(readyPath)})) { if (readinessPoll) clearInterval(readinessPoll); console.error('Descendant exited before readiness:', code, signal); process.exitCode = 1; } });`
  ].join(" ");
  const processInput = {
    ...baseInput,
    executable: process.execPath,
    args: ["-e", leaderScript],
    cwd: root,
    timeout_ms: timeoutMs,
    signal: controller.signal,
    env
  };
  const execution = testHost ? runWindowsProcessWithTail(processInput, testHostLaunch(processInput)) : runProcessWithTail(processInput);
  return { controller, execution };
}

function runTestWindowsHost(input: Parameters<typeof runWindowsProcessWithTail>[0]) {
  return runWindowsProcessWithTail(input, testHostLaunch(input));
}

function testHostLaunch(input: { executable: string; args: string[] }) {
  return {
    executable: join(process.cwd(), "dist", "windows-process-host.test.exe"),
    args: ["--", input.executable, ...input.args]
  };
}

async function waitForWindowsDescendantSpawn(
  invocation: Invocation,
  pidPath: string
): Promise<{ leader: number; descendant: number }> {
  const outcome = await Promise.race([
    waitForFile(pidPath).then(
      (value) => ({ type: "spawned" as const, pids: JSON.parse(value) as { leader: number; descendant: number } }),
      (error: unknown) => ({
        type: error instanceof Error && error.message === `Timed out waiting for ${pidPath}.`
          ? "timeout" as const
          : "read-error" as const,
        error
      })
    ),
    invocation.execution.then(
      (result) => ({ type: "completed" as const, result }),
      (error: unknown) => ({ type: "failed" as const, error })
    )
  ]);

  if (outcome.type === "spawned") return outcome.pids;
  if (outcome.type === "completed") {
    const pids = await readWindowsDescendantPids(pidPath);
    if (pids) return pids;
    throw new Error(`Windows process host completed before descendant spawn: ${JSON.stringify(outcome.result)}`);
  }
  if (outcome.type === "failed") {
    throw new Error(`Windows process host failed before descendant spawn: ${String(outcome.error)}`);
  }
  if (outcome.type === "read-error") {
    throw new Error(`Could not inspect Windows descendant spawn: ${String(outcome.error)}`);
  }

  invocation.controller.abort();
  const result = await invocation.execution.catch((error: unknown) => ({ error: String(error) }));
  throw new Error(`${outcome.error instanceof Error ? outcome.error.message : String(outcome.error)} Host result: ${JSON.stringify(result)}`);
}

async function waitForWindowsDescendantReady(
  invocation: Invocation,
  pids: { leader: number; descendant: number },
  readyPath: string
): Promise<void> {
  const readinessController = new AbortController();
  const outcome = await Promise.race([
    waitForFile(readyPath, READY_TIMEOUT_MS, readinessController.signal).then(
      () => ({ type: "ready" as const }),
      (error: unknown) => ({
        type: error instanceof Error && error.message === `Timed out waiting for ${readyPath}.`
          ? "timeout" as const
          : "read-error" as const,
        error
      })
    ),
    invocation.execution.then(
      (result) => ({ type: "completed" as const, result }),
      (error: unknown) => ({ type: "failed" as const, error })
    )
  ]);
  readinessController.abort();

  if (outcome.type === "ready") return;
  if (outcome.type === "completed") {
    throw new Error(`Windows process host completed before descendant readiness (descendant_alive=${isProcessAlive(pids.descendant)}): ${JSON.stringify(outcome.result)}`);
  }
  if (outcome.type === "failed") {
    throw new Error(`Windows process host failed before descendant readiness: ${String(outcome.error)}`);
  }
  if (outcome.type === "read-error") {
    throw new Error(`Could not inspect Windows descendant readiness: ${String(outcome.error)}`);
  }

  invocation.controller.abort();
  const result = await invocation.execution.catch((error: unknown) => ({ error: String(error) }));
  throw new Error(`${outcome.error instanceof Error ? outcome.error.message : String(outcome.error)} Host result: ${JSON.stringify(result)}, descendant_alive=${isProcessAlive(pids.descendant)}`);
}

async function cleanupWindowsInvocation(
  invocation: Invocation,
  pidPath: string,
  readyPath: string,
  knownPids?: { leader: number; descendant: number }
): Promise<void> {
  invocation.controller.abort();
  await invocation.execution.catch(() => undefined);
  const pids = knownPids ?? await readWindowsDescendantPids(pidPath);
  if (!pids) return;
  if (!isProcessAlive(pids.descendant)) return;

  await writeFile(cleanupPathFor(readyPath), "stop");
  await waitForFile(exitPathFor(readyPath), PROCESS_GONE_TIMEOUT_MS);
}

function cleanupPathFor(readyPath: string): string {
  return readyPath.replace(/\.ready$/, ".cleanup");
}

function exitPathFor(readyPath: string): string {
  return readyPath.replace(/\.ready$/, ".exit");
}

async function readWindowsDescendantPids(pidPath: string): Promise<{ leader: number; descendant: number } | undefined> {
  try {
    return JSON.parse(await readFile(pidPath, "utf8")) as { leader: number; descendant: number };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
}

async function waitForFile(path: string, timeoutMs = READY_TIMEOUT_MS, signal?: AbortSignal): Promise<string> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    signal?.throwIfAborted();
    try {
      return await readFile(path, "utf8");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      await delay(10, undefined, signal ? { signal } : undefined);
    }
  }
  throw new Error(`Timed out waiting for ${path}.`);
}

function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ESRCH") return false;
    throw error;
  }
}

async function expectProcessGone(pid: number): Promise<void> {
  const deadline = Date.now() + PROCESS_GONE_TIMEOUT_MS;
  while (isProcessAlive(pid) && Date.now() < deadline) await delay(20);
  expect(isProcessAlive(pid)).toBe(false);
}
