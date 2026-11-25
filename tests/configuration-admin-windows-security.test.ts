import { randomBytes, randomUUID } from "node:crypto";
import { execFileSync, spawn, spawnSync, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import process from "node:process";
import { describe, expect, test } from "vitest";

const repoRoot = resolve(fileURLToPath(new URL("../", import.meta.url)));
const builtServer = join(repoRoot, "dist", "server.js");
const builtCli = join(repoRoot, "dist", "cli", "connect-gpt.js");
const productionHelper = join(repoRoot, "dist", "windows-configuration-admin-host.exe");
const userProfileRoot = process.env.USERPROFILE;
const publicRoot = process.env.PUBLIC ?? "C:\\Users\\Public";

describe.skipIf(process.platform !== "win32")("Windows configuration pipe identity enforcement", () => {
  test("a distinct SID is denied by the owner pipe while the owner production CLI reloads successfully", async ({ skip }) => {
    const fixtureId = randomUUID().replaceAll("-", "");
    const userName = `CodexIpc${fixtureId.slice(0, 12)}`;
    const password = `${randomBytes(30).toString("base64url")}Aa1!`;
    const ownerLocalAppData = await createOwnerLocalAppData();
    const fixtureRoot = join(publicRoot, `gpt-repo-admin-security-${fixtureId}`);
    const outsiderLocalAppData = join(fixtureRoot, "outsider-app-data");
    const configPath = join(fixtureRoot, "configuration.json");
    const launcherPath = join(fixtureRoot, "run-as-outsider.mjs");
    const fixturePath = join(fixtureRoot, "fixture.json");
    const sidPath = join(fixtureRoot, "outsider.sid");
    const stdoutPath = join(fixtureRoot, "outsider.stdout");
    const stderrPath = join(fixtureRoot, "outsider.stderr");
    const serverEnv: NodeJS.ProcessEnv = {
      ...process.env,
      LOCALAPPDATA: ownerLocalAppData,
      GPT_REPO_CONFIG: configPath,
      GPT_REPO_HOST: "127.0.0.1",
      PORT: "0"
    };
    delete serverEnv.GPT_REPO_ADMIN_TEST_HELPER;
    let server: ChildProcess | undefined;
    let serverOutput = "";
    let fixtureMayBeRestricted = false;
    let ownerSid: string | undefined;
    let fixtureSkipReason: string | undefined;
    let testFailed = false;
    let testError: unknown;
    try {
      await (async () => {
      try {
        createOutsiderDiscoveryFixture(fixtureRoot, outsiderLocalAppData);
        createTemporaryWindowsUser(userName, password, sidPath);
        ownerSid = currentWindowsSid();
      } catch (error) {
        if (process.env.GPT_REPO_REQUIRE_SECURITY_FIXTURES === "1") {
          throw new Error("Windows SID qualification requires local-account creation and alternate-credential process launch on the ephemeral CI runner.", { cause: error });
        }
        fixtureSkipReason = "Windows SID qualification requires local-account creation and alternate-credential process launch.";
        skip(fixtureSkipReason);
        return;
      }
      await writeFile(configPath, JSON.stringify({ repos: [], limits: {} }), { mode: 0o600 });

      server = spawn(process.execPath, [builtServer], {
        cwd: repoRoot,
        env: serverEnv,
        stdio: ["ignore", "ignore", "pipe"],
        windowsHide: true
      });
      server.stderr?.setEncoding("utf8");
      server.stderr?.on("data", (chunk: string) => {
        serverOutput = (serverOutput + chunk).slice(-8_000);
      });
      let serverSpawnError: Error | undefined;
      server.once("error", (error: Error) => {
        serverSpawnError = error;
      });

      const serverPort = await waitForServer(server, () => serverOutput, () => serverSpawnError);
      const ownerRecord = await waitForOwnerRecord(ownerLocalAppData, () => serverOutput);
      const ownerReload = runCli(builtCli, repoRoot, serverEnv, ownerRecord.server_pid);
      expect(ownerReload.status, ownerReload.stderr).toBe(0);
      expect(ownerReload.stdout).toContain("Reloaded configuration");
      expect(await fetch(`http://127.0.0.1:${serverPort}/health`).then((response) => response.ok)).toBe(true);

      const outsiderSid = (await readFile(sidPath, "utf8")).trim();
      expect(outsiderSid).not.toBe(ownerSid);
      fixtureMayBeRestricted = true;
      await writeOutsiderRecord(outsiderLocalAppData, outsiderSid, ownerRecord);
      await writeFile(launcherPath, outsiderLauncherSource, "utf8");
      await writeFile(fixturePath, JSON.stringify({
        expectedSid: outsiderSid,
        localAppData: outsiderLocalAppData,
        configPath,
        cliPath: builtCli,
        helperPath: productionHelper,
        endpoint: ownerRecord.endpoint,
        serverPid: ownerRecord.server_pid
      }), "utf8");

      runAsWindowsUser(userName, password, launcherPath, fixturePath, stdoutPath, stderrPath);
      const result = JSON.parse(await readFile(stdoutPath, "utf8")) as {
        sid: string;
        directStatus: number | null;
        directOutput: string;
        cliStatus: number | null;
        cliError?: string;
        cliOutput: string;
      };
      expect(result.sid).toBe(outsiderSid);
      expect(result.directStatus).toBe(34);
      expect(result.directOutput).toContain("NOT_DISPATCHED\t5");
      expect(result.cliStatus).toBe(1);
      expect(result.cliOutput).toContain("Windows denied access to the owner-local administrative pipe.");
      expect(result.cliOutput).toContain("Configuration reload was not dispatched.");
      })();
    } catch (error) {
      testFailed = true;
      testError = error;
    }

    const cleanupErrors: unknown[] = [];
    let canRemoveFixture = true;
    let canRemoveOwnerData = true;
    let canRemoveTemporaryUser = true;
    try {
      await stopServer(server);
    } catch (error) {
      cleanupErrors.push(error);
      canRemoveFixture = false;
      canRemoveOwnerData = false;
      if (fixtureMayBeRestricted) {
        canRemoveTemporaryUser = false;
        cleanupErrors.push(new Error(`Preserved temporary account ${userName} because the server did not stop and its fixture may remain in use or restricted.`));
      }
    }
    if (fixtureMayBeRestricted && ownerSid) {
      try {
        takeFixtureOwnership(fixtureRoot, ownerSid);
      } catch (error) {
        cleanupErrors.push(error);
        canRemoveFixture = false;
        canRemoveOwnerData = false;
        canRemoveTemporaryUser = false;
        cleanupErrors.push(new Error(`Preserved temporary account ${userName} because fixture ownership could not be restored.`));
        cleanupErrors.push(new Error(`Preserved owner data at ${ownerLocalAppData} because fixture ownership could not be restored.`));
      }
    }
    if (canRemoveTemporaryUser) {
      try {
        removeTemporaryWindowsUser(userName);
      } catch (error) {
        cleanupErrors.push(error);
        canRemoveFixture = false;
        canRemoveOwnerData = false;
        cleanupErrors.push(new Error(`Preserved fixture at ${fixtureRoot} and owner data at ${ownerLocalAppData} because temporary account ${userName} could not be removed.`));
      }
    }
    if (canRemoveFixture) {
      try {
        await rm(fixtureRoot, { recursive: true, force: true });
      } catch (error) {
        cleanupErrors.push(error);
      }
    }
    if (canRemoveOwnerData) {
      try {
        await rm(ownerLocalAppData, { recursive: true, force: true });
      } catch (error) {
        cleanupErrors.push(error);
      }
    }
    const details = cleanupErrors.map((error) => error instanceof Error ? error.message : String(error));
    if (testFailed && cleanupErrors.length > 0) {
      const skipDetail = fixtureSkipReason ? ` Fixture prerequisite: ${fixtureSkipReason}` : "";
      throw new AggregateError([testError, ...cleanupErrors], `Windows SID test and cleanup failed.${skipDetail} ${details.join("; ")}`);
    }
    if (testFailed) throw testError;
    if (cleanupErrors.length > 0) {
      const skipDetail = fixtureSkipReason ? ` after fixture skip: ${fixtureSkipReason}` : "";
      throw new AggregateError(cleanupErrors, `Windows SID fixture cleanup failed${skipDetail}: ${details.join("; ")}`);
    }
  }, 60_000);
});

const outsiderLauncherSource = String.raw`
import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import process from "node:process";
const fixture = JSON.parse(readFileSync(process.argv[2], "utf8"));
process.env.LOCALAPPDATA = fixture.localAppData;
process.env.GPT_REPO_CONFIG = fixture.configPath;
process.env.GPT_REPO_TEST_BUILT_SERVER = "1";
const whoami = execFileSync("whoami.exe", ["/user", "/fo", "csv", "/nh"], { encoding: "utf8" });
const sid = whoami.match(/S-1-[0-9-]+/)?.[0] ?? "";
const requestId = "11111111-1111-4111-8111-111111111111";
const payload = Buffer.from(JSON.stringify({ protocol_version: 1, request_id: requestId, operation: "probe" }));
const frame = Buffer.alloc(4 + payload.length);
frame.writeUInt32BE(payload.length, 0);
payload.copy(frame, 4);
const direct = spawnSync(fixture.helperPath, ["client", fixture.endpoint, "2000"], {
  input: frame,
  timeout: 7000,
  windowsHide: true
});
const cli = spawnSync(process.execPath, [fixture.cliPath, "config", "reload", "--instance", String(fixture.serverPid)], {
  cwd: process.cwd(),
  encoding: "utf8",
  timeout: 15000,
  windowsHide: true,
  env: { ...process.env, GPT_REPO_CONFIG: fixture.configPath }
});
process.stdout.write(JSON.stringify({
  sid,
  directStatus: direct.status,
  directOutput: direct.stdout?.toString("ascii") ?? "",
  directError: direct.error?.code,
  cliStatus: cli.status,
  cliError: cli.error?.code,
  cliOutput: (cli.stdout ?? "") + (cli.stderr ?? "")
}));
`;

function createTemporaryWindowsUser(name: string, password: string, sidPath: string): void {
  runPowerShell(String.raw`
$ErrorActionPreference = 'Stop'
$secure = ConvertTo-SecureString $env:GPT_REPO_SECURITY_PASSWORD -AsPlainText -Force
$user = New-LocalUser -Name $env:GPT_REPO_SECURITY_USER -Password $secure -AccountNeverExpires -PasswordNeverExpires
[System.IO.File]::WriteAllText($env:GPT_REPO_SECURITY_SID_PATH, $user.SID.Value)
`, {
    GPT_REPO_SECURITY_USER: name,
    GPT_REPO_SECURITY_PASSWORD: password,
    GPT_REPO_SECURITY_SID_PATH: sidPath
  });
}

function createOutsiderDiscoveryFixture(fixtureRoot: string, localAppData: string): void {
  runPowerShell(String.raw`
$ErrorActionPreference = 'Stop'
$root = $env:GPT_REPO_SECURITY_FIXTURE_ROOT
$local = $env:GPT_REPO_SECURITY_LOCAL_APP_DATA
[System.IO.Directory]::CreateDirectory($root) | Out-Null
[System.IO.Directory]::CreateDirectory($local) | Out-Null
$adminRoot = Join-Path $local 'GPTRepoMCP'
$admin = Join-Path $adminRoot 'admin'
[System.IO.Directory]::CreateDirectory($admin) | Out-Null
`, {
    GPT_REPO_SECURITY_FIXTURE_ROOT: fixtureRoot,
    GPT_REPO_SECURITY_LOCAL_APP_DATA: localAppData
  });
}

async function writeOutsiderRecord(
  localAppData: string,
  outsiderSid: string,
  record: { server_pid: number; helper_pid: number; instance_id: string; endpoint: string }
): Promise<void> {
  const recordPath = join(localAppData, "GPTRepoMCP", "admin", `server-${record.server_pid}-${record.instance_id}.record`);
  const contents = [
    "protocol_version=1",
    `server_pid=${record.server_pid}`,
    `helper_pid=${record.helper_pid}`,
    `instance_id=${record.instance_id}`,
    `endpoint=${record.endpoint}`,
    ""
  ].join("\n");
  await writeFile(recordPath, contents, "utf8");
  runPowerShell(String.raw`
$ErrorActionPreference = 'Stop'
$sid = [System.Security.Principal.SecurityIdentifier]::new($env:GPT_REPO_SECURITY_OUTSIDER_SID)
function Set-PrivateOwnerAcl([string]$path) {
  $acl = Get-Acl -LiteralPath $path
  $acl.SetAccessRuleProtection($true, $false)
  foreach ($entry in @($acl.Access)) { $acl.RemoveAccessRuleSpecific($entry) }
  $acl.SetOwner($sid)
  $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
    $sid,
    [System.Security.AccessControl.FileSystemRights]::FullControl,
    [System.Security.AccessControl.AccessControlType]::Allow
  )
  $acl.SetAccessRule($rule)
  Set-Acl -LiteralPath $path -AclObject $acl
}
$local = $env:GPT_REPO_SECURITY_LOCAL_APP_DATA
Set-PrivateOwnerAcl $local
Set-PrivateOwnerAcl (Join-Path $local 'GPTRepoMCP')
Set-PrivateOwnerAcl (Join-Path $local 'GPTRepoMCP\admin')
$acl = Get-Acl -LiteralPath $env:GPT_REPO_SECURITY_RECORD_PATH
$acl.SetAccessRuleProtection($true, $false)
foreach ($entry in @($acl.Access)) { $acl.RemoveAccessRuleSpecific($entry) }
$acl.SetOwner($sid)
$rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
  $sid,
  [System.Security.AccessControl.FileSystemRights]::FullControl,
  [System.Security.AccessControl.AccessControlType]::Allow
)
$acl.SetAccessRule($rule)
Set-Acl -LiteralPath $env:GPT_REPO_SECURITY_RECORD_PATH -AclObject $acl
`, {
    GPT_REPO_SECURITY_OUTSIDER_SID: outsiderSid,
    GPT_REPO_SECURITY_LOCAL_APP_DATA: localAppData,
    GPT_REPO_SECURITY_RECORD_PATH: recordPath,
  });
}

function runAsWindowsUser(
  name: string,
  password: string,
  launcherPath: string,
  fixturePath: string,
  stdoutPath: string,
  stderrPath: string
): void {
  runPowerShell(String.raw`
$ErrorActionPreference = 'Stop'
$secure = ConvertTo-SecureString $env:GPT_REPO_SECURITY_PASSWORD -AsPlainText -Force
$credential = [System.Management.Automation.PSCredential]::new(".\$env:GPT_REPO_SECURITY_USER", $secure)
$arguments = '"{0}" "{1}"' -f $env:GPT_REPO_SECURITY_LAUNCHER, $env:GPT_REPO_SECURITY_FIXTURE_FILE
$process = Start-Process -FilePath $env:GPT_REPO_SECURITY_NODE -ArgumentList $arguments -Credential $credential -LoadUserProfile -Wait -PassThru -RedirectStandardOutput $env:GPT_REPO_SECURITY_STDOUT -RedirectStandardError $env:GPT_REPO_SECURITY_STDERR
if ($process.ExitCode -ne 0) { exit $process.ExitCode }
`, {
    GPT_REPO_SECURITY_USER: name,
    GPT_REPO_SECURITY_PASSWORD: password,
    GPT_REPO_SECURITY_LAUNCHER: launcherPath,
    GPT_REPO_SECURITY_FIXTURE_FILE: fixturePath,
    GPT_REPO_SECURITY_NODE: process.execPath,
    GPT_REPO_SECURITY_STDOUT: stdoutPath,
    GPT_REPO_SECURITY_STDERR: stderrPath
  });
}

function removeTemporaryWindowsUser(name: string): void {
  try {
    runPowerShell(String.raw`
$ErrorActionPreference = 'Stop'
$name = $env:GPT_REPO_SECURITY_USER
$user = Get-LocalUser -ErrorAction Stop | Where-Object { $_.Name -eq $name }
if ($null -ne $user) { Remove-LocalUser -Name $name -ErrorAction Stop }
$remaining = Get-LocalUser -ErrorAction Stop | Where-Object { $_.Name -eq $name }
if ($null -ne $remaining) { throw "Temporary local account still exists: $name" }
`, { GPT_REPO_SECURITY_USER: name });
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`The temporary Windows SID qualification account could not be removed: ${detail}`, { cause: error });
  }
}

function takeFixtureOwnership(fixtureRoot: string, ownerSid: string): void {
  runPowerShell(String.raw`
$ErrorActionPreference = 'Stop'
$root = $env:GPT_REPO_SECURITY_FIXTURE_ROOT
if (Test-Path -LiteralPath $root) {
  & takeown.exe /F $root /R /D Y | Out-Null
  $access = "*$($env:GPT_REPO_SECURITY_OWNER_SID):(OI)(CI)F"
  & icacls.exe $root /grant $access /T /C | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Could not restore access to the temporary security fixture.' }
}
`, {
    GPT_REPO_SECURITY_FIXTURE_ROOT: fixtureRoot,
    GPT_REPO_SECURITY_OWNER_SID: ownerSid
  });
}

function runPowerShell(script: string, env: Record<string, string>): void {
  execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script], {
    encoding: "utf8",
    env: { ...process.env, ...env },
    timeout: 15_000,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"]
  });
}

function currentWindowsSid(): string {
  const identity = execFileSync("whoami.exe", ["/user", "/fo", "csv", "/nh"], { encoding: "utf8", windowsHide: true });
  const sid = identity.match(/S-1-[0-9-]+/)?.[0];
  if (!sid) throw new Error("The current Windows SID could not be read.");
  return sid;
}

async function createOwnerLocalAppData(): Promise<string> {
  if (!userProfileRoot) throw new Error("The Windows test requires a user profile directory.");
  return mkdtemp(join(userProfileRoot, "gpt-repo-admin-security-owner-"));
}

async function waitForServer(
  child: ChildProcess,
  readOutput: () => string,
  readSpawnError: () => Error | undefined
): Promise<number> {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    const spawnError = readSpawnError();
    if (spawnError) {
      throw new Error(`Built Windows server could not be spawned: ${spawnError.message}`, { cause: spawnError });
    }
    if (child.exitCode !== null || child.signalCode !== null) {
      throw new Error(`Built Windows server exited before binding. ${readOutput()}`);
    }
    const match = readOutput().match(/listening on http:\/\/[^:\s]+:(\d+)\//);
    if (match) {
      const port = Number(match[1]);
      try {
        if (await fetch(`http://127.0.0.1:${port}/health`).then((response) => response.ok)) return port;
      } catch {
        // The listener may need one more event-loop turn before accepting connections.
      }
    }
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 25));
  }
  throw new Error(`Built Windows server did not become healthy. ${readOutput()}`);
}

async function waitForOwnerRecord(
  localAppData: string,
  readOutput: () => string
): Promise<{ server_pid: number; helper_pid: number; instance_id: string; endpoint: string }> {
  const recordPath = join(localAppData, "GPTRepoMCP", "admin");
  const deadline = Date.now() + 8_000;
  while (Date.now() < deadline) {
    try {
      const records = await import("node:fs/promises").then(({ readdir }) => readdir(recordPath));
      const name = records.find((entry) => /^server-[0-9]+-[0-9a-f-]{36}\.record$/.test(entry));
      if (name) {
        const contents = await readFile(join(recordPath, name), "utf8");
        const fields = Object.fromEntries(contents.trim().split(/\r?\n/).map((line) => {
          const separator = line.indexOf("=");
          return [line.slice(0, separator), line.slice(separator + 1)];
        }));
        return {
          server_pid: Number(fields.server_pid),
          helper_pid: Number(fields.helper_pid),
          instance_id: fields.instance_id!,
          endpoint: fields.endpoint!
        };
      }
    } catch {
      // The native helper may still be creating its secured discovery store.
    }
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 25));
  }
  throw new Error(`Built Windows server did not publish its pipe record. ${readOutput()}`);
}

function runCli(cliPath: string, cwd: string, env: NodeJS.ProcessEnv, serverPid: number) {
  return spawnSync(process.execPath, [cliPath, "config", "reload", "--instance", String(serverPid)], {
    cwd,
    env,
    encoding: "utf8",
    timeout: 20_000,
    maxBuffer: 1_000_000,
    windowsHide: true
  });
}

async function stopServer(child: ChildProcess | undefined): Promise<void> {
  if (!child || child.pid === undefined || child.exitCode !== null || child.signalCode !== null) return;
  child.kill("SIGTERM");
  if (await waitForChildExit(child, 5_000)) return;
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill();
  if (!await waitForChildExit(child, 5_000) && child.exitCode === null && child.signalCode === null) {
    throw new Error(`Windows security server process ${child.pid} did not exit after termination.`);
  }
}

async function waitForChildExit(child: ChildProcess, timeoutMs: number): Promise<boolean> {
  if (child.exitCode !== null || child.signalCode !== null) return true;
  try {
    await once(child, "exit", { signal: AbortSignal.timeout(timeoutMs) });
    return true;
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") return false;
    throw error;
  }
}
