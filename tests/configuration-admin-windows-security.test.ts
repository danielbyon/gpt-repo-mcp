import { randomBytes, randomUUID } from "node:crypto";
import { execFileSync, spawn, spawnSync, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import { access, lstat, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import process from "node:process";
import { describe, expect, test, vi } from "vitest";
import { requestWindowsConfigurationAdmin, startWindowsConfigurationAdminHost } from "../src/runtime/configuration-admin-windows.js";
import { parseAdminRequest, type ConfigurationAdminResponse } from "../src/runtime/configuration-admin-protocol.js";

const repoRoot = resolve(fileURLToPath(new URL("../", import.meta.url)));
const builtServer = join(repoRoot, "dist", "server.js");
const builtCli = join(repoRoot, "dist", "cli", "connect-gpt.js");
const productionHelper = join(repoRoot, "dist", "windows-configuration-admin-host.exe");
const testHelper = join(repoRoot, "dist", "windows-configuration-admin-host.test.exe");
const userProfileRoot = process.env.USERPROFILE;
const publicRoot = process.env.PUBLIC ?? "C:\\Users\\Public";

const replacementPipeServerSource = String.raw`
$ErrorActionPreference = 'Stop'
$pipeName = $env:GPT_REPO_SECURITY_PIPE_NAME
$ownerSid = [System.Security.Principal.SecurityIdentifier]::new($env:GPT_REPO_SECURITY_OWNER_SID)
$serverSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$processInfo = Get-Process -Id $PID
$creationTime = $processInfo.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
$pipeSecurity = [System.IO.Pipes.PipeSecurity]::new()
$pipeSecurity.SetOwner($serverSid)
$pipeSecurity.SetAccessRuleProtection($true, $false)
$accessSids = @($ownerSid)
if ($serverSid.Value -ne $ownerSid.Value -and
    $env:GPT_REPO_SECURITY_OWNER_ONLY_DACL -ne '1') { $accessSids += $serverSid }
foreach ($sid in $accessSids) {
  $rule = [System.IO.Pipes.PipeAccessRule]::new(
    $sid,
    [System.IO.Pipes.PipeAccessRights]::FullControl,
    [System.Security.AccessControl.AccessControlType]::Allow
  )
  $pipeSecurity.AddAccessRule($rule)
}
if ($env:GPT_REPO_SECURITY_UNEXPECTED_DACL -eq '1') {
  $everyoneSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
  $unexpectedRule = [System.IO.Pipes.PipeAccessRule]::new(
    $everyoneSid,
    [System.IO.Pipes.PipeAccessRights]::ReadData,
    [System.Security.AccessControl.AccessControlType]::Allow
  )
  $pipeSecurity.AddAccessRule($unexpectedRule)
}
$pipe = [System.IO.Pipes.NamedPipeServerStream]::new(
  $pipeName,
  [System.IO.Pipes.PipeDirection]::InOut,
  1,
  [System.IO.Pipes.PipeTransmissionMode]::Message,
  [System.IO.Pipes.PipeOptions]::Asynchronous,
  4096,
  4096,
  $pipeSecurity
)
Write-Output ('READY|{0}|{1}|{2}' -f $PID, $serverSid.Value, $creationTime)
[Console]::Out.Flush()
if (-not $pipe.WaitForConnectionAsync().Wait(10000)) {
  Write-Output 'NO_CONNECTION'
  exit 2
}
if ($env:GPT_REPO_SECURITY_CHANGE_DACL -eq '1') {
  if ([Console]::In.ReadLine() -ne 'CHANGE_DACL') {
    throw 'The DACL mutation command was missing.'
  }
  $everyoneSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
  $mutationRule = [System.IO.Pipes.PipeAccessRule]::new(
    $everyoneSid,
    [System.IO.Pipes.PipeAccessRights]::ReadData,
    [System.Security.AccessControl.AccessControlType]::Allow
  )
  $pipeSecurity.AddAccessRule($mutationRule)
  $pipe.SetAccessControl($pipeSecurity)
  Write-Output 'DACL_CHANGED'
  [Console]::Out.Flush()
}
$buffer = [byte[]]::new(65536)
$received = $pipe.Read($buffer, 0, $buffer.Length)
Write-Output ('CONNECTED|{0}' -f $received)
$pipe.Dispose()
`;

const pipeNamespaceClaimLauncherSource = String.raw`
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const fixture = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const identity = spawnSync('whoami.exe', ['/user', '/fo', 'csv', '/nh'], {
  encoding: 'utf8',
  windowsHide: true
});
const sid = identity.stdout?.match(/S-1-[0-9-]+/)?.[0];
if (identity.status !== 0 || !sid) {
  process.stderr.write(identity.stderr || 'The pipe claimant SID could not be read.');
  process.exit(2);
}
const claim = spawnSync(fixture.helperPath, ['claim', fixture.endpoint], {
  encoding: 'utf8',
  timeout: 5000,
  windowsHide: true
});
if (claim.error) {
  process.stderr.write(claim.error.message);
  process.exit(3);
}
process.stdout.write(JSON.stringify({ sid, status: claim.status, stdout: claim.stdout, stderr: claim.stderr }));
if (claim.status !== 0) process.exit(claim.status ?? 4);
`;

const replacementPipeProbeScript = String.raw`
$ErrorActionPreference = 'Stop'
$pipeServer = $null
$serveProcess = $null
$clientProcess = $null
$securePassword = $null
try {
  $serverStart = [System.Diagnostics.ProcessStartInfo]::new()
  $serverStart.FileName = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
  $serverStart.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}"' -f $env:GPT_REPO_SECURITY_REPLACEMENT_SCRIPT
  $serverStart.WorkingDirectory = $env:GPT_REPO_SECURITY_WORKING_DIRECTORY
  $serverStart.UseShellExecute = $false
  $serverStart.RedirectStandardOutput = $true
  $serverStart.RedirectStandardError = $true
  $serverStart.CreateNoWindow = $true
  $serverStart.EnvironmentVariables['GPT_REPO_SECURITY_PIPE_NAME'] = $env:GPT_REPO_SECURITY_PIPE_NAME
  $serverStart.EnvironmentVariables['GPT_REPO_SECURITY_OWNER_SID'] = $env:GPT_REPO_SECURITY_OWNER_SID
  $serverStart.EnvironmentVariables['GPT_REPO_SECURITY_UNEXPECTED_DACL'] = $env:GPT_REPO_SECURITY_UNEXPECTED_DACL
  $serverStart.EnvironmentVariables['GPT_REPO_SECURITY_OWNER_ONLY_DACL'] = $env:GPT_REPO_SECURITY_OWNER_ONLY_DACL
  if ($env:GPT_REPO_SECURITY_RUN_AS_OUTSIDER -eq '1') {
    $securePassword = [System.Security.SecureString]::new()
    foreach ($character in $env:GPT_REPO_SECURITY_PASSWORD.ToCharArray()) { $securePassword.AppendChar($character) }
    $securePassword.MakeReadOnly()
    $serverStart.UserName = $env:GPT_REPO_SECURITY_USER
    $serverStart.Domain = $env:COMPUTERNAME
    $serverStart.Password = $securePassword
    $serverStart.LoadUserProfile = $true
  }

  $pipeServer = [System.Diagnostics.Process]::Start($serverStart)
  $serverErrorTask = $pipeServer.StandardError.ReadToEndAsync()
  $readyTask = $pipeServer.StandardOutput.ReadLineAsync()
  if (-not $readyTask.Wait(10000)) { throw 'The replacement pipe server did not become ready.' }
  $readyLine = $readyTask.GetAwaiter().GetResult()
  $readyParts = $readyLine.Split('|')
  if ($readyParts.Length -ne 4 -or $readyParts[0] -ne 'READY') {
    throw "The replacement pipe server returned an invalid ready line: $readyLine"
  }
  $replacementPid = [uint32]$readyParts[1]
  $replacementSid = $readyParts[2]
  $replacementCreationTime = $readyParts[3]
  $expectedPid = [uint32]$env:GPT_REPO_SECURITY_HELPER_PID
  $expectedCreationTime = $env:GPT_REPO_SECURITY_HELPER_CREATION_TIME
  if ($env:GPT_REPO_SECURITY_EXPECTED_IDENTITY_MODE -eq 'replacement-pid' -or
      $env:GPT_REPO_SECURITY_EXPECTED_IDENTITY_MODE -eq 'replacement-process') {
    $expectedPid = $replacementPid
  }
  if ($env:GPT_REPO_SECURITY_EXPECTED_IDENTITY_MODE -eq 'replacement-process') {
    $expectedCreationTime = $replacementCreationTime
  }

  $recreateExitCode = $null
  if ($env:GPT_REPO_SECURITY_TRY_SERVER_RECREATION -eq '1') {
    $serveStart = [System.Diagnostics.ProcessStartInfo]::new()
    $serveStart.FileName = $env:GPT_REPO_SECURITY_HELPER_PATH
    $serveStart.Arguments = 'serve {0} "{1}"' -f $env:GPT_REPO_SECURITY_SERVER_PID, $env:GPT_REPO_SECURITY_INSTANCE_ID
    $serveStart.WorkingDirectory = $env:GPT_REPO_SECURITY_WORKING_DIRECTORY
    $serveStart.UseShellExecute = $false
    $serveStart.RedirectStandardOutput = $true
    $serveStart.RedirectStandardError = $true
    $serveStart.CreateNoWindow = $true
    $serveStart.EnvironmentVariables['LOCALAPPDATA'] = $env:GPT_REPO_SECURITY_OWNER_LOCALAPPDATA
    $serveProcess = [System.Diagnostics.Process]::Start($serveStart)
    $serveStdoutTask = $serveProcess.StandardOutput.ReadToEndAsync()
    $serveStderrTask = $serveProcess.StandardError.ReadToEndAsync()
    if ($serveProcess.WaitForExit(5000)) {
      $recreateExitCode = $serveProcess.ExitCode
    } else {
      $serveProcess.Kill()
      $null = $serveProcess.WaitForExit(5000)
      $recreateExitCode = -1
    }
  }

  $clientStart = [System.Diagnostics.ProcessStartInfo]::new()
  $clientStart.FileName = $env:GPT_REPO_SECURITY_HELPER_PATH
  $clientStart.Arguments = 'client "{0}" 2000 {1} {2}' -f $env:GPT_REPO_SECURITY_ENDPOINT, $expectedPid, $expectedCreationTime
  $clientStart.WorkingDirectory = $env:GPT_REPO_SECURITY_WORKING_DIRECTORY
  $clientStart.UseShellExecute = $false
  $clientStart.RedirectStandardInput = $true
  $clientStart.RedirectStandardOutput = $true
  $clientStart.RedirectStandardError = $true
  $clientStart.CreateNoWindow = $true
  $clientProcess = [System.Diagnostics.Process]::Start($clientStart)
  $clientStdoutTask = $clientProcess.StandardOutput.ReadToEndAsync()
  $clientStderrTask = $clientProcess.StandardError.ReadToEndAsync()
  $frame = [Convert]::FromBase64String($env:GPT_REPO_SECURITY_FRAME)
  $clientProcess.StandardInput.BaseStream.Write($frame, 0, $frame.Length)
  $clientProcess.StandardInput.BaseStream.Flush()
  $clientProcess.StandardInput.Close()
  if (-not $clientProcess.WaitForExit(10000)) {
    $clientProcess.Kill()
    $null = $clientProcess.WaitForExit(5000)
    throw 'The native client did not exit before its deadline.'
  }
  $clientStdout = $clientStdoutTask.GetAwaiter().GetResult()
  $clientStderr = $clientStderrTask.GetAwaiter().GetResult()

  $serverResultTask = $pipeServer.StandardOutput.ReadLineAsync()
  if (-not $serverResultTask.Wait(5000)) { throw 'The replacement pipe server did not finish the connection.' }
  $serverLine = $serverResultTask.GetAwaiter().GetResult()
  if (-not $pipeServer.WaitForExit(5000)) {
    $pipeServer.Kill()
    $null = $pipeServer.WaitForExit(5000)
    throw 'The replacement pipe server did not exit after the connection.'
  }
  $serverError = $serverErrorTask.GetAwaiter().GetResult()
  [pscustomobject]@{
    serverPid = $replacementPid
    serverSid = $replacementSid
    serverCreationTime = $replacementCreationTime
    expectedHelperPid = $expectedPid
    expectedCreationTime = $expectedCreationTime
    serverLine = $serverLine
    serverError = $serverError
    clientExitCode = $clientProcess.ExitCode
    clientStdout = $clientStdout
    clientStderr = $clientStderr
    serverRecreationExitCode = $recreateExitCode
  } | ConvertTo-Json -Compress
} finally {
  foreach ($child in @($clientProcess, $serveProcess, $pipeServer)) {
    if ($null -ne $child) {
      try {
        if (-not $child.HasExited) {
          $child.Kill()
          $null = $child.WaitForExit(5000)
        }
      } catch {
        if (-not $child.HasExited) { throw }
      }
      $child.Dispose()
    }
  }
  if ($null -ne $securePassword) { $securePassword.Dispose() }
}
`;

const pipeConnectionRaceProbeScript = String.raw`
$ErrorActionPreference = 'Stop'
$serverA = $null
$serverB = $null
$clientProcess = $null
try {
  $serverAStart = [System.Diagnostics.ProcessStartInfo]::new()
  $serverAStart.FileName = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
  $serverAStart.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}"' -f $env:GPT_REPO_SECURITY_REPLACEMENT_SCRIPT
  $serverAStart.WorkingDirectory = $env:GPT_REPO_SECURITY_WORKING_DIRECTORY
  $serverAStart.UseShellExecute = $false
  $serverAStart.RedirectStandardInput = $true
  $serverAStart.RedirectStandardOutput = $true
  $serverAStart.RedirectStandardError = $true
  $serverAStart.CreateNoWindow = $true
  $serverAStart.EnvironmentVariables['GPT_REPO_SECURITY_PIPE_NAME'] = $env:GPT_REPO_SECURITY_PIPE_NAME
  $serverAStart.EnvironmentVariables['GPT_REPO_SECURITY_OWNER_SID'] = $env:GPT_REPO_SECURITY_OWNER_SID
  $serverAStart.EnvironmentVariables['GPT_REPO_SECURITY_CHANGE_DACL'] = $env:GPT_REPO_SECURITY_CHANGE_DACL
  $serverA = [System.Diagnostics.Process]::Start($serverAStart)
  $serverAErrorTask = $serverA.StandardError.ReadToEndAsync()
  $serverAReadyTask = $serverA.StandardOutput.ReadLineAsync()
  if (-not $serverAReadyTask.Wait(10000)) { throw 'The initial pipe server did not become ready.' }
  $serverAReadyLine = $serverAReadyTask.GetAwaiter().GetResult()
  $serverAReady = $serverAReadyLine.Split('|')
  if ($serverAReady.Length -ne 4 -or $serverAReady[0] -ne 'READY') {
    throw "The initial pipe server returned an invalid ready line: $serverAReadyLine"
  }

  $clientStart = [System.Diagnostics.ProcessStartInfo]::new()
  $clientStart.FileName = $env:GPT_REPO_SECURITY_TEST_HELPER_PATH
  $clientStart.Arguments = 'client "{0}" 2000 {1} {2}' -f $env:GPT_REPO_SECURITY_ENDPOINT, $serverAReady[1], $serverAReady[3]
  $clientStart.WorkingDirectory = $env:GPT_REPO_SECURITY_WORKING_DIRECTORY
  $clientStart.UseShellExecute = $false
  $clientStart.RedirectStandardInput = $true
  $clientStart.RedirectStandardOutput = $true
  $clientStart.RedirectStandardError = $true
  $clientStart.CreateNoWindow = $true
  $clientStart.EnvironmentVariables['GPT_REPO_ADMIN_TEST_FAULT'] = 'pause-after-pipe-security-check'
  $clientStart.EnvironmentVariables['GPT_REPO_ADMIN_TEST_RELEASE_MARKER'] = $env:GPT_REPO_SECURITY_CLIENT_RELEASE_MARKER
  $clientProcess = [System.Diagnostics.Process]::Start($clientStart)
  $clientVerificationTask = $clientProcess.StandardOutput.ReadLineAsync()
  $clientErrorTask = $clientProcess.StandardError.ReadToEndAsync()
  $frame = [Convert]::FromBase64String($env:GPT_REPO_SECURITY_FRAME)
  $clientProcess.StandardInput.BaseStream.Write($frame, 0, $frame.Length)
  $clientProcess.StandardInput.BaseStream.Flush()
  $clientProcess.StandardInput.Close()
  if (-not $clientVerificationTask.Wait(10000)) { throw 'The native client did not finish peer verification.' }
  $clientVerificationLine = $clientVerificationTask.GetAwaiter().GetResult()
  if ($clientVerificationLine -ne 'VERIFIED') {
    throw "The native client returned no verification marker: $clientVerificationLine"
  }

  $serverBReady = $false
  $serverBReadyLine = $null
  $serverBLine = $null
  $serverBPid = 0
  $serverBSid = ''
  $serverBExitCode = $null
  $serverBError = ''
  $serverALine = $null
  $serverAExitCode = $null
  if ($env:GPT_REPO_SECURITY_CHANGE_DACL -eq '1') {
    $serverA.StandardInput.WriteLine('CHANGE_DACL')
    $serverA.StandardInput.Flush()
    $daclChangedTask = $serverA.StandardOutput.ReadLineAsync()
    if (-not $daclChangedTask.Wait(5000)) { throw 'The pipe DACL change did not complete.' }
    $daclChangedLine = $daclChangedTask.GetAwaiter().GetResult()
    if ($daclChangedLine -ne 'DACL_CHANGED') { throw "Unexpected DACL update result: $daclChangedLine" }
  } else {
    $serverA.Kill()
    if (-not $serverA.WaitForExit(5000)) { throw 'The verified pipe server did not terminate.' }
    $serverAError = $serverAErrorTask.GetAwaiter().GetResult()
    $serverA.Dispose()
    $serverA = $null

  $serverBStart = [System.Diagnostics.ProcessStartInfo]::new()
  $serverBStart.FileName = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
  $serverBStart.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}"' -f $env:GPT_REPO_SECURITY_REPLACEMENT_SCRIPT
  $serverBStart.WorkingDirectory = $env:GPT_REPO_SECURITY_WORKING_DIRECTORY
  $serverBStart.UseShellExecute = $false
  $serverBStart.RedirectStandardOutput = $true
  $serverBStart.RedirectStandardError = $true
  $serverBStart.CreateNoWindow = $true
  $serverBStart.EnvironmentVariables['GPT_REPO_SECURITY_PIPE_NAME'] = $env:GPT_REPO_SECURITY_PIPE_NAME
  $serverBStart.EnvironmentVariables['GPT_REPO_SECURITY_OWNER_SID'] = $env:GPT_REPO_SECURITY_OWNER_SID
  $serverB = [System.Diagnostics.Process]::Start($serverBStart)
  $serverBErrorTask = $serverB.StandardError.ReadToEndAsync()
  $serverBReadyTask = $serverB.StandardOutput.ReadLineAsync()
  $serverBReadyLine = $null
  $serverBReady = $false
  if ($serverBReadyTask.Wait(10000)) {
    $serverBReadyLine = $serverBReadyTask.GetAwaiter().GetResult()
    $serverBReady = $serverBReadyLine -like 'READY|*'
  }
  if (-not $serverBReady) {
    if (-not $serverB.HasExited) {
      $serverB.Kill()
      $null = $serverB.WaitForExit(5000)
    }
    throw "The replacement pipe server did not become ready: $serverBReadyLine"
  }
  }

  [System.IO.File]::WriteAllText($env:GPT_REPO_SECURITY_CLIENT_RELEASE_MARKER, 'release')

  $clientStdoutTask = $clientProcess.StandardOutput.ReadToEndAsync()
  if (-not $clientProcess.WaitForExit(10000)) {
    $clientProcess.Kill()
    $null = $clientProcess.WaitForExit(5000)
    throw 'The native client did not exit before its deadline.'
  }
  $clientStdout = $clientStdoutTask.GetAwaiter().GetResult()
  $clientError = $clientErrorTask.GetAwaiter().GetResult()
  if ($env:GPT_REPO_SECURITY_CHANGE_DACL -eq '1') {
    $serverAResultTask = $serverA.StandardOutput.ReadLineAsync()
    if (-not $serverAResultTask.Wait(10000)) { throw 'The original pipe server did not report received bytes.' }
    $serverALine = $serverAResultTask.GetAwaiter().GetResult()
    if (-not $serverA.WaitForExit(5000)) {
      $serverA.Kill()
      $null = $serverA.WaitForExit(5000)
      throw 'The original pipe server did not exit after reporting received bytes.'
    }
    $serverAExitCode = $serverA.ExitCode
    $serverAError = $serverAErrorTask.GetAwaiter().GetResult()
  }
  $serverBLine = $null
  $serverBPid = 0
  $serverBSid = ''
  $serverBExitCode = $null
  if ($serverBReady) {
    $serverBParts = $serverBReadyLine.Split('|')
    if ($serverBParts.Length -ne 4) { throw "The replacement server returned an invalid ready line: $serverBReadyLine" }
    $serverBPid = [int]$serverBParts[1]
    $serverBSid = $serverBParts[2]
    $serverBResultTask = $serverB.StandardOutput.ReadLineAsync()
    if (-not $serverBResultTask.Wait(11000)) {
      throw 'The replacement server did not report whether it received a connection.'
    }
    $serverBLine = $serverBResultTask.GetAwaiter().GetResult()
    if (-not $serverB.WaitForExit(5000)) {
      $serverB.Kill()
      $null = $serverB.WaitForExit(5000)
      throw 'The replacement server did not exit after reporting its connection result.'
    }
    $serverBExitCode = $serverB.ExitCode
    $serverBError = $serverBErrorTask.GetAwaiter().GetResult()
  }
  if (-not $clientProcess.HasExited) { throw 'The client process did not exit.' }
  [pscustomobject]@{
    clientVerificationLine = $clientVerificationLine
    clientExitCode = $clientProcess.ExitCode
    clientStdout = $clientStdout
    clientError = $clientError
    serverASid = $serverAReady[2]
    serverALine = $serverALine
    serverAExitCode = $serverAExitCode
    serverBReady = $serverBReady
    serverBPid = $serverBPid
    serverBSid = $serverBSid
    serverBLine = $serverBLine
    serverBExitCode = $serverBExitCode
    serverBError = $serverBError
    serverAError = $serverAError
  } | ConvertTo-Json -Compress
} finally {
  foreach ($child in @($clientProcess, $serverB, $serverA)) {
    if ($null -ne $child) {
      try {
        if (-not $child.HasExited) {
          $child.Kill()
          $null = $child.WaitForExit(5000)
        }
      } catch {
        if (-not $child.HasExited) { throw }
      }
      $child.Dispose()
    }
  }
}
`;

class WindowsSecurityFixtureUnavailableError extends Error {}

function skipUnavailableSecurityFixture(
  error: unknown,
  skip: (reason: string) => void,
  required = process.env.GPT_REPO_REQUIRE_SECURITY_FIXTURES === "1"
): boolean {
  if (!(error instanceof WindowsSecurityFixtureUnavailableError)) return false;
  if (required) {
    throw new Error(`Required Windows security fixture is unavailable: ${error.message}`, { cause: error });
  }
  skip(error.message);
  return true;
}

test("required Windows security fixtures fail instead of being skipped", () => {
  const skip = vi.fn();
  expect(() => skipUnavailableSecurityFixture(
    new WindowsSecurityFixtureUnavailableError("alternate-account launch is unavailable"),
    skip,
    true
  )).toThrow("Required Windows security fixture is unavailable");
  expect(skip).not.toHaveBeenCalled();
});

describe.skipIf(process.platform !== "win32")("Windows configuration pipe identity enforcement", () => {
  test("keeps the production pipe namespace owner-controlled while admitted clients drain", async ({ skip }) => {
    const fixtureRoot = await mkdtemp(join(publicRoot, "pipe-namespace-"));
    const fixtureId = randomUUID().replaceAll("-", "");
    const userName = `PipeTest${fixtureId.slice(0, 12)}`;
    const password = `Aa1!${randomBytes(8).toString("base64url").slice(0, 10)}`;
    const sidPath = join(fixtureRoot, "claimant.sid");
    const launcherPath = join(fixtureRoot, "pipe-namespace-claim.mjs");
    const claimFixturePath = join(fixtureRoot, "pipe-namespace-claim.json");
    const stdoutPath = join(fixtureRoot, "claimant.stdout");
    const stderrPath = join(fixtureRoot, "claimant.stderr");
    const capacityPath = join(fixtureRoot, "capacity-reached");
    const workersClosedPath = join(fixtureRoot, "workers-closed");
    const releasePath = join(fixtureRoot, "release-capacity");
    const instanceId = randomUUID();
    const ownerSid = currentWindowsSid();
    let outsiderSid: string | undefined;
    let accountCreated = false;
    let localAppData: string | undefined;
    let host: Awaited<ReturnType<typeof startWindowsConfigurationAdminHost>> | undefined;
    let releaseHandlers = (): void => {};
    let requestBatch: Promise<ConfigurationAdminResponse[]> | undefined;
    let continuityProbe: Promise<ConfigurationAdminResponse> | undefined;

    try {
      try {
        createTemporaryWindowsUser(userName, password, sidPath);
        accountCreated = true;
      } catch (error) {
        if (skipUnavailableSecurityFixture(error, skip)) return;
        throw error;
      }

      outsiderSid = (await readFile(sidPath, "utf8")).trim();
      expect(outsiderSid).not.toBe(ownerSid);
      localAppData = await createOwnerLocalAppData();
      vi.stubEnv("LOCALAPPDATA", localAppData);
      vi.stubEnv("GPT_REPO_ADMIN_TEST_HELPER", "1");
      vi.stubEnv("GPT_REPO_ADMIN_TEST_FAULT", "hold-at-connection-capacity");
      vi.stubEnv("GPT_REPO_ADMIN_TEST_CAPACITY_REACHED", capacityPath);
      vi.stubEnv("GPT_REPO_ADMIN_TEST_WORKERS_CLOSED", workersClosedPath);
      vi.stubEnv("GPT_REPO_ADMIN_TEST_RELEASE_CAPACITY", releasePath);

      let helperPid: number | undefined;
      let startedCount = 0;
      let signalHandlersStarted = (): void => {};
      const handlersStarted = new Promise<void>((resolveStarted) => {
        signalHandlersStarted = resolveStarted;
      });
      let signalHandlersReleased = (): void => {};
      const handlersReleased = new Promise<void>((resolveReleased) => {
        signalHandlersReleased = resolveReleased;
      });
      releaseHandlers = signalHandlersReleased;
      const sourceIdentity = {
        status: "available" as const,
        platform: "win32" as const,
        path: join(localAppData, "configuration.json")
      };

      host = await startWindowsConfigurationAdminHost({
        serverPid: process.pid,
        instanceId,
        onHelperPid: (pid) => { helperPid = pid; },
        handle: async (value): Promise<ConfigurationAdminResponse> => {
          const request = parseAdminRequest(value);
          if (request.operation !== "probe") throw new Error("The namespace fixture accepts probe requests only.");
          startedCount += 1;
          if (startedCount === 2) signalHandlersStarted();
          await handlersReleased;
          return {
            protocol_version: 1,
            request_id: request.request_id,
            server_pid: process.pid,
            helper_pid: helperPid,
            instance_id: instanceId,
            source_identity: sourceIdentity,
            operation: "probe_result",
            effective_generation: 1,
            accepted_source_sha256: "a".repeat(64),
            pending_restart: false
          };
        }
      });

      const makeProbe = (): Promise<ConfigurationAdminResponse> => requestWindowsConfigurationAdmin(host!.record, {
        protocol_version: 1,
        request_id: randomUUID(),
        operation: "probe"
      });
      requestBatch = Promise.all([makeProbe(), makeProbe()]);
      await waitForSignal(handlersStarted, 5000, "Both owner probe requests did not reach the isolated helper.");
      await waitForTestFile(capacityPath, 5000, "The test helper did not reach its connection limit.");

      releaseHandlers();
      await requestBatch;
      await waitForTestFile(workersClosedPath, 5000, "The admitted pipe workers did not close.");

      const ownerClaim = spawnSync(testHelper, ["claim", host.record.endpoint], {
        encoding: "utf8",
        timeout: 5000,
        windowsHide: true
      });
      expect(ownerClaim.status, ownerClaim.stderr).toBe(0);
      expect(ownerClaim.stdout).toBe("CREATED\n");

      await writeFile(launcherPath, pipeNamespaceClaimLauncherSource, "utf8");
      await writeFile(claimFixturePath, JSON.stringify({ helperPath: testHelper, endpoint: host.record.endpoint }), "utf8");
      runAsWindowsUser(userName, password, launcherPath, claimFixturePath, stdoutPath, stderrPath);
      const outsiderClaim = JSON.parse(await readFile(stdoutPath, "utf8")) as {
        sid: string;
        status: number | null;
        stdout: string;
        stderr: string;
      };
      expect(outsiderClaim.sid).toBe(outsiderSid);
      expect(outsiderClaim.status, outsiderClaim.stderr).toBe(0);
      expect(outsiderClaim.stdout).toBe("NOT_CREATED\t5\n");

      await writeFile(releasePath, "continue");
      continuityProbe = makeProbe();
      await expect(continuityProbe).resolves.toMatchObject({ operation: "probe_result" });
    } finally {
      releaseHandlers();
      await writeFile(releasePath, "continue").catch(() => undefined);
      if (host) await host.close();
      if (requestBatch) await Promise.allSettled([requestBatch]);
      if (continuityProbe) await Promise.allSettled([continuityProbe]);
      vi.unstubAllEnvs();
      if (localAppData) await rm(localAppData, { recursive: true, force: true });
      await rm(fixtureRoot, { recursive: true, force: true });
      if (accountCreated) removeTemporaryWindowsUser(userName);
    }
  }, 45_000);

  test("does not dispatch through an open connection after its verified server exits", async () => {
    const fixtureRoot = await mkdtemp(join(userProfileRoot ?? publicRoot, "pipe-connection-race-"));
    const ownerSid = currentWindowsSid();
    const instanceId = randomUUID();
    const endpoint = `\\\\.\\pipe\\gpt-repo-mcp-${process.pid}-${instanceId}`;
    try {
      const result = await runPipeConnectionRaceProbe({
        endpoint,
        helperPath: testHelper,
        ownerSid,
        fixtureRoot
      });
      expect(result.clientVerificationLine).toBe("VERIFIED");
      expect(result.clientExitCode).toBe(34);
      expect(result.clientStdout).toMatch(/^NOT_DISPATCHED\t\d+\s*$/);
      expect(result.clientStdout).not.toContain("RESPONSE\n");
      expect(result.serverAError).toBe("");
      expect(result.serverBReady).toBe(true);
      expect(result.serverBSid).toBe(ownerSid);
      expect(result.serverBLine).toBe("NO_CONNECTION");
      expect(result.serverBExitCode).toBe(2);
      expect(result.serverBError).toBe("");
    } finally {
      await rm(fixtureRoot, { recursive: true, force: true });
    }
  }, 30_000);

  test("rechecks the connected pipe DACL immediately before dispatch", async () => {
    const fixtureRoot = await mkdtemp(join(userProfileRoot ?? publicRoot, "pipe-dacl-race-"));
    const ownerSid = currentWindowsSid();
    const instanceId = randomUUID();
    const endpoint = `\\\\.\\pipe\\gpt-repo-mcp-${process.pid}-${instanceId}`;
    try {
      const result = await runPipeConnectionRaceProbe({
        endpoint,
        helperPath: testHelper,
        ownerSid,
        fixtureRoot,
        changeDacl: true
      });
      expect(result.clientVerificationLine).toBe("VERIFIED");
      expect(result.clientExitCode).toBe(34);
      expect(result.clientStdout).toMatch(/^NOT_DISPATCHED\t\d+\s*$/);
      expect(result.serverASid).toBe(ownerSid);
      expect(result.serverALine).toBe("CONNECTED|0");
      expect(result.serverAExitCode).toBe(0);
      expect(result.serverAError).toBe("");
    } finally {
      await rm(fixtureRoot, { recursive: true, force: true });
    }
  }, 30_000);

  test("validates helper creation time arguments before reading a request", () => {
    const endpoint = "\\\\.\\pipe\\gpt-repo-mcp-1-22222222-2222-4222-8222-222222222222";
    for (const creationTime of ["01", "00000000000000000001", "100000000000000000000"]) {
      const result = spawnSync(productionHelper, ["client", endpoint, "2000", "1", creationTime], {
        input: Buffer.alloc(0),
        encoding: "utf8",
        timeout: 2_000,
        windowsHide: true
      });
      expect(result.status, result.stderr).toBe(5);
      expect(result.stdout).toBe("");
    }

    const maximum = spawnSync(productionHelper, [
      "client",
      endpoint,
      "2000",
      "1",
      "18446744073709551615"
    ], {
      input: Buffer.alloc(0),
      encoding: "utf8",
      timeout: 2_000,
      windowsHide: true
    });
    expect(maximum.status, maximum.stderr).toBe(31);
    expect(maximum.stdout).toBe("NOT_DISPATCHED\t0\n");
  });

  test("rejects a replacement pipe after helper exit while the owner production CLI reloads successfully", async ({ skip }) => {
    const fixtureId = randomUUID().replaceAll("-", "");
    const userName = `PipeTest${fixtureId.slice(0, 12)}`;
    const password = `Aa1!${randomBytes(8).toString("base64url").slice(0, 10)}`;
    const restrictedPaths: string[] = [];
    expect(password).toHaveLength(14);
    const ownerLocalAppData = await createOwnerLocalAppData();
    const fixtureRoot = join(publicRoot, `configuration-admin-security-${fixtureId}`);
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
        await createOutsiderDiscoveryFixture(fixtureRoot, outsiderLocalAppData);
        createTemporaryWindowsUser(userName, password, sidPath);
        ownerSid = currentWindowsSid();
      } catch (error) {
        if (error instanceof AggregateError) {
          throw new Error("Windows SID qualification requires local-account creation and alternate-credential process launch on the ephemeral CI runner.", { cause: error });
        }
        if (error instanceof WindowsSecurityFixtureUnavailableError) fixtureSkipReason = error.message;
        if (!skipUnavailableSecurityFixture(error, skip)) throw error;
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
      const helperCreationTime = ownerRecord.helper_creation_time;
      const ownerReload = runCli(builtCli, repoRoot, serverEnv, ownerRecord.server_pid);
      expect(ownerReload.status, ownerReload.stderr).toBe(0);
      expect(ownerReload.stdout).toContain("Reloaded configuration");
      expect(await fetch(`http://127.0.0.1:${serverPort}/health`).then((response) => response.ok)).toBe(true);

      const outsiderSid = (await readFile(sidPath, "utf8")).trim();
      expect(outsiderSid).not.toBe(ownerSid);
      fixtureMayBeRestricted = true;
      const serverOwnerSid = ownerSid;
      if (!serverOwnerSid) throw new Error("The production server owner SID was not established.");
      await writeOutsiderRecord(outsiderLocalAppData, outsiderSid, serverOwnerSid, ownerRecord, restrictedPaths);
      await writeFile(launcherPath, outsiderLauncherSource, "utf8");
      await writeFile(fixturePath, JSON.stringify({
        expectedSid: outsiderSid,
        localAppData: outsiderLocalAppData,
        configPath,
        cliPath: builtCli,
        helperPath: productionHelper,
        endpoint: ownerRecord.endpoint,
        helperPid: ownerRecord.helper_pid,
        helperCreationTime,
        serverPid: ownerRecord.server_pid
      }), "utf8");

      runAsWindowsUser(userName, password, launcherPath, fixturePath, stdoutPath, stderrPath);
      const result = JSON.parse(await readFile(stdoutPath, "utf8")) as {
        sid: string;
        discoveryStatus: number | null;
        discoveryOutput: string;
        discoveryError?: string;
        directStatus: number | null;
        directOutput: string;
        cliStatus: number | null;
        cliError?: string;
        cliOutput: string;
      };
      expect(result.sid).toBe(outsiderSid);
      expect(result.discoveryStatus, `${result.discoveryError ?? "no spawn error"}: ${result.discoveryOutput}`).toBe(0);
      expect(result.discoveryOutput).toContain(`"server_pid":${ownerRecord.server_pid}`);
      expect(result.directStatus).toBe(34);
      expect(result.directOutput).toContain("NOT_DISPATCHED\t5");
      expect(result.cliStatus).toBe(1);
      expect(result.cliOutput).toContain("Windows denied access to the owner-local administrative pipe.");
      expect(result.cliOutput).toContain("Configuration reload was not dispatched.");

      terminateHelperProcess(ownerRecord.helper_pid, helperCreationTime, productionHelper);
      expect(await fetch(`http://127.0.0.1:${serverPort}/health`).then((response) => response.ok)).toBe(true);
      const staleRecordPath = join(
        ownerLocalAppData,
        "GPTRepoMCP",
        "admin",
        `server-${ownerRecord.server_pid}-${ownerRecord.instance_id}.record`
      );
      const staleRecord = await readFile(staleRecordPath, "utf8");
      expect(staleRecord).toContain(`helper_pid=${ownerRecord.helper_pid}`);
      expect(staleRecord).toContain(`helper_creation_time=${helperCreationTime}`);

      const replacement = await runReplacementPipeProbe({
        endpoint: ownerRecord.endpoint,
        helperPath: productionHelper,
        helperPid: ownerRecord.helper_pid,
        helperCreationTime,
        instanceId: ownerRecord.instance_id,
        ownerLocalAppData,
        ownerSid,
        outsiderName: userName,
        outsiderPassword: password,
        serverPid: ownerRecord.server_pid,
        runAsOutsider: true,
        tryServerRecreation: true,
        fixtureRoot,
        expectedIdentityMode: "discovery"
      });
      expect(replacement.serverSid).toBe(outsiderSid);
      expect(replacement.serverPid).not.toBe(ownerRecord.helper_pid);
      expect(replacement.clientExitCode).toBe(34);
      expect(replacement.clientOutput).toContain("NOT_DISPATCHED\t5");
      expect(replacement.serverLine).toBe("CONNECTED|0");
      expect(replacement.serverRecreationExitCode).toBe(24);

      const staleHelper = await runReplacementPipeProbe({
        endpoint: ownerRecord.endpoint,
        helperPath: productionHelper,
        helperPid: ownerRecord.helper_pid,
        helperCreationTime,
        instanceId: ownerRecord.instance_id,
        ownerLocalAppData,
        ownerSid,
        outsiderName: userName,
        outsiderPassword: password,
        serverPid: ownerRecord.server_pid,
        runAsOutsider: false,
        tryServerRecreation: false,
        fixtureRoot,
        expectedIdentityMode: "discovery"
      });
      expect(staleHelper.serverSid).toBe(ownerSid);
      expect(staleHelper.serverPid).not.toBe(ownerRecord.helper_pid);
      expect(staleHelper.serverCreationTime).not.toBe(helperCreationTime);
      expect(staleHelper.clientExitCode).toBe(34);
      expect(staleHelper.clientOutput).toMatch(/NOT_DISPATCHED\t\d+/);
      expect(staleHelper.serverLine).toBe("CONNECTED|0");

      const wrongOwner = await runReplacementPipeProbe({
        endpoint: ownerRecord.endpoint,
        helperPath: productionHelper,
        helperPid: ownerRecord.helper_pid,
        helperCreationTime,
        instanceId: ownerRecord.instance_id,
        ownerLocalAppData,
        ownerSid,
        outsiderName: userName,
        outsiderPassword: password,
        serverPid: ownerRecord.server_pid,
        runAsOutsider: true,
        tryServerRecreation: false,
        ownerOnlyDacl: true,
        fixtureRoot,
        expectedIdentityMode: "replacement-process"
      });
      expect(wrongOwner.serverPid).toBe(wrongOwner.expectedHelperPid);
      expect(wrongOwner.serverCreationTime).toBe(wrongOwner.expectedCreationTime);
      expect(wrongOwner.serverSid).toBe(outsiderSid);
      expect(wrongOwner.clientExitCode).toBe(34);
      expect(wrongOwner.clientOutput).toContain("NOT_DISPATCHED\t5");
      expect(wrongOwner.serverLine).toBe("CONNECTED|0");

      const wrongDacl = await runReplacementPipeProbe({
        endpoint: ownerRecord.endpoint,
        helperPath: productionHelper,
        helperPid: ownerRecord.helper_pid,
        helperCreationTime,
        instanceId: ownerRecord.instance_id,
        ownerLocalAppData,
        ownerSid,
        outsiderName: userName,
        outsiderPassword: password,
        serverPid: ownerRecord.server_pid,
        runAsOutsider: false,
        tryServerRecreation: false,
        unexpectedDacl: true,
        fixtureRoot,
        expectedIdentityMode: "replacement-process"
      });
      expect(wrongDacl.serverSid).toBe(ownerSid);
      expect(wrongDacl.serverPid).toBe(wrongDacl.expectedHelperPid);
      expect(wrongDacl.serverCreationTime).toBe(wrongDacl.expectedCreationTime);
      expect(wrongDacl.clientExitCode).toBe(34);
      expect(wrongDacl.clientOutput).toContain("NOT_DISPATCHED\t5");
      expect(wrongDacl.serverLine).toBe("CONNECTED|0");

      // Matching PID but retaining the old creation time models a reused PID.
      const reusedPid = await runReplacementPipeProbe({
        endpoint: ownerRecord.endpoint,
        helperPath: productionHelper,
        helperPid: ownerRecord.helper_pid,
        helperCreationTime,
        instanceId: ownerRecord.instance_id,
        ownerLocalAppData,
        ownerSid,
        outsiderName: userName,
        outsiderPassword: password,
        serverPid: ownerRecord.server_pid,
        runAsOutsider: false,
        tryServerRecreation: false,
        fixtureRoot,
        expectedIdentityMode: "replacement-pid"
      });
      expect(reusedPid.serverSid).toBe(ownerSid);
      expect(reusedPid.expectedHelperPid).toBe(reusedPid.serverPid);
      expect(reusedPid.serverCreationTime).not.toBe(reusedPid.expectedCreationTime);
      expect(reusedPid.clientExitCode).toBe(34);
      expect(reusedPid.clientOutput).toContain("NOT_DISPATCHED\t5");
      expect(reusedPid.serverLine).toBe("CONNECTED|0");
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
        await takeFixtureOwnership(fixtureRoot, ownerSid, restrictedPaths);
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
const discovery = spawnSync(fixture.helperPath, ["discover"], {
  encoding: "utf8",
  timeout: 7000,
  windowsHide: true
});
const direct = spawnSync(fixture.helperPath, [
  "client",
  fixture.endpoint,
  "2000",
  String(fixture.helperPid),
  fixture.helperCreationTime
], {
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
  discoveryStatus: discovery.status,
  discoveryOutput: discovery.stdout ?? "",
  discoveryError: discovery.error?.code,
  directStatus: direct.status,
  directOutput: direct.stdout?.toString("ascii") ?? "",
  directError: direct.error?.code,
  cliStatus: cli.status,
  cliError: cli.error?.code,
  cliOutput: (cli.stdout ?? "") + (cli.stderr ?? "")
}));
`;

function createTemporaryWindowsUser(name: string, password: string, sidPath: string): void {
  try {
    execFileSync("net.exe", ["user", name, password, "/add", "/expires:never", "/passwordchg:no"], {
      encoding: "utf8",
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"]
    });
  } catch (error) {
    const detail = safeCommandFailure(error, password);
    if (/system error (5|1314|2245) has occurred|access is denied|required privilege is not held|password.*policy/i.test(detail)) {
      throw new WindowsSecurityFixtureUnavailableError(`Windows local-account creation is unavailable on this host (${detail}).`);
    }
    throw new Error(`Unexpected failure creating the isolated Windows local account (${detail}).`);
  }
  try {
    runPowerShell(String.raw`
$ErrorActionPreference = 'Stop'
$accountName = '{0}\{1}' -f $env:COMPUTERNAME, $env:GPT_REPO_SECURITY_USER
$sid = ([System.Security.Principal.NTAccount]::new($accountName)).Translate([System.Security.Principal.SecurityIdentifier]).Value
[System.IO.File]::WriteAllText($env:GPT_REPO_SECURITY_SID_PATH, $sid)
`, {
      GPT_REPO_SECURITY_USER: name,
      GPT_REPO_SECURITY_SID_PATH: sidPath
    });
  } catch (setupError) {
    try {
      execFileSync("net.exe", ["user", name, "/delete"], {
        encoding: "utf8",
        windowsHide: true,
        stdio: ["ignore", "pipe", "pipe"]
      });
    } catch (cleanupError) {
      throw new AggregateError([setupError, cleanupError], `Temporary Windows account ${name} was created but SID setup and rollback both failed.`);
    }
    throw setupError;
  }
}

async function createOutsiderDiscoveryFixture(fixtureRoot: string, localAppData: string): Promise<void> {
  try {
    await mkdir(fixtureRoot, { recursive: true });
    await mkdir(join(localAppData, "GPTRepoMCP", "admin"), { recursive: true });
  } catch (error) {
    throw new WindowsSecurityFixtureUnavailableError("The Windows host does not allow creation of the isolated public fixture directory.", { cause: error });
  }
}

function safeCommandFailure(error: unknown, secret: string): string {
  if (typeof error !== "object" || error === null) return "the command failed without a diagnostic";
  const result = error as { status?: number | null; stdout?: Buffer | string; stderr?: Buffer | string };
  const output = [result.stdout, result.stderr]
    .filter((value): value is Buffer | string => value !== undefined)
    .map((value) => Buffer.isBuffer(value) ? value.toString("utf8") : value)
    .join(" ")
    .replaceAll(secret, "[redacted]")
    .replace(/[\r\n\t]+/g, " ")
    .trim();
  const status = result.status === null || result.status === undefined ? "no exit status" : `exit ${result.status}`;
  return output ? `${status}: ${output}` : status;
}

async function writeOutsiderRecord(
  localAppData: string,
  outsiderSid: string,
  ownerSid: string,
  record: { server_pid: number; helper_pid: number; helper_creation_time: string; instance_id: string; endpoint: string },
  restrictedPaths: string[]
): Promise<void> {
  const recordPath = join(localAppData, "GPTRepoMCP", "admin", `server-${record.server_pid}-${record.instance_id}.record`);
  const contents = [
    "protocol_version=1",
    `server_pid=${record.server_pid}`,
    `helper_pid=${record.helper_pid}`,
    `helper_creation_time=${record.helper_creation_time}`,
    `instance_id=${record.instance_id}`,
    `endpoint=${record.endpoint}`,
    ""
  ].join("\n");
  await writeFile(recordPath, contents, "utf8");
  const administrationRoot = join(localAppData, "GPTRepoMCP");
  const administrationDirectory = join(administrationRoot, "admin");
  for (const path of [recordPath, administrationDirectory, administrationRoot, localAppData]) {
    setOutsiderPathAcl(path, outsiderSid, ownerSid, restrictedPaths);
  }
}

function setOutsiderPathAcl(path: string, outsiderSid: string, ownerSid: string, restrictedPaths: string[]): void {
  const permission = "F";
  execFileSync("icacls.exe", [
    path,
    "/inheritance:r",
    "/grant:r",
    `*${ownerSid}:${permission}`
  ], { encoding: "utf8", windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
  execFileSync("icacls.exe", [path, "/grant", `*${outsiderSid}:${permission}`], {
    encoding: "utf8",
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"]
  });
  execFileSync("icacls.exe", [path, "/setowner", `*${outsiderSid}`], {
    encoding: "utf8",
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"]
  });
  try {
    execFileSync("icacls.exe", [path, "/remove:g", `*${ownerSid}`], {
      encoding: "utf8",
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"]
    });
  } catch (error) {
    try {
      execFileSync("icacls.exe", [path, "/grant:r", `*${ownerSid}:F`], {
        encoding: "utf8",
        windowsHide: true,
        stdio: ["ignore", "pipe", "pipe"]
      });
    } catch (restoreError) {
      restrictedPaths.push(path);
      throw new AggregateError([error, restoreError], `Could not remove or restore the owner ACL for ${path}.`);
    }
    throw error;
  }
  restrictedPaths.push(path);
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
$secure = [System.Security.SecureString]::new()
foreach ($character in $env:GPT_REPO_SECURITY_PASSWORD.ToCharArray()) { $secure.AppendChar($character) }
$secure.MakeReadOnly()
$startInfo = [System.Diagnostics.ProcessStartInfo]::new()
$startInfo.FileName = $env:GPT_REPO_SECURITY_NODE
$startInfo.Arguments = '"{0}" "{1}"' -f $env:GPT_REPO_SECURITY_LAUNCHER, $env:GPT_REPO_SECURITY_FIXTURE_FILE
$startInfo.WorkingDirectory = $env:GPT_REPO_SECURITY_WORKING_DIRECTORY
$startInfo.UserName = $env:GPT_REPO_SECURITY_USER
$startInfo.Domain = $env:COMPUTERNAME
$startInfo.Password = $secure
$startInfo.LoadUserProfile = $true
$startInfo.UseShellExecute = $false
$startInfo.RedirectStandardOutput = $true
$startInfo.RedirectStandardError = $true
$process = $null
$stdout = $null
$stderr = $null
$exitCode = $null
try {
  $process = [System.Diagnostics.Process]::Start($startInfo)
  $stdout = $process.StandardOutput.ReadToEndAsync()
  $stderr = $process.StandardError.ReadToEndAsync()
  if (-not $process.WaitForExit(20000)) {
    try { $process.Kill() } catch {
      if (-not $process.HasExited) { throw }
    }
    if (-not $process.WaitForExit(5000)) {
      throw 'The alternate-identity qualification process did not terminate after cancellation.'
    }
    $null = $stdout.GetAwaiter().GetResult()
    $null = $stderr.GetAwaiter().GetResult()
    throw 'The alternate-identity qualification process did not exit before its deadline.'
  }
  [System.IO.File]::WriteAllText($env:GPT_REPO_SECURITY_STDOUT, $stdout.GetAwaiter().GetResult())
  [System.IO.File]::WriteAllText($env:GPT_REPO_SECURITY_STDERR, $stderr.GetAwaiter().GetResult())
  $exitCode = $process.ExitCode
} finally {
  try {
    if ($null -ne $process -and -not $process.HasExited) {
      try { $process.Kill() } catch {
        if (-not $process.HasExited) { throw }
      }
      if (-not $process.WaitForExit(5000)) {
        throw 'The alternate-identity qualification process did not terminate during cleanup.'
      }
    }
  } finally {
    if ($null -ne $process) { $process.Dispose() }
    $secure.Dispose()
  }
}
if ($exitCode -ne 0) { exit $exitCode }
`, {
    GPT_REPO_SECURITY_USER: name,
    GPT_REPO_SECURITY_PASSWORD: password,
    GPT_REPO_SECURITY_LAUNCHER: launcherPath,
    GPT_REPO_SECURITY_FIXTURE_FILE: fixturePath,
    GPT_REPO_SECURITY_NODE: process.execPath,
    GPT_REPO_SECURITY_WORKING_DIRECTORY: repoRoot,
    GPT_REPO_SECURITY_STDOUT: stdoutPath,
    GPT_REPO_SECURITY_STDERR: stderrPath
  });
}

function removeTemporaryWindowsUser(name: string): void {
  try {
    runPowerShell(String.raw`
$ErrorActionPreference = 'Stop'
$accountName = '{0}\{1}' -f $env:COMPUTERNAME, $env:GPT_REPO_SECURITY_USER
$account = [System.Security.Principal.NTAccount]::new($accountName)
try {
  $null = $account.Translate([System.Security.Principal.SecurityIdentifier])
} catch [System.Security.Principal.IdentityNotMappedException] {
  return
}
& net.exe user $env:GPT_REPO_SECURITY_USER /delete | Out-Null
$deleteExitCode = $LASTEXITCODE
if ($deleteExitCode -ne 0) {
  throw "The temporary local qualification account could not be removed (net.exe exit code $deleteExitCode)."
}
`, { GPT_REPO_SECURITY_USER: name });
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`The temporary Windows SID qualification account could not be removed: ${detail}`, { cause: error });
  }
}

async function takeFixtureOwnership(fixtureRoot: string, ownerSid: string, restrictedPaths: readonly string[]): Promise<void> {
  try {
    await lstat(fixtureRoot);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  const restorationErrors: Error[] = [];
  for (const path of [...restrictedPaths].reverse()) {
    try {
      try {
        await lstat(path);
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code === "ENOENT") continue;
        if (code !== "EPERM" && code !== "EACCES") throw error;
      }
      execFileSync("takeown.exe", ["/F", path], {
        encoding: "utf8",
        windowsHide: true,
        stdio: ["ignore", "pipe", "pipe"]
      });
      execFileSync("icacls.exe", [path, "/grant:r", `*${ownerSid}:F`], {
        encoding: "utf8",
        windowsHide: true,
        stdio: ["ignore", "pipe", "pipe"]
      });
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      restorationErrors.push(new Error(`Could not restore owner access to ${path}: ${detail}`));
    }
  }
  if (restorationErrors.length > 0) {
    throw new AggregateError(restorationErrors, `Could not restore access to ${restorationErrors.length} restricted fixture path(s).`);
  }
}

function runPowerShell(script: string, env: Record<string, string>): void {
  execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script], {
    encoding: "utf8",
    env: { ...process.env, ...env },
    timeout: 30_000,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"]
  });
}

function runPowerShellOutput(script: string, env: Record<string, string>): string {
  return execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script], {
    encoding: "utf8",
    env: { ...process.env, ...env },
    timeout: 30_000,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"]
  });
}

async function waitForSignal(signal: Promise<void>, timeoutMs: number, message: string): Promise<void> {
  let timer: NodeJS.Timeout | undefined;
  try {
    await Promise.race([
      signal,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error(message)), timeoutMs);
      })
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

async function waitForTestFile(path: string, timeoutMs: number, message: string): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      await access(path);
      return;
    } catch (error) {
      if (!(error instanceof Error && "code" in error && error.code === "ENOENT")) throw error;
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 20));
    }
  }
  throw new Error(message);
}

function terminateHelperProcess(helperPid: number, creationTime: string, helperPath: string): void {
  runPowerShell(String.raw`
$ErrorActionPreference = 'Stop'
$processInfo = [System.Diagnostics.Process]::GetProcessById([int]$env:GPT_REPO_SECURITY_HELPER_PID)
$actualCreationTime = $processInfo.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
if ($actualCreationTime -ne $env:GPT_REPO_SECURITY_HELPER_CREATION_TIME) {
  throw 'The helper PID now belongs to a different process.'
}
$actualPath = [System.IO.Path]::GetFullPath($processInfo.Path)
$expectedPath = [System.IO.Path]::GetFullPath($env:GPT_REPO_SECURITY_HELPER_PATH)
if (-not [string]::Equals($actualPath, $expectedPath, [System.StringComparison]::OrdinalIgnoreCase)) {
  throw 'The helper PID now belongs to a different executable.'
}
$processInfo.Kill()
if (-not $processInfo.WaitForExit(5000)) { throw 'The native helper did not exit after termination.' }
`, {
    GPT_REPO_SECURITY_HELPER_PID: String(helperPid),
    GPT_REPO_SECURITY_HELPER_CREATION_TIME: creationTime,
    GPT_REPO_SECURITY_HELPER_PATH: helperPath
  });
}

async function runPipeConnectionRaceProbe(options: {
  endpoint: string;
  helperPath: string;
  ownerSid: string;
  fixtureRoot: string;
  changeDacl?: boolean;
}): Promise<{
  clientVerificationLine: string;
  clientExitCode: number;
  clientStdout: string;
  serverAError: string;
  serverASid: string;
  serverALine: string | null;
  serverAExitCode: number | null;
  serverBReady: boolean;
  serverBLine: string;
  serverBExitCode: number;
  serverBSid: string;
  serverBError: string;
}> {
  const scriptPath = join(options.fixtureRoot, "replacement-pipe-server.ps1");
  await writeFile(scriptPath, replacementPipeServerSource, "utf8");
  const payload = Buffer.from(JSON.stringify({
    protocol_version: 1,
    request_id: "11111111-1111-4111-8111-111111111111",
    operation: "probe"
  }));
  const frame = Buffer.alloc(4 + payload.length);
  frame.writeUInt32BE(payload.length, 0);
  payload.copy(frame, 4);
  const result = JSON.parse(runPowerShellOutput(pipeConnectionRaceProbeScript, {
    GPT_REPO_SECURITY_PIPE_NAME: options.endpoint.slice("\\\\.\\pipe\\".length),
    GPT_REPO_SECURITY_OWNER_SID: options.ownerSid,
    GPT_REPO_SECURITY_CHANGE_DACL: options.changeDacl ? "1" : "0",
    GPT_REPO_SECURITY_REPLACEMENT_SCRIPT: scriptPath,
    GPT_REPO_SECURITY_TEST_HELPER_PATH: options.helperPath,
    GPT_REPO_SECURITY_ENDPOINT: options.endpoint,
    GPT_REPO_SECURITY_FRAME: frame.toString("base64"),
    GPT_REPO_SECURITY_CLIENT_RELEASE_MARKER: join(options.fixtureRoot, "client-release"),
    GPT_REPO_SECURITY_WORKING_DIRECTORY: repoRoot
  })) as {
    clientVerificationLine: string;
    clientExitCode: number;
    clientStdout: string;
    serverAError: string;
    serverASid: string;
    serverALine: string | null;
    serverAExitCode: number | null;
    serverBReady: boolean;
    serverBLine: string;
    serverBExitCode: number;
    serverBSid: string;
    serverBError: string;
  };
  return result;
}

async function runReplacementPipeProbe(options: {
  endpoint: string;
  helperPath: string;
  helperPid: number;
  helperCreationTime: string;
  instanceId: string;
  ownerLocalAppData: string;
  ownerSid: string;
  outsiderName: string;
  outsiderPassword: string;
  serverPid: number;
  runAsOutsider: boolean;
  tryServerRecreation: boolean;
  unexpectedDacl?: boolean;
  ownerOnlyDacl?: boolean;
  expectedIdentityMode: "discovery" | "replacement-pid" | "replacement-process";
  fixtureRoot: string;
}): Promise<{
  serverPid: number;
  serverSid: string;
  serverCreationTime: string;
  expectedHelperPid: number;
  expectedCreationTime: string;
  serverLine: string;
  clientExitCode: number;
  clientOutput: string;
  serverRecreationExitCode: number | null;
}> {
  const scriptPath = join(options.fixtureRoot, "replacement-pipe-server.ps1");
  await writeFile(scriptPath, replacementPipeServerSource, "utf8");
  const payload = Buffer.from(JSON.stringify({
    protocol_version: 1,
    request_id: "11111111-1111-4111-8111-111111111111",
    operation: "probe"
  }));
  const frame = Buffer.alloc(4 + payload.length);
  frame.writeUInt32BE(payload.length, 0);
  payload.copy(frame, 4);
  const probe = JSON.parse(runPowerShellOutput(replacementPipeProbeScript, {
    GPT_REPO_SECURITY_PIPE_NAME: options.endpoint.slice("\\\\.\\pipe\\".length),
    GPT_REPO_SECURITY_OWNER_SID: options.ownerSid,
    GPT_REPO_SECURITY_REPLACEMENT_SCRIPT: scriptPath,
    GPT_REPO_SECURITY_RUN_AS_OUTSIDER: options.runAsOutsider ? "1" : "0",
    GPT_REPO_SECURITY_OWNER_LOCALAPPDATA: options.ownerLocalAppData,
    GPT_REPO_SECURITY_PASSWORD: options.outsiderPassword,
    GPT_REPO_SECURITY_USER: options.outsiderName,
    GPT_REPO_SECURITY_HELPER_PID: String(options.helperPid),
    GPT_REPO_SECURITY_HELPER_CREATION_TIME: options.helperCreationTime,
    GPT_REPO_SECURITY_EXPECTED_IDENTITY_MODE: options.expectedIdentityMode,
    GPT_REPO_SECURITY_TRY_SERVER_RECREATION: options.tryServerRecreation ? "1" : "0",
    GPT_REPO_SECURITY_UNEXPECTED_DACL: options.unexpectedDacl ? "1" : "0",
    GPT_REPO_SECURITY_OWNER_ONLY_DACL: options.ownerOnlyDacl ? "1" : "0",
    GPT_REPO_SECURITY_SERVER_PID: String(options.serverPid),
    GPT_REPO_SECURITY_INSTANCE_ID: options.instanceId,
    GPT_REPO_SECURITY_HELPER_PATH: options.helperPath,
    GPT_REPO_SECURITY_ENDPOINT: options.endpoint,
    GPT_REPO_SECURITY_FRAME: frame.toString("base64"),
    GPT_REPO_SECURITY_WORKING_DIRECTORY: repoRoot
  })) as {
    serverPid: number;
    serverSid: string;
    serverCreationTime: string;
    expectedHelperPid: number;
    expectedCreationTime: string;
    serverLine: string;
    clientExitCode: number;
    clientStdout: string;
    serverRecreationExitCode: number | null;
  };
  return {
    serverPid: probe.serverPid,
    serverSid: probe.serverSid,
    serverCreationTime: probe.serverCreationTime,
    expectedHelperPid: probe.expectedHelperPid,
    expectedCreationTime: probe.expectedCreationTime,
    serverLine: probe.serverLine,
    clientExitCode: probe.clientExitCode,
    clientOutput: probe.clientStdout,
    serverRecreationExitCode: probe.serverRecreationExitCode
  };
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
): Promise<{ server_pid: number; helper_pid: number; helper_creation_time: string; instance_id: string; endpoint: string }> {
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
          helper_creation_time: fields.helper_creation_time!,
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
