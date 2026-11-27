# Windows remote named-pipe qualification

Two-host SMB status: **NOT RUN**. That procedure is optional supplementary evidence and does not block the single-host qualification or draft publication.

## Required single-host qualification

Windows CI on Node 20 and 22 is the required qualification. The native test helper creates otherwise equivalent accept-remote and reject-remote controls with matching access mode, pipe type, buffer sizes, timeout, and owner DACL. It also calls the shared production pipe factory to create the first and successor instances, then queries those exact handles with GetNamedPipeInfo. Existing Windows security tests separately exercise the production CLI and server lifecycle.

The test records the exact mode passed by the production factory to CreateNamedPipeW. It requires PIPE_REJECT_REMOTE_CLIENTS on both instances. Clearing the bit from either recorded argument must fail the regression assertion. The Windows test is required on its designated CI jobs and must fail there instead of skipping.

Microsoft documents that CreateNamedPipeW automatically rejects remote clients when this flag is set. The public GetNamedPipeInfo reference lists endpoint and pipe-type flags but does not list the remote-rejection bit. Microsoft's HLK test says GetNamedPipeInfo returns the correct option for this mode. CI treats the runtime observation as qualified only when the paired controls differ by the remote-rejection bit and the production handles match the reject-remote control. If they do not, the test reports NOT_QUALIFIED and retains the exact production-call regression evidence. Production does not use GetNamedPipeInfo for enforcement.

The owner approved single-host CI as the required gate because it checks the documented local pipe-creation contract on the Windows kernel used by CI. A two-host attempt adds a second Windows machine, SID and account coordination, DNS, SMB services, and port 445 availability. Those requirements qualify the end-to-end network path. They add infrastructure cost beyond the approved local creation-mode check, so the two-host procedure remains supplementary.

## 1. Optional two-host pass criteria

When running the supplementary check, count it as a pass only when all of these conditions hold:

1. The client and server are separate existing Windows hosts. The client can resolve the server name and reach TCP port 445.
2. The positive control connects over the network, exchanges a nonce, and reports the authenticated client SID. That SID must match the server helper's owner SID.
3. The positive-control DACL grants `ReadWrite | CreateNewInstance` to that SID. The control and production attempts use the same `NamedPipeClientStream` constructor, `PipeDirection.InOut`, and client-side options, so both request equivalent access.
4. The negative attempt targets the pipe created by the production native helper. The connection fails with `ERROR_PIPE_LOCAL` (`0xE5`). A different error is inconclusive; a successful connection fails the gate.
5. A second positive control succeeds after the negative attempt. The isolated server remains healthy and accepts a local administrative reload.

Do not infer identity from account names. Local accounts with the same name on two computers may have different SIDs. The positive control checks the SID represented by the remote connection on the server. See Microsoft's [SID guidance](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers).

## 2. Optional host and network requirements

1. **Server:** Windows 10 or 11, Node.js 20 or 22, and Visual Studio C++ Build Tools plus the Windows SDK for the installed Node architecture. The client needs no repository checkout.
2. **Client:** a second Windows 10 or 11 host with PowerShell 7.4 or later and the .NET named-pipe APIs.
3. **Identity:** use a domain account available on both hosts. Confirm the SID on each host with `whoami /user`. The server-side positive control must report that same SID. If a local account is used, proceed only when the observed server-side SID matches the helper owner SID.
4. **Network:** DNS must resolve the server, SMB named-pipe traffic must be available over TCP 445, and the server and workstation services must already be running. Do not change firewall rules, services, registry values, or machine-wide settings for this check. If a prerequisite fails, record the two-host run as NOT RUN or INCONCLUSIVE.

Named-pipe remote connections use the SMB `IPC$` share. The [production helper](../native/windows/configuration-admin-host.cpp) creates its pipe with an owner-SID DACL and `PIPE_REJECT_REMOTE_CLIENTS`; the positive control below uses a test DACL for that same owner SID. Microsoft documents the flag as automatically rejecting remote clients and defines `ERROR_PIPE_LOCAL` as “The pipe is local.” The [public GetNamedPipeInfo reference](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-getnamedpipeinfo) does not list the remote-rejection bit in its `lpFlags` table. The [HLK test](https://learn.microsoft.com/en-us/windows-hardware/test/hlk/testref/e3bcbd3f-3e9c-484a-a587-3c081cb28f7a) states that it checks whether GetNamedPipeInfo returns the option. See [CreateNamedPipeW](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createnamedpipew), [named pipes](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipes), and [system error codes](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-).

## 3. Build and start an isolated production server

On the server, check out the candidate and run the repository's normal Windows build and validation under Node 20 and Node 22. Use a Developer PowerShell whose compiler architecture matches `node -p "process.arch"`.

```powershell
npm ci
npm run build
npm test
npm run verify:dist
npm run verify:package-archive
```

For the two-host run, use either supported Node version. Start the server from a fresh PowerShell window at the repository root. These variables isolate its config, local data, and loopback health port from any existing MCP process.

```powershell
$fixture = Join-Path $env:TEMP ("gpt-repo-mcp-remote-" + [guid]::NewGuid().ToString("N"))
$env:LOCALAPPDATA = Join-Path $fixture "localappdata"
$env:GPT_REPO_CONFIG = Join-Path $fixture "config.json"
$env:GPT_REPO_HOST = "127.0.0.1"
$env:PORT = "18787"
Remove-Item Env:GPT_REPO_ADMIN_TEST_HELPER -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $env:LOCALAPPDATA -Force | Out-Null
'{"repos":[],"limits":{}}' | Set-Content -Path $env:GPT_REPO_CONFIG -Encoding utf8NoBOM

$serverOwnerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$serverHost = hostname
$serverService = Get-Service -Name LanmanServer
$serverService
if ($serverService.Status -ne "Running") { throw "The SMB server service is not running." }
if (Get-NetTCPConnection -LocalPort 18787 -State Listen -ErrorAction SilentlyContinue) {
  throw "Port 18787 is already in use; choose a free loopback port and update PORT and the health URL."
}
$productionHelper = (Resolve-Path "dist/windows-configuration-admin-host.exe").Path
Get-FileHash -Algorithm SHA256 $productionHelper
$server = Start-Process -FilePath node -ArgumentList "dist/server.js" `
  -WorkingDirectory (Get-Location).Path -PassThru
$serverPid = $server.Id
$deadline = (Get-Date).AddSeconds(15)
$health = $null
do {
  Start-Sleep -Milliseconds 250
  try { $health = Invoke-RestMethod "http://127.0.0.1:18787/health" } catch { $health = $null }
} while (-not $health -and (Get-Date) -lt $deadline)
if (-not $health) { throw "The isolated server did not become healthy." }

node dist/cli/connect-gpt.js config reload --instance $serverPid
$adminDir = Join-Path $env:LOCALAPPDATA "GPTRepoMCP\admin"
$recordFile = Get-ChildItem -LiteralPath $adminDir -Filter "server-$serverPid-*.record" |
  Select-Object -First 1
if (-not $recordFile) { throw "The isolated server did not publish a discovery record." }
$fields = @{}
Get-Content -LiteralPath $recordFile.FullName | ForEach-Object {
  $separator = $_.IndexOf('=')
  if ($separator -gt 0) { $fields[$_.Substring(0, $separator)] = $_.Substring($separator + 1) }
}
$record = [pscustomobject]@{
  server_pid = [int]$fields.server_pid
  helper_pid = [int]$fields.helper_pid
  helper_creation_time = [string]$fields.helper_creation_time
  instance_id = $fields.instance_id
  endpoint = $fields.endpoint
}
if ($record.server_pid -ne $serverPid) { throw "The record belongs to another server." }
if ($record.helper_creation_time -notmatch '^[1-9][0-9]{0,19}$') {
  throw "The discovery record has no valid helper creation time."
}
$helper = Get-CimInstance Win32_Process -Filter "ProcessId = $($record.helper_pid)"
if ($helper.ExecutablePath -ine $productionHelper) {
  throw "The isolated server is not using the production native helper."
}
$pipeName = $record.endpoint.Substring($record.endpoint.LastIndexOf('\') + 1)
"SERVER_OWNER_SID=$serverOwnerSid"
"SERVER_HOST=$serverHost"
"SERVER_PID=$serverPid"
"HELPER_PID=$($record.helper_pid)"
"HELPER_CREATION_TIME=$($record.helper_creation_time)"
"PRODUCTION_PIPE=$pipeName"
"POSITIVE_CONTROL_OWNER_SID=$serverOwnerSid"
```

Keep this server window open. Record its host name and the printed values. Do not use the owner's active MCP instance.

## 4. Run the authenticated positive control

In another PowerShell window on the server, start a new control server for each run. It creates a one-use pipe with a protected DACL granting `ReadWrite | CreateNewInstance` only to the server's current user SID.

```powershell
Add-Type -AssemblyName System.IO.Pipes.AccessControl
$positiveName = "gpt-repo-control-" + [guid]::NewGuid().ToString("N")
$serverOwnerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$security = [System.IO.Pipes.PipeSecurity]::new()
$security.SetAccessRuleProtection($true, $false)
$rule = [System.IO.Pipes.PipeAccessRule]::new(
  $serverOwnerSid,
  ([System.IO.Pipes.PipeAccessRights]::ReadWrite -bor [System.IO.Pipes.PipeAccessRights]::CreateNewInstance),
  [System.Security.AccessControl.AccessControlType]::Allow
)
$security.AddAccessRule($rule)
$control = [System.IO.Pipes.NamedPipeServerStreamAcl]::Create(
  $positiveName,
  [System.IO.Pipes.PipeDirection]::InOut,
  1,
  [System.IO.Pipes.PipeTransmissionMode]::Byte,
  [System.IO.Pipes.PipeOptions]::None,
  4096,
  4096,
  $security
)
"POSITIVE_CONTROL_PIPE=$positiveName"
$control.WaitForConnection()
$reader = [IO.StreamReader]::new($control, [Text.Encoding]::UTF8, $false, 1024, $true)
$writer = [IO.StreamWriter]::new($control, [Text.UTF8Encoding]::new($false), 1024, $true)
$writer.AutoFlush = $true
$nonce = $reader.ReadLine()
$remoteName = $control.GetImpersonationUserName()
$remoteSid = ([Security.Principal.NTAccount]::new($remoteName)).Translate(
  [Security.Principal.SecurityIdentifier]
).Value
if ($remoteSid -ne $serverOwnerSid.Value) { throw "The authenticated client SID does not match the helper owner SID." }
if ($nonce -ne "owner-local-pipe-control-v1") { throw "The control nonce did not match." }
$writer.WriteLine("ACK:$nonce")
"POSITIVE_CONTROL_REMOTE_USER=$remoteName"
"POSITIVE_CONTROL_REMOTE_SID=$remoteSid"
$control.Dispose()
```

On the client, confirm the two hosts are distinct, compare `whoami /user` with the server SID, and check DNS and SMB connectivity. Then run the following block with the control pipe name printed by the server.

```powershell
$serverName = "<server-dns-name>"
$positiveName = "<positive-control-pipe-name>"
$clientHost = hostname
"CLIENT_HOST=$clientHost"
if ($clientHost -ieq "<server-host-name>") { throw "The client and server must be different hosts." }
$workstationService = Get-Service -Name LanmanWorkstation
$workstationService
if ($workstationService.Status -ne "Running") { throw "The SMB workstation service is not running." }
Resolve-DnsName $serverName -ErrorAction Stop
$network = Test-NetConnection $serverName -Port 445
$network
if (-not $network.TcpTestSucceeded) { throw "SMB port 445 is not reachable." }
whoami /user
$serverOwnerSid = "<server-owner-sid>"
$clientSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ($clientSid -ne $serverOwnerSid) { throw "The client logon SID does not match the server helper owner SID." }
$client = [System.IO.Pipes.NamedPipeClientStream]::new(
  $serverName,
  $positiveName,
  [System.IO.Pipes.PipeDirection]::InOut,
  [System.IO.Pipes.PipeOptions]::None,
  [Security.Principal.TokenImpersonationLevel]::Impersonation
)
try {
  $client.Connect(5000)
  $reader = [IO.StreamReader]::new($client, [Text.Encoding]::UTF8, $false, 1024, $true)
  $writer = [IO.StreamWriter]::new($client, [Text.UTF8Encoding]::new($false), 1024, $true)
  $writer.AutoFlush = $true
  $writer.WriteLine("owner-local-pipe-control-v1")
  $response = $reader.ReadLine()
  if ($response -ne "ACK:owner-local-pipe-control-v1") { throw "The positive control did not exchange the nonce." }
  "POSITIVE_CONTROL_ACK=$response"
} finally {
  $client.Dispose()
}
```

The server must report the client's authenticated SID, and the client must receive the nonce acknowledgement. Repeat this positive control after the production attempt with a new pipe name. If DNS, TCP 445, the SID check, or either positive control fails, the negative result is inconclusive.

## 5. Probe the production pipe remotely

On the client, use the same `NamedPipeClientStream` constructor and access direction as the positive control. Use the exact pipe name printed by the isolated server. Do not send protocol data: a successful connection is already a failure of remote rejection.

```powershell
$serverName = "<server-dns-name>"
$pipeName = "<production-pipe-name-from-the-server>"
$client = [System.IO.Pipes.NamedPipeClientStream]::new(
  $serverName,
  $pipeName,
  [System.IO.Pipes.PipeDirection]::InOut,
  [System.IO.Pipes.PipeOptions]::None,
  [Security.Principal.TokenImpersonationLevel]::Impersonation
)
$connected = $false
$failure = $null
try {
  $client.Connect(5000)
  $connected = $client.IsConnected
} catch {
  $failure = $_.Exception
} finally {
  $client.Dispose()
}
if ($connected) { throw "FAIL: the production pipe accepted a remote client." }
if ($null -eq $failure) { throw "No connection result was captured." }
$win32Error = $failure.HResult -band 0xFFFF
if ($win32Error -ne 0xE5) {
  throw ("INCONCLUSIVE: expected ERROR_PIPE_LOCAL (0xE5), received 0x{0:X}." -f $win32Error)
}
"PRODUCTION_REMOTE_REJECTED=ERROR_PIPE_LOCAL (0xE5)"
```

The script extracts the Win32 code from the `IOException.HResult` low 16 bits. .NET documents this conversion for native I/O errors in its [IOException guidance](https://learn.microsoft.com/en-us/dotnet/standard/io/handling-io-errors).

After the second positive control passes, check the isolated server's `/health` endpoint and run the same local reload command again. The production helper must remain healthy and the discovery record must still refer to the same server and helper.

## 6. Evidence and cleanup

Preserve the host names, server and client SIDs, positive-control DACL and nonce results, DNS and TCP 445 output, production executable path and SHA-256, discovery record, production error code, health response, and local reload result. Any missing or mismatched evidence leaves remote rejection **BLOCKED**.

Stop only the isolated server and its helper, then remove only the temporary fixture directory:

```powershell
$helperPid = [int]$record.helper_pid
Stop-Process -Id $serverPid -Force
Wait-Process -Id $serverPid -ErrorAction SilentlyContinue
$deadline = (Get-Date).AddSeconds(5)
do {
  $helper = Get-Process -Id $helperPid -ErrorAction SilentlyContinue
  if ($helper) { Start-Sleep -Milliseconds 100 }
} while ($helper -and (Get-Date) -lt $deadline)
if ($helper) {
  Stop-Process -Id $helperPid -Force -ErrorAction SilentlyContinue
  Wait-Process -Id $helperPid -ErrorAction SilentlyContinue
}
Remove-Item -LiteralPath $fixture -Recurse -Force
```

Close the dedicated PowerShell window to discard its temporary environment variables. Do not change machine-wide settings or contact another MCP process. Until this optional procedure is run, record its result as **NOT RUN**. A run with missing or mismatched evidence is **INCONCLUSIVE**.
