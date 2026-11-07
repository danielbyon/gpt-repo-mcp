# Process supervision outcome contract

This is the behavior contract for the validation execution boundary on POSIX
and Windows. It distinguishes the **runner's result** from the **supervisor's
ability to prove cleanup**. A confirmed command failure is not a host failure.

| Observation | Cleanup confirmed | Host failure | Cancelled | Timed out | Validation receipt |
| --- | --- | --- | --- | --- | --- |
| Command exits 0 after group/job cleanup | Yes | No | No | No | Passed |
| Command exits nonzero after cleanup | Yes | No | No | No | Failed |
| Windows command launch_failed (native error, no command started) | Yes, only with accepted terminal frame and confirmed helper exit | No | No | No | Failed artifact and latest pointer; never passed/gate-eligible |
| Command timeout followed by verified cleanup | Yes | No | No | Yes | Failed |
| Explicit cancellation followed by verified cleanup | Yes | No | Yes | No | None |
| Supervisor cannot spawn or admit its anchor | No command admitted; evidence depends on spawn/close | Yes | No | No | None |
| Supervisor control/read/wait/kill failure with cleanup confirmed | Yes | Yes | Varies | Varies | None |
| Process-group or Job Object cleanup unconfirmed | No | Either | Varies | Varies | None |
| Contradictory native terminal result frame | Not accepted as proof | Yes / invalid protocol | No success inferred | No success inferred | None |

**Precedence:** Validate confirmed cleanup first, then supervisor failure,
then cancellation. Ordinary command completion and confirmed timeout can
produce passed/failed validation, and a Windows command-launch failure with
confirmed cleanup produces a failed artifact (no exit code). It is not an
ordinary command exit or a supervisor failure. Receipt publication remains
cancellable until the `latest.json` pointer write is admitted, and
does not retroactively undo an admitted write.

On POSIX, the anchor's `spawn`, `ready`, and `start` milestones are
distinct. A failed `child.kill()` is not proof that no process exists.
Closed anchors require process-group absence evidence before confirmed
cleanup. An inaccessible group probe (for example `EPERM`) is
**uncertain**, not successful cleanup.

On Windows, terminal-frame exit and native error fields are status-specific.
Completed command frames use native error 0, with command exit code retained.
The `launch_failed` frame carries a nonzero native error and zero native
exit code, but the mapped ProcessTailResult intentionally omits `exit_code`,
reports the error in the bounded stderr tail, and has no `host_failure`
when helper cleanup is confirmed. ValidationService maps that absence of a
successful command exit to `failed`, persists a failed validation artifact,
and advances `latest.json` with `status: "failed"`. That record is
**not** a passed or gate-eligible validation receipt. Other native failure
frames also carry nonzero native errors and zero exit codes, but
`supervision_failed` is a host failure and `cleanup_unconfirmed` is
not proof of cleanup; neither may publish any artifact or latest pointer.
A helper that fails to spawn is likewise a supervisor failure rather than
a command launch failure. Confirmed cancellation uses the protocol
cancellation code; contradictory metadata fails before a validation
receipt can be published.

## Regression map

- `tests/process-exec-supervision.test.ts`: anchor spawn/READY/START,
  pre-start cancellation, kill errors, inaccessible process-group checks,
  malformed control data, and confirmed/uncertain cleanup.
- `tests/windows-process-host-protocol.test.ts`: every permitted
  terminal status and contradictory metadata.
- `tests/windows-process-host.test.ts`: helper launch races,
  cancellation, duplicate frames, host errors, and cleanup uncertainty.
- `tests/validation-service.test.ts`: synthesized Windows launch_failed
  frame mapped through the host and persisted as a failed artifact, alongside
  receipt suppression on
  supervision or cleanup failures, cancellation before admission, and
  non-cancellable admitted pointer publication.

Linux Node 20/22 CI runs the POSIX tests unfiltered. The scoped Windows
Node 20/22 workflow runs the Windows protocol and host test files.
