# Process supervision outcome contract

This is the behavior contract for the validation execution boundary on POSIX
and Windows. It distinguishes the **runner's result** from the **supervisor's
ability to prove cleanup**. A confirmed command failure is not a host failure.

| Observation | Cleanup confirmed | Host failure | Cancelled | Timed out | Validation receipt |
| --- | --- | --- | --- | --- | --- |
| Command exits 0 after group/job cleanup | Yes | No | No | No | Passed |
| Command exits nonzero after cleanup | Yes | No | No | No | Failed |
| Command timeout followed by verified cleanup | Yes | No | No | Yes | Failed |
| Explicit cancellation followed by verified cleanup | Yes | No | Yes | No | None |
| Supervisor cannot spawn or admit its anchor | No command admitted; evidence depends on spawn/close | Yes | No | No | None |
| Supervisor control/read/wait/kill failure with cleanup confirmed | Yes | Yes | Varies | Varies | None |
| Process-group or Job Object cleanup unconfirmed | No | Either | Varies | Varies | None |
| Contradictory native terminal result frame | Not accepted as proof | Yes / invalid protocol | No success inferred | No success inferred | None |

**Precedence:** Validate confirmed cleanup first, then supervisor failure,
then cancellation. Only ordinary command completion or confirmed timeout
may advance to failed/passed validation status. Receipt publication remains
cancellable until the `latest.json` pointer write is admitted, and
does not retroactively undo an admitted write.

On POSIX, the anchor's `spawn`, `ready`, and `start` milestones are
distinct. A failed `child.kill()` is not proof that no process exists.
Closed anchors require process-group absence evidence before confirmed
cleanup. An inaccessible group probe (for example `EPERM`) is
**uncertain**, not successful cleanup.

On Windows, terminal-frame exit and native error fields are status-specific.
Completed command frames use native error 0, with command exit code retained.
Failure frames carry a nonzero native error and zero command exit code.
Confirmed cancellation uses the protocol cancellation code; contradictory
metadata fails before a validation receipt can be published.

## Regression map

- `tests/process-exec-supervision.test.ts`: anchor spawn/READY/START,
  pre-start cancellation, kill errors, inaccessible process-group checks,
  malformed control data, and confirmed/uncertain cleanup.
- `tests/windows-process-host-protocol.test.ts`: every permitted
  terminal status and contradictory metadata.
- `tests/windows-process-host.test.ts`: helper launch races,
  cancellation, duplicate frames, host errors, and cleanup uncertainty.
- `tests/validation-service.test.ts`: receipt suppression on
  supervision or cleanup failures, cancellation before admission, and
  non-cancellable admitted pointer publication.

Linux Node 20/22 CI runs the POSIX tests unfiltered. The scoped Windows
Node 20/22 workflow runs the Windows protocol and host test files.
