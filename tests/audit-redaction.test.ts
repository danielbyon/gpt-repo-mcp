import { describe, expect, test } from "vitest";
import {
  createAuditEvent,
  requestAudit,
  withRequestTelemetry,
} from "../src/runtime/telemetry.js";
import { redactSensitiveText } from "../src/runtime/result-envelope.js";

describe("audit redaction", () => {
  test("redacts supported absolute path roots without changing output labels", () => {
    expect(
      redactSensitiveText(
        "rustc=/Volumes/Test Scratch/tmp/run-42/bin/rustc; threads=1",
      ),
    ).toBe("rustc=[REDACTED_PATH]; threads=1");
    expect(
      redactSensitiveText(
        "toolchain=1.98.1; threads=1; rustc=/Volumes/Test Scratch/tmp/run-42/bin/rustc; cargo-home-matches=true",
      ),
    ).toBe(
      "toolchain=1.98.1; threads=1; rustc=[REDACTED_PATH]; cargo-home-matches=true",
    );
    expect(
      redactSensitiveText(
        "rustc=/Volumes/Test Scratch/tmp/run-42/bin/rustc; cargo-home-matches=true\n",
      ),
    ).toBe("rustc=[REDACTED_PATH]; cargo-home-matches=true\n");
    expect(
      redactSensitiveText(
        "source=/Volumes/Test Scratch/tmp/run-42/plan.txt; threads=1; status=failed; detail=ok; cargo-home-matches=true",
      ),
    ).toBe(
      "source=[REDACTED_PATH]; threads=1; status=failed; detail=ok; cargo-home-matches=true",
    );
    expect(
      redactSensitiveText(
        "source=/Volumes/Client's Drive/plan.txt; status=failed; result=ok",
      ),
    ).toBe("source=[REDACTED_PATH]; status=failed; result=ok");
    expect(
      redactSensitiveText(
        'source="/Volumes/Test Scratch/tmp/validation runs/stdout.txt" status=failed',
      ),
    ).toBe('source="[REDACTED_PATH]" status=failed');
    expect(
      redactSensitiveText(
        'source="/Volumes/Test\' Scratch/tmp/validation.txt" status=failed',
      ),
    ).toBe('source="[REDACTED_PATH]" status=failed');
    expect(
      redactSensitiveText(
        'source="/Volumes/Test Scratch/folder\\"quoted/file.txt" status=failed',
      ),
    ).toBe('source="[REDACTED_PATH]" status=failed');
    expect(
      redactSensitiveText(
        "source='/Volumes/Owner'\\''s Drive/file.txt' status=failed",
      ),
    ).toBe("source='[REDACTED_PATH]' status=failed");
    expect(
      redactSensitiveText(
        "source=/Volumes/Test Scratch/Project, Final/report.txt; threads=1",
      ),
    ).toBe("source=[REDACTED_PATH]; threads=1");
    expect(
      redactSensitiveText(
        "path=/Volumes/'Build Volume'/tmp/run-42/output.txt; status=failed",
      ),
    ).toBe("path=[REDACTED_PATH]; status=failed");
    expect(
      redactSensitiveText(
        'source="/Volumes/Test Scratch/tmp/run status=failed" status=ok',
      ),
    ).toBe('source="[REDACTED_PATH]" status=ok');
    expect(
      redactSensitiveText(
        "source=/Volumes/Build Scratch/tmp/Customer; Quarter/report.txt; status=failed",
      ),
    ).toBe("source=[REDACTED_PATH]; status=failed");
    expect(
      redactSensitiveText(
        "source=/Volumes/Build Scratch/tmp/run status=failed/archive.txt; result=ok",
      ),
    ).toBe("source=[REDACTED_PATH]; result=ok");
    expect(
      redactSensitiveText(
        "source=/Volumes/Build Scratch/tmp/status=failed archive.txt",
      ),
    ).toBe("source=[REDACTED_PATH]");
    expect(
      redactSensitiveText(
        "source=/Volumes/Build Scratch/tmp/run status=failed archive.txt",
      ),
    ).toBe("source=[REDACTED_PATH]");
    expect(
      redactSensitiveText(
        "source=/Volumes/Client Drive/plan.txt; status=failed; detail=permission denied",
      ),
    ).toBe("source=[REDACTED_PATH]; status=failed; detail=permission denied");
    expect(
      redactSensitiveText(
        "source=/Volumes/Client Drive/Legal Matter=Acquisition",
      ),
    ).toBe("source=[REDACTED_PATH]");
    expect(
      redactSensitiveText("source=/Volumes/Client Drive/status=failed"),
    ).toBe("source=[REDACTED_PATH]");
    expect(
      redactSensitiveText(
        "source=/Volumes/Build Scratch/tmp/run status=failed: /Customer Data/plan.txt",
      ),
    ).toBe("source=[REDACTED_PATH]");
    expect(
      redactSensitiveText(
        "source=/Volumes/Build Scratch/tmp/dir: status=failed/file.txt; result=ok",
      ),
    ).toBe("source=[REDACTED_PATH]; result=ok");
    expect(
      redactSensitiveText(
        "source=/Volumes/Test Scratch/tmp/run; target=/Volumes/Other Drive/tmp/next; status=ok",
      ),
    ).toBe("source=[REDACTED_PATH]; target=[REDACTED_PATH]; status=ok");
    expect(
      redactSensitiveText(
        "source=/Volumes/Test Scratch/tmp/run; url=https://example.test/Volumes/releases/v1; status=ok",
      ),
    ).toBe(
      "source=[REDACTED_PATH]; url=https://example.test/Volumes/releases/v1; status=ok",
    );
    expect(
      redactSensitiveText(
        "asset=file:///Volumes/Build%20Scratch/Docs/plan.txt; status=failed",
      ),
    ).toBe("asset=file:///[REDACTED_PATH]; status=failed");
    expect(
      redactSensitiveText("profile:///Volumes/releases/v1 status=ok"),
    ).toBe("profile:///Volumes/releases/v1 status=ok");
    expect(redactSensitiveText("custom:file:///Volumes/releases/v1")).toBe(
      "custom:file:///[REDACTED_PATH]",
    );
    expect(
      redactSensitiveText(
        "asset=file://localhost/Volumes/Build%20Scratch/tmp/plan.txt; status=failed",
      ),
    ).toBe("asset=file://localhost/[REDACTED_PATH]; status=failed");
    expect(
      redactSensitiveText(
        "asset=file://build-host/Volumes/Client Drive/tmp/plan.txt; status=failed",
      ),
    ).toBe("asset=file://build-host/[REDACTED_PATH]; status=failed");
    expect(
      redactSensitiveText(
        "asset=file://operator:fixture-pass@build-host/Volumes/Client%20Drive/plan.txt; status=failed",
      ),
    ).toBe("asset=file://build-host/[REDACTED_PATH]; status=failed");
    expect(
      redactSensitiveText(
        "asset=file://operator@build-host/projects/private.txt; status=failed",
      ),
    ).toBe("asset=file://build-host/projects/private.txt; status=failed");
    expect(
      redactSensitiveText(
        "asset=file:///./Volumes/Client%20Drive/plan.txt; status=failed",
      ),
    ).toBe("asset=file:///[REDACTED_PATH]; status=failed");
    expect(
      redactSensitiveText(
        "asset=file:///tmp/../%56olumes/Client%20Drive/plan.txt; status=failed",
      ),
    ).toBe("asset=file:///[REDACTED_PATH]; status=failed");
    expect(
      redactSensitiveText(
        "asset=file:///%56olumes/Client%20Drive/plan.txt; status=failed",
      ),
    ).toBe("asset=file:///[REDACTED_PATH]; status=failed");
    expect(
      redactSensitiveText(
        "asset=file:///Volumes%2FClient%20Drive/plan.txt; status=failed",
      ),
    ).toBe("asset=file:///[REDACTED_PATH]; status=failed");
    expect(
      redactSensitiveText(
        "asset=file://build-host/Users/Alice/Documents/plan.txt; status=failed",
      ),
    ).toBe("asset=file://build-host/[REDACTED_PATH]; status=failed");
    expect(
      redactSensitiveText(
        "asset=file:///C:/Users/Alice/Documents/plan.txt; status=failed",
      ),
    ).toBe("asset=file:///[REDACTED_PATH]; status=failed");
    expect(
      redactSensitiveText("url=https://example.test/tmp/releases/v1 status=ok"),
    ).toBe("url=https://example.test/tmp/releases/v1 status=ok");
    expect(redactSensitiveText("url=custom:/tmp/releases/v1 status=ok")).toBe(
      "url=custom:/tmp/releases/v1 status=ok",
    );
    expect(redactSensitiveText("volume=/Volumes/Test Scratch")).toBe(
      "volume=[REDACTED_PATH]",
    );
    expect(
      redactSensitiveText(
        "url=https://example.test/Volumes/releases/v1 status=ok",
      ),
    ).toBe("url=https://example.test/Volumes/releases/v1 status=ok");
    expect(
      redactSensitiveText(
        "user=/Users/example/project home=/home/example/project tmp=/tmp/run-42",
      ),
    ).toBe("user=[REDACTED_PATH] home=[REDACTED_PATH] tmp=[REDACTED_PATH]");
    expect(
      redactSensitiveText(
        "cache=C:\\Users\\example\\AppData\\Local\\Temp\\run-42 status=failed",
      ),
    ).toBe("cache=[REDACTED_PATH] status=failed");
    expect(
      redactSensitiveText(
        "cache=C:/Users/example/AppData/Local/Temp/run-42 temp=D:/tmp/run-42 status=failed",
      ),
    ).toBe("cache=[REDACTED_PATH] temp=[REDACTED_PATH] status=failed");
    expect(
      redactSensitiveText(
        "toolchain=1.98.1; threads=1; cargo-home-matches=true",
      ),
    ).toBe("toolchain=1.98.1; threads=1; cargo-home-matches=true");
    expect(
      redactSensitiveText(
        "rustc=/Volumes/Test Scratch/tmp/run-42/bin/rustc; threads=1; status=failed; detail=ok; cargo-home-matches=true",
      ),
    ).toBe(
      "rustc=[REDACTED_PATH]; threads=1; status=failed; detail=ok; cargo-home-matches=true",
    );
  });

  test("redacts percent-encoded Windows drive file URIs", () => {
    expect(
      redactSensitiveText(
        "asset=file:///C%3A/Users/Test/private.txt status=failed",
      ),
    ).toBe("asset=file:///[REDACTED_PATH] status=failed");
  });

  test("redacts percent-encoded paths in path-shaped fields", () => {
    expect(
      redactSensitiveText(
        "source=%2FVolumes%2FTest%20Scratch%2Ftmp%2Frun-42%2Fsecret.txt; status=failed",
      ),
    ).toBe("source=[REDACTED_PATH]; status=failed");
    expect(
      redactSensitiveText(
        'source="%2FVolumes%2FTest%20Scratch%2Ftmp%2Frun-42%2Fsecret.txt" status=failed',
      ),
    ).toBe('source="[REDACTED_PATH]" status=failed');
    expect(
      redactSensitiveText(
        "source=C%3A%5CUsers%5CAlice%5Cprivate.txt; status=failed",
      ),
    ).toBe("source=[REDACTED_PATH]; status=failed");
  });

  test("redacts encoded file URIs inside URL query values", () => {
    expect(
      redactSensitiveText(
        "url=https://example.test/?path=file%3A%2F%2F%2FVolumes%2FTest%20Scratch%2Ftmp%2Frun-42%2Fsecret.txt&status=failed",
      ),
    ).toBe(
      "url=https://example.test/?path=file:///[REDACTED_PATH]&status=failed",
    );
  });

  test("redacts credentials in percent-encoded remote file URIs", () => {
    expect(
      redactSensitiveText(
        "target=file%3A%2F%2Foperator%3Asynthetic%40build-host",
      ),
    ).toBe("target=file://build-host");
  });

  test("redacts percent-encoded paths in URL fragments", () => {
    expect(
      redactSensitiveText(
        "url=https://example.test/#path=%2FVolumes%2FTest%20Scratch%2Ftmp%2Fsecret.txt",
      ),
    ).toBe("url=https://example.test/#path=[REDACTED_PATH]");
    expect(
      redactSensitiveText(
        "asset=file:///safe/file#next=%2FUsers%2FExample%2Fprivate",
      ),
    ).toBe("asset=file:///safe/file#next=[REDACTED_PATH]");
  });

  test("redacts encoded path fields at the start of later lines", () => {
    expect(
      redactSensitiveText(
        "build finished\nsource=%2FVolumes%2FTest%20Scratch%2Ftmp%2Fsecret.txt",
      ),
    ).toBe("build finished\nsource=[REDACTED_PATH]");
  });

  test("does not carry traversal path starts across output lines", () => {
    const text =
      "cache=/Users/Alice/private.txt\nsource=relative/../Volumes/Test Scratch/tmp/run-42/secret.txt; status=failed";

    expect(redactSensitiveText(text)).toBe(
      "cache=[REDACTED_PATH]\nsource=relative/../Volumes/Test Scratch/tmp/run-42/secret.txt; status=failed",
    );
  });

  test("does not reuse traversal starts inside URI routes", () => {
    const uriOutput =
      "label=/safe/path info=https://host.invalid/x/../Volumes/Example/private status=failed";
    expect(redactSensitiveText(uriOutput)).toBe(uriOutput);
  });

  test("does not reuse traversal starts across output text", () => {
    const text =
      "label=/safe/path message text/../Volumes/Test Scratch/tmp/run-42/secret.txt; status=failed";
    expect(
      redactSensitiveText(text),
    ).toBe(text);
  });

  test("preserves non-file URI routes containing volume-like segments", () => {
    expect(
      redactSensitiveText("url=https://[2001:db8::1]/Volumes/releases/v1"),
    ).toBe("url=https://[2001:db8::1]/Volumes/releases/v1");
    expect(
      redactSensitiveText("url=custom:/Volumes/releases/v1 status=ok"),
    ).toBe("url=custom:/Volumes/releases/v1 status=ok");
    expect(
      redactSensitiveText("url=custom:/Users/Alice/private.txt status=ok"),
    ).toBe("url=custom:/Users/Alice/private.txt status=ok");
  });

  test("preserves trailing permission diagnostics after unquoted volume paths", () => {
    expect(
      redactSensitiveText(
        "error: cannot read /Volumes/Client Drive/tmp/run/output.txt: permission denied",
      ),
    ).toBe("error: cannot read [REDACTED_PATH]: permission denied");
    expect(
      redactSensitiveText(
        "error: cannot read /Volumes/Client Drive/tmp/run/output.txt: No such file or directory",
      ),
    ).toBe("error: cannot read [REDACTED_PATH]: No such file or directory");
  expect(
    redactSensitiveText(
      "error: cannot read /Volumes/Client Drive/file.txt: Read-only file system",
    ),
  ).toBe("error: cannot read [REDACTED_PATH]: Read-only file system");
  });

  test("redacts ambiguous field-like suffixes on unquoted volume paths", () => {
    expect(
      redactSensitiveText(
        "source=/Volumes/Client Drive status=failed detail=Customer Finance",
      ),
    ).toBe("source=[REDACTED_PATH]");
    expect(
      redactSensitiveText("source=/Volumes/Client Drive PatientAlice=ok"),
    ).toBe("source=[REDACTED_PATH]");
    expect(
      redactSensitiveText("source=/Volumes/Patient Archive detail=Alice"),
    ).toBe("source=[REDACTED_PATH]");
  });

  test("preserves output fields after unquoted volume paths", () => {
    expect(
      redactSensitiveText("source=/Volumes/Client Drive status=failed"),
    ).toBe("source=[REDACTED_PATH] status=failed");
    expect(
      redactSensitiveText("source=/Volumes/Client Drive/plan.txt; retries=2"),
    ).toBe("source=[REDACTED_PATH]; retries=2");
    expect(
      redactSensitiveText(
        "rustc=/Volumes/Test Scratch/tmp/run-42/bin/rustc threads=1 status=failed detail=ok cargo-home-matches=true",
      ),
    ).toBe(
      "rustc=[REDACTED_PATH] threads=1 status=failed detail=ok cargo-home-matches=true",
    );
    expect(
      redactSensitiveText("source=/Volumes/Client Drive/plan.txt phase=complete"),
    ).toBe("source=[REDACTED_PATH]");
    expect(
      redactSensitiveText("source=/Volumes/Client Drive patient=alice"),
    ).toBe("source=[REDACTED_PATH]");
    expect(
      redactSensitiveText("source=/Volumes/Client Drive/plan.txt phase=Complete"),
    ).toBe("source=[REDACTED_PATH]");
  });

  test("preserves bounded fields without a field-name allowlist", () => {
    expect(
      redactSensitiveText(
        "source=/Volumes/Test Scratch/tmp/run-42/file.txt; attempt_count=3; state=passed",
      ),
    ).toBe("source=[REDACTED_PATH]; attempt_count=3; state=passed");
    expect(
      redactSensitiveText(
        "source=/Volumes/Test Scratch/tmp/run-42/file.txt; endpoint=https://example.test/releases/v1",
      ),
    ).toBe(
      "source=[REDACTED_PATH]; endpoint=https://example.test/releases/v1",
    );
  });

  test("redacts separator-rich paths and retains the final output field", () => {
    const fieldLikePathSegments = Array.from(
      { length: 128 },
      (_, index) => `field${index}=value`,
    ).join("; ");
    expect(
      redactSensitiveText(
        `source=/Volumes/Test Scratch/root; ${fieldLikePathSegments}; malformed; status=failed`,
      ),
    ).toBe("source=[REDACTED_PATH]; status=failed");
  });

  test("redacts repeated path fields and preserves the final output field", () => {
    const count = 128;
    const inputFields = Array.from(
      { length: count },
      (_, index) =>
        "path" +
        index +
        "=/Volumes/Test Scratch/tmp/run-" +
        index +
        "/artifact.txt",
    );
    const expectedFields = Array.from(
      { length: count },
      (_, index) => "path" + index + "=[REDACTED_PATH]",
    );

    expect(
      redactSensitiveText(inputFields.join("; ") + "; status=failed"),
    ).toBe(expectedFields.join("; ") + "; status=failed");
  });

  test("redacts POSIX path values in recognized field suffixes", () => {
    expect(
      redactSensitiveText(
        "source=/Volumes/Client Drive; detail=/Users/Alice/private",
      ),
    ).toBe("source=[REDACTED_PATH]; detail=[REDACTED_PATH]");
  });

  test("redacts file URI paths in recognized URL field suffixes", () => {
    expect(
      redactSensitiveText(
        "source=/Volumes/Client Drive; url=file:///Users/Alice/private",
      ),
    ).toBe("source=[REDACTED_PATH]; url=file:///[REDACTED_PATH]");
  });

  test("redacts sensitive file URI paths with spaces and preserves explicit fields", () => {
    expect(
      redactSensitiveText(
        "asset=file:///Users/Alice/Private Matter/plan.txt; status=failed",
      ),
    ).toBe("asset=file:///[REDACTED_PATH]; status=failed");
  });

  test("redacts file URIs with repeated leading path slashes", () => {
    expect(
      redactSensitiveText(
        "asset=file:////Volumes/Client Drive/secret.txt; status=failed",
      ),
    ).toBe("asset=file:///[REDACTED_PATH]; status=failed");
    expect(
      redactSensitiveText(
        "asset=file:////operator:password@build-host/Volumes/Client/secret.txt",
      ),
  ).toBe("asset=file:///[REDACTED_PATH]");
  expect(redactSensitiveText("asset=file:////workspace/tmp/build.log")).toBe(
    "asset=file:////workspace/tmp/build.log",
  );
  });

  test("redacts malformed encoded external-volume file URIs", () => {
    expect(
      redactSensitiveText(
        "asset=file:///%56olumes/Client%ZZ/plan.txt; status=failed",
      ),
    ).toBe("asset=file:///[REDACTED_PATH]; status=failed");
    expect(redactSensitiveText("asset=file:///%56olumes%ZZ/plan.txt")).toBe(
      "asset=file:///[REDACTED_PATH]",
    );
    expect(
      redactSensitiveText(
        "asset=file:///Volu%6des%ZZ/Client%20Drive/plan.txt; status=failed",
      ),
    ).toBe("asset=file:///[REDACTED_PATH]; status=failed");
    expect(
      redactSensitiveText("asset=file:///%2FVolumes%2FArchive/plan.txt"),
    ).toBe("asset=file:///[REDACTED_PATH]");
    expect(redactSensitiveText("diagnostic=file://[malformed/path")).toBe(
      "diagnostic=file://[malformed/path",
    );
  });

  test("redacts encoded external-volume file URIs with query and fragment suffixes", () => {
    expect(
      redactSensitiveText(
        "asset=file:///%56olumes/Client%20Drive/plan.txt?next=/Users/Example/private#fragment",
      ),
    ).toBe(
      "asset=file:///[REDACTED_PATH]?next=[REDACTED_PATH]#fragment",
    );
    expect(
      redactSensitiveText(
        "asset='file:///%56olumes/Client%20Drive/plan.txt?next=/Users/Example/private' status=failed",
      ),
  ).toBe(
    "asset='file:///[REDACTED_PATH]?next=[REDACTED_PATH]' status=failed",
  );
  });

  test("preserves safe file URI query and fragment suffixes", () => {
    expect(
      redactSensitiveText(
        "asset=file:///Users/Alice/private?mode=summary#section",
      ),
    ).toBe("asset=file:///[REDACTED_PATH]?mode=summary#section");
    expect(
      redactSensitiveText(
        "asset=file://build-host/Volumes/Client%20Drive/private.txt?mode=summary#section",
      ),
    ).toBe("asset=file://build-host/[REDACTED_PATH]?mode=summary#section");
    expect(
      redactSensitiveText(
        "asset=file:///C:/Users/Alice/Private Matter/plan.txt?mode=summary#section",
      ),
    ).toBe("asset=file:///[REDACTED_PATH]?mode=summary#section");
    expect(
      redactSensitiveText(
        "asset=file:///Volumes/Client/plan.txt?next=https://example.test/Volumes/releases/v1",
      ),
    ).toBe(
      "asset=file:///[REDACTED_PATH]?next=https://example.test/Volumes/releases/v1",
    );
  });

  test("preserves non-sensitive local file URI paths", () => {
    expect(
      redactSensitiveText("asset=file:///project/build.log?mode=summary"),
    ).toBe("asset=file:///project/build.log?mode=summary");
    expect(
      redactSensitiveText(
        "asset=file:///project/build.log?next=%2FVolumes%2FClient%20Drive%2Fsecret.txt",
      ),
    ).toBe("asset=file:///project/build.log?next=[REDACTED_PATH]");
  });

  test("redacts encoded sensitive file URI query values and preserves safe suffixes", () => {
    expect(
      redactSensitiveText(
        "asset=file:///Volumes/Build/secret?next=%2F%56olumes%2FPrivate%2Fplan.txt",
      ),
    ).toBe("asset=file:///[REDACTED_PATH]?next=[REDACTED_PATH]");
    expect(
      redactSensitiveText(
        "asset=file:///Volumes/Build/secret?next=%2E%2E%2F%56olumes%2FPrivate%2Fplan.txt",
      ),
    ).toBe("asset=file:///[REDACTED_PATH]?next=[REDACTED_PATH]");
  });

  test("removes file URI user-info when the path is not sensitive", () => {
    expect(
      redactSensitiveText(
        "asset=file://operator:password@build-host/projects/private.txt; status=failed",
      ),
    ).toBe("asset=file://build-host/projects/private.txt; status=failed");
  });

  test("removes file URI user-info when no path follows the authority", () => {
    expect(
      redactSensitiveText("asset=file://operator:password@build-host"),
    ).toBe("asset=file://build-host");
  });

  test("redacts percent-encoded sensitive POSIX roots in file URIs", () => {
    expect(
      redactSensitiveText(
        "asset=file:///Users%2FAlice/private.txt; status=failed",
      ),
    ).toBe("asset=file:///[REDACTED_PATH]; status=failed");
    expect(
      redactSensitiveText(
        "asset=file:///./Users/Alice/private.txt; status=failed",
      ),
    ).toBe("asset=file:///[REDACTED_PATH]; status=failed");
  });

  test("redacts encoded external-volume file URIs with path spaces", () => {
    expect(
      redactSensitiveText(
        "asset=file://build-host/%56olumes/Client Drive/private/file; status=failed",
      ),
    ).toBe("asset=file://build-host/[REDACTED_PATH]; status=failed");
    expect(
      redactSensitiveText(
        "asset='file:///%56olumes/Client Drive/private/file' status=failed",
      ),
    ).toBe("asset='file:///[REDACTED_PATH]' status=failed");
  });

  test("preserves URL routes with Windows-like path segments", () => {
    expect(
      redactSensitiveText("url=https://example.test/C:/releases/v1 status=ok"),
    ).toBe("url=https://example.test/C:/releases/v1 status=ok");
  });

  test("preserves a quoted field after an unquoted file URI path", () => {
    expect(
      redactSensitiveText(
        'note="x" asset=file:///Volumes/Private/secret.txt; status="ok"',
      ),
    ).toBe('note="x" asset=file:///[REDACTED_PATH]; status="ok"');
  });

  test("redacts POSIX paths in file URI query and fragment values", () => {
    expect(
      redactSensitiveText(
        "asset=file:///project/file?next=/Users/Alice/private",
      ),
    ).toBe("asset=file:///project/file?next=[REDACTED_PATH]");
    expect(
      redactSensitiveText("asset=file:///project/file#ref=/tmp/run-42"),
    ).toBe("asset=file:///project/file#ref=[REDACTED_PATH]");
  });

  test("redacts POSIX paths after diagnostic labels", () => {
    expect(redactSensitiveText("error: /Users/Alice/private")).toBe(
      "error: [REDACTED_PATH]",
    );
    expect(redactSensitiveText("next=/Users/Alice/private")).toBe(
      "next=[REDACTED_PATH]",
    );
    expect(
      redactSensitiveText(
        "rustc=/Applications/../Volumes/Client/tmp/run/bin/rustc",
      ),
    ).toBe("rustc=[REDACTED_PATH]");
  });

  test("redacts POSIX paths with spaces and preserves following fields", () => {
    expect(
      redactSensitiveText(
        "path=/Users/Alice/Private Matter/plan.txt; status=failed",
      ),
    ).toBe("path=[REDACTED_PATH]; status=failed");
    expect(
      redactSensitiveText(
        'path="/Users/Alice/Private Matter/plan.txt" status=failed',
      ),
    ).toBe('path="[REDACTED_PATH]" status=failed');
    expect(
      redactSensitiveText("path=/home/alice/Work Space/config.txt detail=ok"),
    ).toBe("path=[REDACTED_PATH] detail=ok");
    expect(
      redactSensitiveText(
        "path=/private/var/Build Scratch/tmp/run-42 result=ok",
      ),
    ).toBe("path=[REDACTED_PATH] result=ok");
  });

  test("redacts private path components before a trailing permission diagnostic", () => {
    expect(
      redactSensitiveText(
        "error: cannot read /Volumes/Client Drive/permission denied/private/secret.txt: permission denied",
      ),
    ).toBe("error: cannot read [REDACTED_PATH]: permission denied");
  });

  test("redacts external-volume paths inside nested file URIs", () => {
    expect(
      redactSensitiveText(
        "custom:file:///Volumes/Client%20Drive/private.txt; status=failed",
      ),
    ).toBe("custom:file:///[REDACTED_PATH]; status=failed");
  });

  test("redacts single-slash file URIs for external-volume paths", () => {
    expect(
      redactSensitiveText(
        "asset=file:/Volumes/Client%20Drive/tmp/plan.txt; status=failed",
      ),
    ).toBe("asset=file:///[REDACTED_PATH]; status=failed");
  });

  test("redacts POSIX paths in single-slash file URIs and preserves field delimiters", () => {
    expect(
      redactSensitiveText(
        "asset=file:/Users/Alice/Documents/plan.txt; status=failed",
      ),
    ).toBe("asset=file:///[REDACTED_PATH]; status=failed");
    expect(
      redactSensitiveText(
        "asset=file:/home/alice/.config/private; status=failed",
      ),
    ).toBe("asset=file:///[REDACTED_PATH]; status=failed");
    expect(redactSensitiveText("asset=file:/tmp/run-42; status=failed")).toBe(
      "asset=file:///[REDACTED_PATH]; status=failed",
    );
  });

  test("redacts absolute paths and secret-looking values from audit event fields", () => {
    const event = createAuditEvent({
      tool: "repo_fetch_file",
      repo_id: "example",
      paths: ["/Users/example/project/.env"],
      globs: ["/tmp/private/**/*.ts"],
      warnings: [
        "Failed with OPENAI_API_KEY=sk-secret and /Users/example/project/.env",
      ],
    });

    const serialized = JSON.stringify(event);

    expect(serialized).not.toContain("/Users/example");
    expect(serialized).not.toContain("/tmp/private");
    expect(serialized).not.toContain("sk-secret");
    expect(serialized).toContain("[REDACTED_PATH]");
    expect(serialized).toContain("[REDACTED_SECRET]");
  });

  test("audit event created inside request telemetry includes safe correlation fields", () => {
    const event = withRequestTelemetry(
      {
        request_id: "req_test",
        http_method: "POST",
        route: "/mcp",
        mcp_session: "present",
        mcp_method: "tools/call",
        mcp_tool: "repo_write_stage",
      },
      () =>
        createAuditEvent({
          tool: "repo_write_stage",
          repo_id: "example",
          paths: [".chatgpt/tool-tests/file.md"],
        }),
    );

    expect(event).toMatchObject({
      request_id: "req_test",
      mcp_method: "tools/call",
      mcp_tool: "repo_write_stage",
      tool: "repo_write_stage",
    });
    expect(JSON.stringify(event)).not.toContain("mcp-session-id");
  });

  test("audit event created inside request telemetry redacts and caps MCP labels", async () => {
    const longToolName = `/Users/example/project/.env-${"x".repeat(200)}-OPENAI_API_KEY=sk-secret`;
    const event = await withRequestTelemetry(
      {
        request_id: "req_test",
        http_method: "POST",
        route: "/mcp",
        mcp_session: "present",
        mcp_method: `/tmp/private/tools/call-${"y".repeat(200)}`,
        mcp_tool: longToolName,
      },
      () =>
        createAuditEvent({
          tool: "repo_write_stage",
          repo_id: "example",
        }),
    );

    const serialized = JSON.stringify(event);
    expect(serialized).not.toContain("/Users/example");
    expect(serialized).not.toContain("/tmp/private");
    expect(serialized).not.toContain("sk-secret");
    expect(event.mcp_tool?.length).toBeLessThanOrEqual(128);
    expect(event.mcp_method?.length).toBeLessThanOrEqual(128);
  });

  test("requestAudit logs safe request metadata without request body or arguments", () => {
    const lines: string[] = [];
    const originalError = console.error;
    console.error = (message?: unknown) => {
      lines.push(String(message));
    };

    try {
      requestAudit({
        event: "mcp_request_start",
        request_id: "req_test",
        http_method: "POST",
        route: "/mcp",
        mcp_session: "present",
        mcp_method: "tools/call",
        mcp_tool: "repo_write_file",
      });
    } finally {
      console.error = originalError;
    }

    expect(lines).toHaveLength(1);
    const serialized = lines[0] ?? "";
    expect(serialized).toContain("mcp_request_start");
    expect(serialized).toContain("req_test");
    expect(serialized).toContain("repo_write_file");
    expect(serialized).not.toContain("arguments");
    expect(serialized).not.toContain("content");
    expect(serialized).not.toContain("mcp-session-id");
    expect(serialized).not.toContain("sk-secret");
    expect(serialized).not.toContain("/Users/example");
  });

  test("requestAudit redacts and caps client-controlled MCP labels", () => {
    const lines: string[] = [];
    const originalError = console.error;
    console.error = (message?: unknown) => {
      lines.push(String(message));
    };

    try {
      requestAudit({
        event: "mcp_request_start",
        request_id: "req_test",
        http_method: "POST",
        route: "/mcp",
        mcp_session: "present",
        mcp_method: `/Users/example/project/.env-${"m".repeat(200)}`,
        mcp_tool: `OPENAI_API_KEY=sk-secret-${"t".repeat(200)}`,
      });
    } finally {
      console.error = originalError;
    }

    const parsed = JSON.parse(lines[0] ?? "{}") as {
      mcp_method?: string;
      mcp_tool?: string;
    };
    const serialized = lines[0] ?? "";
    expect(serialized).not.toContain("/Users/example");
    expect(serialized).not.toContain("sk-secret");
    expect(parsed.mcp_method?.length).toBeLessThanOrEqual(128);
    expect(parsed.mcp_tool?.length).toBeLessThanOrEqual(128);
  });

  test("redacts a POSIX path after a diagnostic label", () => {
    expect(redactSensitiveText("error:/Users/Alice/private")).toBe(
      "error:[REDACTED_PATH]",
    );
  });

  test("redacts complete Windows drive paths containing /Volumes", () => {
    expect(redactSensitiveText("C:/Volumes/Client Drive/secret.txt")).toBe(
      "[REDACTED_PATH]",
    );
  });

  test("preserves URL routes with drive-shaped path components", () => {
    expect(
      redactSensitiveText("https://example.test/C:/Volumes/releases/v1"),
    ).toBe("https://example.test/C:/Volumes/releases/v1");
    expect(
      redactSensitiveText("https://example.test/C:/Users/Alice/private"),
    ).toBe("https://example.test/C:/Users/Alice/private");
  });

  test("redacts complete Windows drive paths inside file URIs", () => {
    expect(
      redactSensitiveText("file:///C:/Volumes/Build%20Scratch/tmp/secret.txt"),
    ).toBe("file:///[REDACTED_PATH]");
  });

  test("preserves single-slash custom URI routes", () => {
    expect(redactSensitiveText("custom:/Users/Alice/private")).toBe(
      "custom:/Users/Alice/private",
    );
  });

  test("redacts paths attached directly to command options", () => {
    expect(redactSensitiveText("-L/Volumes/Client Drive/tmp/run-42/lib")).toBe(
      "-L[REDACTED_PATH]",
    );
    expect(redactSensitiveText("-I/Users/Alice/private")).toBe(
      "-I[REDACTED_PATH]",
    );
    expect(redactSensitiveText("CFLAGS=-I/Volumes/Client Drive/include")).toBe(
      "CFLAGS=-I[REDACTED_PATH]",
    );
  });

  test("redacts Windows paths with spaces", () => {
    expect(
      redactSensitiveText("C:\\Users\\Alice\\Private Matter\\plan.txt"),
    ).toBe("[REDACTED_PATH]");
    expect(redactSensitiveText("cache=/C:/Users/Alice/private")).toBe(
      "cache=[REDACTED_PATH]",
    );
    expect(
      redactSensitiveText(
        "cache=C:\\Users\\Alice\\Private Matter\\plan.txt; status=failed",
      ),
    ).toBe("cache=[REDACTED_PATH]; status=failed");
  });

  test("redacts path components that resemble output fields", () => {
    expect(
      redactSensitiveText("source=/Volumes/Client Drive/folder/status=failed"),
    ).toBe("source=[REDACTED_PATH]");
    expect(
      redactSensitiveText(
        "source=C:\\Users\\Alice\\Private Matter\\plan.txt detail=permission denied",
      ),
    ).toBe("source=[REDACTED_PATH]");
  });

  test("redacts Windows file URI paths with spaces", () => {
    expect(
      redactSensitiveText(
        "asset=file:///C:/Users/Alice/Private Matter/plan.txt; status=failed",
      ),
    ).toBe("asset=file:///[REDACTED_PATH]; status=failed");
  });

  test("redacts volume paths in URL query values while preserving URL routes", () => {
    expect(
      redactSensitiveText(
        "url=https://example.test/?source=/Volumes/Client%20Drive/private.txt",
      ),
    ).toBe("url=https://example.test/?source=[REDACTED_PATH]");
    expect(
      redactSensitiveText("url=https://example.test/Volumes/releases/v1"),
    ).toBe("url=https://example.test/Volumes/releases/v1");
  expect(
    redactSensitiveText(
      "url=https://example.test/?source=%2FVolumes%2FClient%20Drive%2Ftmp%2Frun&status=failed",
    ),
  ).toBe(
    "url=https://example.test/?source=[REDACTED_PATH]&status=failed",
  );
  });

  test("redacts sensitive filesystem roots without a child path", () => {
    expect(redactSensitiveText("path=/Users")).toBe("path=[REDACTED_PATH]");
    expect(redactSensitiveText("path=/private")).toBe("path=[REDACTED_PATH]");
    expect(redactSensitiveText("path=/var")).toBe("path=[REDACTED_PATH]");
    expect(redactSensitiveText("path=/tmp")).toBe("path=[REDACTED_PATH]");
    expect(redactSensitiveText("path=/Volumes")).toBe("path=[REDACTED_PATH]");
    expect(redactSensitiveText("asset=file:///Users")).toBe(
      "asset=file:///[REDACTED_PATH]",
    );
    expect(redactSensitiveText("asset=file:///Volumes")).toBe(
      "asset=file:///[REDACTED_PATH]",
    );
  });

  test("preserves option labels while redacting path-shaped option values", () => {
    expect(redactSensitiveText("-D:/Users/Alice/private")).toBe(
      "-D:[REDACTED_PATH]",
    );
    expect(redactSensitiveText("-D:\\Users\\Alice\\private")).toBe(
      "-D:[REDACTED_PATH]",
    );
  });

  test("request errors log only an allowlisted category and request correlation", () => {
    const lines: string[] = [];
    const originalError = console.error;
    console.error = (message?: unknown) => {
      lines.push(String(message));
    };

    try {
      requestAudit({
        event: "mcp_request_error",
        request_id: "req_safe_category",
        http_method: "POST",
        route: "/mcp",
        status_code: 500,
        error_category: "server_initialization",
      });
    } finally {
      console.error = originalError;
    }

    expect(JSON.parse(lines[0] ?? "{}")).toMatchObject({
      event: "mcp_request_error",
      request_id: "req_safe_category",
      error_category: "server_initialization",
    });
    expect(lines[0]).not.toContain("stack");
    expect(lines[0]).not.toContain("message");
    expect(lines[0]).not.toContain("body");
  });
});
