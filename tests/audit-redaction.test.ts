import { describe, expect, test } from "vitest";
import {
  createAuditEvent,
  requestAudit,
  withRequestTelemetry
} from "../src/runtime/telemetry.js";
import { redactSensitiveText } from "../src/runtime/result-envelope.js";

describe("audit redaction", () => {
  test("redacts supported absolute path roots without changing output labels", () => {
    expect(redactSensitiveText("rustc=/Volumes/Test Scratch/tmp/run-42/bin/rustc threads=1"))
      .toBe("rustc=[REDACTED_PATH] threads=1");
    expect(redactSensitiveText('source="/Volumes/Test Scratch/tmp/validation runs/stdout.txt" status=failed'))
      .toBe('source="[REDACTED_PATH]" status=failed');
    expect(redactSensitiveText('source="/Volumes/Test\' Scratch/tmp/validation.txt" status=failed'))
      .toBe('source="[REDACTED_PATH]" status=failed');
    expect(redactSensitiveText('source="/Volumes/Test Scratch/folder\\"quoted/file.txt" status=failed'))
      .toBe('source="[REDACTED_PATH]" status=failed');
    expect(redactSensitiveText("source='/Volumes/Owner'\\''s Drive/file.txt' status=failed"))
      .toBe("source='[REDACTED_PATH]' status=failed");
    expect(redactSensitiveText("source=/Volumes/Test Scratch/Project, Final/report.txt threads=1"))
      .toBe("source=[REDACTED_PATH] threads=1");
    expect(redactSensitiveText("path=/Volumes/'Build Volume'/tmp/run-42/output.txt status=failed"))
      .toBe("path=[REDACTED_PATH] status=failed");
    expect(redactSensitiveText('source="/Volumes/Test Scratch/tmp/run status=failed" status=ok'))
      .toBe('source="[REDACTED_PATH]" status=ok');
    expect(redactSensitiveText("source=/Volumes/Build Scratch/tmp/Customer; Quarter/report.txt status=failed"))
      .toBe("source=[REDACTED_PATH] status=failed");
    expect(redactSensitiveText("source=/Volumes/Build Scratch/tmp/run status=failed/archive.txt result=ok"))
      .toBe("source=[REDACTED_PATH] result=ok");
    expect(redactSensitiveText("source=/Volumes/Build Scratch/tmp/dir: status=failed/file.txt result=ok"))
      .toBe("source=[REDACTED_PATH] result=ok");
    expect(redactSensitiveText("source=/Volumes/Test Scratch/tmp/run target=/Volumes/Other Drive/tmp/next status=ok"))
      .toBe("source=[REDACTED_PATH] target=[REDACTED_PATH] status=ok");
    expect(redactSensitiveText("source=/Volumes/Test Scratch/tmp/run url=https://example.test/Volumes/releases/v1 status=ok"))
      .toBe("source=[REDACTED_PATH] url=https://example.test/Volumes/releases/v1 status=ok");
    expect(redactSensitiveText("asset=file:///Volumes/Build%20Scratch/Docs/plan.txt status=failed"))
      .toBe("asset=file:///[REDACTED_PATH] status=failed");
    expect(redactSensitiveText("volume=/Volumes/Test Scratch"))
      .toBe("volume=[REDACTED_PATH]");
    expect(redactSensitiveText("url=https://example.test/Volumes/releases/v1 status=ok"))
      .toBe("url=https://example.test/Volumes/releases/v1 status=ok");
    expect(redactSensitiveText("user=/Users/example/project home=/home/example/project tmp=/tmp/run-42"))
      .toBe("user=[REDACTED_PATH] home=[REDACTED_PATH] tmp=[REDACTED_PATH]");
    expect(redactSensitiveText("cache=C:\\Users\\example\\AppData\\Local\\Temp\\run-42 status=failed"))
      .toBe("cache=[REDACTED_PATH] status=failed");
    expect(redactSensitiveText("toolchain=1.98.1; threads=1; cargo-home-matches=true"))
      .toBe("toolchain=1.98.1; threads=1; cargo-home-matches=true");
  });

  test("redacts absolute paths and secret-looking values from audit event fields", () => {
    const event = createAuditEvent({
      tool: "repo_fetch_file",
      repo_id: "example",
      paths: ["/Users/example/project/.env"],
      globs: ["/tmp/private/**/*.ts"],
      warnings: ["Failed with OPENAI_API_KEY=sk-secret and /Users/example/project/.env"]
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
        mcp_tool: "repo_write_stage"
      },
      () =>
        createAuditEvent({
          tool: "repo_write_stage",
          repo_id: "example",
          paths: [".chatgpt/tool-tests/file.md"]
        })
    );

    expect(event).toMatchObject({
      request_id: "req_test",
      mcp_method: "tools/call",
      mcp_tool: "repo_write_stage",
      tool: "repo_write_stage"
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
        mcp_tool: longToolName
      },
      () =>
        createAuditEvent({
          tool: "repo_write_stage",
          repo_id: "example"
        })
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
        mcp_tool: "repo_write_file"
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
        mcp_tool: `OPENAI_API_KEY=sk-secret-${"t".repeat(200)}`
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
        error_category: "server_initialization"
      });
    } finally {
      console.error = originalError;
    }

    expect(JSON.parse(lines[0] ?? "{}")).toMatchObject({
      event: "mcp_request_error",
      request_id: "req_safe_category",
      error_category: "server_initialization"
    });
    expect(lines[0]).not.toContain("stack");
    expect(lines[0]).not.toContain("message");
    expect(lines[0]).not.toContain("body");
  });
});
