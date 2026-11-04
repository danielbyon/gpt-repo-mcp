import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, test, vi } from "vitest";
import { withRequestTelemetry } from "../src/runtime/telemetry.js";
import type { RuntimeContext } from "../src/runtime/context.js";
import { toolCatalog } from "../src/tools/catalog.js";
import { registerCatalogTool } from "../src/tools/define-tool.js";
import { TASK_EXECUTION_POLICIES, TASK_EXECUTION_TOOL_NAMES } from "../src/tools/task-execution-policy.js";
import type { ToolDefinition } from "../src/tools/tool-definition.js";
import { gitStatusHandler } from "../src/tools/handlers.js";

describe("tool handler validation boundary", () => {
  test("keeps every enrolled tool on the central execution policy map", () => {
    const mappedNames = Object.keys(TASK_EXECUTION_POLICIES).sort();
    const enrolledNames = toolCatalog.filter((tool) => tool.taskExecution).map((tool) => tool.name).sort();
    expect(mappedNames).toEqual([...TASK_EXECUTION_TOOL_NAMES].sort());
    expect(enrolledNames).toEqual(mappedNames);
    expect(toolCatalog.find((tool) => tool.name === "repo_review_patchset")?.taskExecution?.({ repo_id: "fixture-repo" }))
      .toEqual({ repo_id: "fixture-repo", operation: "patchset_review" });
  });

  test("validates input against the tool contract before using runtime services", async () => {
    let registryUsed = false;
    const context = {
      registry: {
        get() {
          registryUsed = true;
          throw new Error("registry should not be used for invalid input");
        },
        list() {
          registryUsed = true;
          throw new Error("registry should not be used for invalid input");
        }
      }
    } as unknown as RuntimeContext;

    const result = await gitStatusHandler({}, context);
    const structured = result.structuredContent as { error: { code: string } };

    expect(registryUsed).toBe(false);
    expect(result.isError).toBe(true);
    expect(structured.error.code).toBe("VALIDATION_ERROR");
  });

  test("validates task metadata input before selecting an enrolled operation", async () => {
    const sourceTool = toolCatalog.find((tool) => tool.name === "repo_validate")!;
    const taskExecution = vi.fn(sourceTool.taskExecution);
    const handler = vi.fn(sourceTool.handler);
    const tool: ToolDefinition = { ...sourceTool, taskExecution, handler };
    let invoke: ((args: unknown) => Promise<CallToolResult>) | undefined;
    const server = {
      registerTool: (_name: string, _config: unknown, callback: (args: unknown) => Promise<CallToolResult>) => {
        invoke = callback;
      }
    } as unknown as McpServer;
    const context = {
      registry: { get: vi.fn(), list: vi.fn() }
    } as unknown as RuntimeContext;

    registerCatalogTool(server, context, tool);
    const result = await invoke!({ repo_id: 42 });

    expect(result.isError).toBe(true);
    expect(result.structuredContent).toMatchObject({ error: { code: "VALIDATION_ERROR" } });
    expect(taskExecution).not.toHaveBeenCalled();
    expect(handler).not.toHaveBeenCalled();
    expect(context.registry.get).not.toHaveBeenCalled();
  });


  test("forwards protocol cancellation to the catalog tool handler", async () => {
    const sourceTool = toolCatalog.find((tool) => tool.name === "repo_list_roots")!;
    const server = new McpServer({ name: "cancellation-test", version: "0.1.0" });
    let receivedSignal: AbortSignal | undefined;
    let markStarted!: () => void;
    const started = new Promise<void>((resolve) => { markStarted = resolve; });
    const handler: ToolDefinition["handler"] = async (_input, _context, _taskExecution, signal) => {
      receivedSignal = signal;
      markStarted();
      await new Promise<void>((resolve) => {
        if (signal?.aborted) resolve();
        else signal?.addEventListener("abort", () => resolve(), { once: true });
      });
      return { content: [{ type: "text", text: "cancelled" }] };
    };
    const tool: ToolDefinition = { ...sourceTool, handler };
    const client = new Client({ name: "cancellation-test-client", version: "0.1.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const controller = new AbortController();

    registerCatalogTool(server, {} as RuntimeContext, tool);
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
    try {
      const request = client.callTool({ name: tool.name, arguments: {} }, undefined, { signal: controller.signal });
      await started;
      controller.abort();
      await expect(request).rejects.toThrow();

      expect(receivedSignal).toBeDefined();
      expect(receivedSignal?.aborted).toBe(true);
    } finally {
      await client.close();
      await server.close();
    }
  });

  test("aborts the tool handler when the MCP server closes", async () => {
    const sourceTool = toolCatalog.find((tool) => tool.name === "repo_list_roots")!;
    const server = new McpServer({ name: "server-cancellation-test", version: "0.1.0" });
    let receivedSignal: AbortSignal | undefined;
    let markStarted!: () => void;
    const started = new Promise<void>((resolve) => { markStarted = resolve; });
    const handler: ToolDefinition["handler"] = async (_input, _context, _taskExecution, signal) => {
      receivedSignal = signal;
      markStarted();
      await new Promise<void>((resolve) => {
        if (signal?.aborted) resolve();
        else signal?.addEventListener("abort", () => resolve(), { once: true });
      });
      return { content: [{ type: "text", text: "closed" }] };
    };
    const tool: ToolDefinition = { ...sourceTool, handler };
    const client = new Client({ name: "server-cancellation-client", version: "0.1.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();

    registerCatalogTool(server, {} as RuntimeContext, tool);
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
    try {
      const request = client.callTool({ name: tool.name, arguments: {} });
      await started;
      await server.close();
      await expect(request).rejects.toThrow();

      expect(receivedSignal?.aborted).toBe(true);
    } finally {
      await client.close();
    }
  });

  test("combines the HTTP disconnect signal with the MCP request signal", async () => {
    const sourceTool = toolCatalog.find((tool) => tool.name === "repo_list_roots")!;
    const server = new McpServer({ name: "combined-signal-test", version: "0.1.0" });
    let receivedSignal: AbortSignal | undefined;
    let markStarted!: () => void;
    const started = new Promise<void>((resolve) => { markStarted = resolve; });
    const handler: ToolDefinition["handler"] = async (_input, _context, _taskExecution, signal) => {
      receivedSignal = signal;
      markStarted();
      await new Promise<void>((resolve) => {
        if (signal?.aborted) resolve();
        else signal?.addEventListener("abort", () => resolve(), { once: true });
      });
      return { content: [{ type: "text", text: "ok" }] };
    };
    const tool: ToolDefinition = { ...sourceTool, handler };
    const client = new Client({ name: "combined-signal-client", version: "0.1.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const httpController = new AbortController();
    const protocolController = new AbortController();

    registerCatalogTool(server, {} as RuntimeContext, tool);
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
    try {
      const request = withRequestTelemetry({ request_id: "disconnect-test", abort_signal: httpController.signal }, () =>
        client.callTool({ name: tool.name, arguments: {} }, undefined, { signal: protocolController.signal })
      );
      await started;
      httpController.abort();

      expect(receivedSignal?.aborted).toBe(true);
      expect(protocolController.signal.aborted).toBe(false);
      protocolController.abort();
      await expect(request).rejects.toThrow();
    } finally {
      await client.close();
      await server.close();
    }
  });

  test("combines request signals when AbortSignal.any is unavailable", async () => {
    const originalAnyDescriptor = Object.getOwnPropertyDescriptor(AbortSignal, "any");
    const sourceTool = toolCatalog.find((tool) => tool.name === "repo_list_roots")!;
    const server = new McpServer({ name: "fallback-signal-test", version: "0.1.0" });
    const client = new Client({ name: "fallback-signal-client", version: "0.1.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const httpController = new AbortController();
    const protocolController = new AbortController();
    const started = deferred<void>();
    let receivedSignal: AbortSignal | undefined;
    const handler: ToolDefinition["handler"] = async (_input, _context, _taskExecution, signal) => {
      receivedSignal = signal;
      started.resolve();
      await new Promise<void>((resolve) => {
        if (signal?.aborted) resolve();
        else signal?.addEventListener("abort", () => resolve(), { once: true });
      });
      return { structuredContent: { repos: [] }, content: [{ type: "text", text: "aborted" }] };
    };

    Object.defineProperty(AbortSignal, "any", { configurable: true, value: undefined });
    try {
      registerCatalogTool(server, {} as RuntimeContext, { ...sourceTool, handler });
      await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
      const request = withRequestTelemetry(
        { request_id: "fallback-disconnect-test", abort_signal: httpController.signal },
        () => client.callTool({ name: sourceTool.name, arguments: {} }, undefined, { signal: protocolController.signal })
      ) as Promise<CallToolResult>;
      const invocationStarted = await Promise.race([
        started.promise.then(() => true),
        request.then(() => false, () => false)
      ]);

      expect(invocationStarted).toBe(true);
      httpController.abort();

      await expect(request).resolves.toMatchObject({ structuredContent: { repos: [] } });
      expect(receivedSignal?.aborted).toBe(true);
      expect(protocolController.signal.aborted).toBe(false);
    } finally {
      if (originalAnyDescriptor) {
        Object.defineProperty(AbortSignal, "any", originalAnyDescriptor);
      } else {
        Reflect.deleteProperty(AbortSignal, "any");
      }
      await client.close();
      await server.close();
    }
    expect(Object.getOwnPropertyDescriptor(AbortSignal, "any")).toEqual(originalAnyDescriptor);
  });

  test("keeps concurrent HTTP cancellation signals bound to their own tool calls", async () => {
    const sourceTool = toolCatalog.find((tool) => tool.name === "repo_validate")!;
    const server = new McpServer({ name: "concurrent-cancellation-test", version: "0.1.0" });
    const client = new Client({ name: "concurrent-cancellation-client", version: "0.1.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const calls = ["first", "second"] as const;
    const starts = new Map(calls.map((call) => [call, deferred<void>()]));
    const signals = new Map<string, AbortSignal>();
    const releases = new Map<string, () => void>();
    const handler: ToolDefinition["handler"] = async (input, _context, _taskExecution, signal) => {
      const call = (input as { repo_id: string }).repo_id;
      signals.set(call, signal!);
      starts.get(call as typeof calls[number])?.resolve();
      await new Promise<void>((resolve) => {
        if (signal?.aborted) {
          resolve();
          return;
        }
        const onAbort = (): void => resolve();
        signal?.addEventListener("abort", onAbort, { once: true });
        releases.set(call, () => {
          signal?.removeEventListener("abort", onAbort);
          resolve();
        });
      });
      return { content: [{ type: "text", text: call }] };
    };
    const tool: ToolDefinition = { ...sourceTool, taskExecution: undefined, handler };
    const firstHttp = new AbortController();
    const secondHttp = new AbortController();
    const firstProtocol = new AbortController();
    const secondProtocol = new AbortController();

    registerCatalogTool(server, {} as RuntimeContext, tool);
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
    const callTool = (call: typeof calls[number], httpSignal: AbortSignal, protocolSignal: AbortSignal) =>
      withRequestTelemetry({ request_id: `request-${call}`, abort_signal: httpSignal }, () =>
        client.callTool(
          { name: tool.name, arguments: { repo_id: call, profile: "smoke" } },
          undefined,
          { signal: protocolSignal }
        )
      );
    const firstRequest = Promise.resolve(callTool("first", firstHttp.signal, firstProtocol.signal));
    const secondRequest = Promise.resolve(callTool("second", secondHttp.signal, secondProtocol.signal));

    try {
      await Promise.all(calls.map((call) => starts.get(call)!.promise));
      firstHttp.abort();
      await firstRequest;

      expect(signals.get("first")?.aborted).toBe(true);
      expect(signals.get("second")?.aborted).toBe(false);
      releases.get("second")?.();
      await secondRequest;
      expect(secondProtocol.signal.aborted).toBe(false);
    } finally {
      firstHttp.abort();
      secondHttp.abort();
      releases.get("first")?.();
      releases.get("second")?.();
      await Promise.all([firstRequest.catch(() => undefined), secondRequest.catch(() => undefined)]);
      await client.close();
      await server.close();
    }
  });
});

function deferred<T>(): { promise: Promise<T>; resolve: (value: T | PromiseLike<T>) => void } {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((complete) => { resolve = complete; });
  return { promise, resolve };
}
