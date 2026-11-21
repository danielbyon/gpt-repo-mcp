import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, test, vi } from "vitest";
import { withRequestTelemetry } from "../src/runtime/telemetry.js";
import type { RuntimeContext } from "../src/runtime/context.js";
import { toolCatalog } from "../src/tools/catalog.js";
import { registerCatalogTool } from "../src/tools/define-tool.js";
import type { ToolDefinition } from "../src/tools/tool-definition.js";
import { gitStatusHandler } from "../src/tools/handlers.js";

describe("tool handler validation boundary", () => {
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

  test("dispatches patchset review with ordinary tool arguments", async () => {
    const tool = toolCatalog.find(({ name }) => name === "repo_review_patchset")!;
    const handler = vi.fn<ToolDefinition["handler"]>().mockResolvedValue({
      content: [{ type: "text", text: "reviewed" }]
    });
    let invoke!: (args: unknown) => Promise<CallToolResult>;
    const server = {
      registerTool: (_name: string, _config: unknown, callback: typeof invoke) => { invoke = callback; }
    } as unknown as McpServer;
    const context = { registry: { get: vi.fn() } } as unknown as RuntimeContext;

    registerCatalogTool(server, context, { ...tool, handler });
    const args = { repo_id: "fixture-repo", patchset_id: "patchset-fixture" };
    await expect(invoke(args)).resolves.toMatchObject({ content: [{ type: "text", text: "reviewed" }] });
    expect(handler).toHaveBeenCalledTimes(1);
    expect(handler.mock.calls[0]?.slice(0, 2)).toEqual([args, context]);
    expect(context.registry.get).not.toHaveBeenCalled();
  });

  test.each([false, true])("disposes both signal listeners when a handler settles (throws: %s)", async (throws) => {
    const tool = toolCatalog.find(({ name }) => name === "repo_list_roots")!;
    const protocol = new AbortController();
    const http = new AbortController();
    const removeProtocol = vi.spyOn(protocol.signal, "removeEventListener");
    const removeHttp = vi.spyOn(http.signal, "removeEventListener");
    let invoke!: (args: unknown, extra: { signal: AbortSignal }) => Promise<CallToolResult>;
    const server = {
      registerTool: (_name: string, _config: unknown, callback: typeof invoke) => { invoke = callback; }
    } as unknown as McpServer;
    const handler: ToolDefinition["handler"] = async () => {
      if (throws) throw new Error("handler failed");
      return { content: [{ type: "text", text: "complete" }] };
    };

    registerCatalogTool(server, {} as RuntimeContext, { ...tool, handler });
    const result = await withRequestTelemetry({ request_id: "disposal-test", abort_signal: http.signal },
      () => invoke({}, { signal: protocol.signal }));
    expect(Boolean(result.isError)).toBe(throws);
    expect(removeProtocol).toHaveBeenCalledExactlyOnceWith("abort", expect.any(Function));
    expect(removeHttp).toHaveBeenCalledExactlyOnceWith("abort", expect.any(Function));
  });

  test("forwards protocol cancellation to the catalog tool handler", async () => {
    const sourceTool = toolCatalog.find((tool) => tool.name === "repo_list_roots")!;
    const server = new McpServer({ name: "cancellation-test", version: "0.1.0" });
    let receivedSignal: AbortSignal | undefined;
    const started = deferred<void>();
    const finished = deferred<void>();
    const handler: ToolDefinition["handler"] = async (_input, _context, signal) => {
      receivedSignal = signal;
      started.resolve();
      await new Promise<void>((resolve) => {
        if (signal?.aborted) resolve();
        else signal?.addEventListener("abort", () => resolve(), { once: true });
      });
      finished.resolve();
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
      await started.promise;
      controller.abort();
      await expect(request).rejects.toThrow();
      await finished.promise;

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
    const started = deferred<void>();
    const finished = deferred<void>();
    const handler: ToolDefinition["handler"] = async (_input, _context, signal) => {
      receivedSignal = signal;
      started.resolve();
      await new Promise<void>((resolve) => {
        if (signal?.aborted) resolve();
        else signal?.addEventListener("abort", () => resolve(), { once: true });
      });
      finished.resolve();
      return { content: [{ type: "text", text: "closed" }] };
    };
    const tool: ToolDefinition = { ...sourceTool, handler };
    const client = new Client({ name: "server-cancellation-client", version: "0.1.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();

    registerCatalogTool(server, {} as RuntimeContext, tool);
    await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
    try {
      const request = client.callTool({ name: tool.name, arguments: {} });
      await started.promise;
      await server.close();
      await expect(request).rejects.toThrow();
      await finished.promise;

      expect(receivedSignal?.aborted).toBe(true);
    } finally {
      await client.close();
    }
  });

  test("combines the HTTP disconnect signal with the MCP request signal", async () => {
    const sourceTool = toolCatalog.find((tool) => tool.name === "repo_list_roots")!;
    const server = new McpServer({ name: "combined-signal-test", version: "0.1.0" });
    let receivedSignal: AbortSignal | undefined;
    const started = deferred<void>();
    const finished = deferred<void>();
    const handler: ToolDefinition["handler"] = async (_input, _context, signal) => {
      receivedSignal = signal;
      started.resolve();
      await new Promise<void>((resolve) => {
        if (signal?.aborted) resolve();
        else signal?.addEventListener("abort", () => resolve(), { once: true });
      });
      finished.resolve();
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
      await started.promise;
      httpController.abort();

      expect(receivedSignal?.aborted).toBe(true);
      expect(protocolController.signal.aborted).toBe(false);
      protocolController.abort();
      await expect(request).rejects.toThrow();
      await finished.promise;
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
    const handler: ToolDefinition["handler"] = async (_input, _context, signal) => {
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
    const handler: ToolDefinition["handler"] = async (input, _context, signal) => {
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
    const tool: ToolDefinition = { ...sourceTool, handler };
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
