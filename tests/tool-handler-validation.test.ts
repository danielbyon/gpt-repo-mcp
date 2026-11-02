import { describe, expect, test, vi } from "vitest";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
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
});
