import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { RuntimeContext } from "../runtime/context.js";
import { createErrorEnvelope } from "../runtime/result-envelope.js";
import { toRepoReaderError } from "../runtime/errors.js";
import { createTaskExecutionBoundaryFromEnvironment } from "../services/task-execution-boundary.js";
import { getRequestTelemetry } from "../runtime/telemetry.js";
import type { TaskExecutionToolArgs, ToolDefinition } from "./tool-definition.js";

function combineAbortSignals(first?: AbortSignal, second?: AbortSignal): { signal?: AbortSignal; dispose: () => void } {
  if (!first || !second || first === second) return { signal: first ?? second, dispose: () => {} };

  const controller = new AbortController();
  const dispose = (): void => {
    first.removeEventListener("abort", onFirstAbort);
    second.removeEventListener("abort", onSecondAbort);
  };
  const abortFrom = (source: AbortSignal): void => {
    if (controller.signal.aborted) return;
    controller.abort(source.reason);
    dispose();
  };
  const onFirstAbort = (): void => abortFrom(first);
  const onSecondAbort = (): void => abortFrom(second);

  if (first.aborted) abortFrom(first);
  else if (second.aborted) abortFrom(second);
  else {
    first.addEventListener("abort", onFirstAbort, { once: true });
    second.addEventListener("abort", onSecondAbort, { once: true });
  }

  return { signal: controller.signal, dispose };
}

export function registerCatalogTool(server: McpServer, context: RuntimeContext, tool: ToolDefinition): void {
  server.registerTool(
    tool.name,
    {
      title: tool.title,
      description: tool.description,
      inputSchema: tool.inputSchema.shape,
      outputSchema: tool.outputSchema.shape,
      annotations: tool.annotations
    },
    async (args, extra) => {
      const requestSignal = getRequestTelemetry()?.abort_signal;
      const composed = combineAbortSignals(extra?.signal, requestSignal);
      try {
        let guarded;
        let taskExecutionArgs: TaskExecutionToolArgs | undefined;
        if (tool.taskExecution) {
          const parsed = tool.inputSchema.safeParse(args);
          if (!parsed.success) return createErrorEnvelope(toRepoReaderError(parsed.error));
          taskExecutionArgs = parsed.data as TaskExecutionToolArgs;
          guarded = tool.taskExecution(taskExecutionArgs);
        }
        if (!guarded) return await tool.handler(args, context, undefined, composed.signal);
        const boundary = await createTaskExecutionBoundaryFromEnvironment(process.env, {
          cwd: () => context.registry.get(guarded.repo_id).root
        });
        if (!boundary) return await tool.handler(args, context, undefined, composed.signal);
        const repo = context.registry.get(guarded.repo_id);
        return (await boundary.execute({
          repo_id: guarded.repo_id,
          root: repo.root,
          registered_repo: { repo_id: repo.repo_id, root: repo.root },
          resolve_registered_repo: () => {
            const current = context.registry.get(guarded.repo_id);
            return { repo_id: current.repo_id, root: current.root };
          },
          operation: guarded.operation,
          ...(guarded.run_id ? { run_id: guarded.run_id } : {}),
          ...(guarded.run_ids ? { run_ids: guarded.run_ids } : {}),
          task_text: JSON.stringify(args)
        }, (_explicitCwd, taskExecution) => {
          const forwarded = taskExecutionArgs
            ? tool.taskExecution?.(taskExecutionArgs, taskExecution.run_id)
            : undefined;
          const handlerArgs = forwarded?.run_id && typeof args === "object" && args !== null && !Array.isArray(args)
            ? { ...args as Record<string, unknown>, run_id: forwarded.run_id }
            : args;
          return tool.handler(handlerArgs, context, taskExecution, composed.signal);
        })).result;
      } catch (error) {
        return createErrorEnvelope(toRepoReaderError(error));
      } finally {
        composed.dispose();
      }
    }
  );
}
