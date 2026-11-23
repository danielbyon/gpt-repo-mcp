import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { RuntimeContext } from "../runtime/context.js";
import { createErrorEnvelope } from "../runtime/result-envelope.js";
import { toRepoReaderError } from "../runtime/errors.js";
import { getRequestTelemetry } from "../runtime/telemetry.js";
import type { ToolDefinition } from "./tool-definition.js";

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

export function registerCatalogTool(server: McpServer, context: RuntimeContext | (() => RuntimeContext), tool: ToolDefinition): void {
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
        const requestContext = typeof context === "function" ? context() : context;
        return await tool.handler(args, requestContext, composed.signal);
      } catch (error) {
        return createErrorEnvelope(toRepoReaderError(error));
      } finally {
        composed.dispose();
      }
    }
  );
}
