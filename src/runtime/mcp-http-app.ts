import { randomUUID } from "node:crypto";
import express, { type Express, type Request, type Response } from "express";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import type {
  ConfigurationRevisionState,
  ConfigurationRevisionStore,
  EffectiveHotRevision
} from "../services/configuration-revision-store.js";
import { createMcpServer } from "../register.js";
import { requireAdmittedRuntimeContext, runWithAdmittedRuntimeContext } from "./admitted-runtime-context.js";
import { attachMcpRequestCancellation } from "./mcp-request-cancellation.js";
import { buildMcpRoutePatterns, isAuthorizedMcpPath, sanitizeMcpRouteForAudit } from "./mcp-routes.js";
import { isAllowedBrowserOrigin } from "./network-boundary.js";
import { TransportSessionStore, type SessionReservation } from "./transport-session-store.js";
import {
  createRequestId,
  requestAudit,
  withRequestTelemetry,
  type McpRequestErrorCategory,
  type RequestTelemetryContext
} from "./telemetry.js";

export type McpHttpAppOptions = Readonly<{
  revisionStore: ConfigurationRevisionStore;
  publicPathToken?: string;
  maxSessions: number;
  sessionIdleTtlMs: number;
  /** Observes or pauses a request after its revision is fixed and before SDK dispatch. */
  afterAdmission?: (revision: EffectiveHotRevision, request: Request) => Promise<void>;
}>;

export type McpHttpApp = Readonly<{
  app: Express;
  dispose: () => Promise<void>;
  /** Reloads the selected configuration file into this server process. */
  reloadConfiguration: () => Promise<ConfigurationRevisionState>;
}>;

/** Builds the HTTP routes that serve MCP sessions from the active revision store. */
export function createMcpHttpApp(options: McpHttpAppOptions): McpHttpApp {
  const app = express();
  app.use((req, res, next) => {
    const origin = typeof req.headers.origin === "string" ? req.headers.origin : undefined;
    const requestHost = typeof req.headers.host === "string" ? req.headers.host : undefined;
    if (!isAllowedBrowserOrigin(origin, requestHost)) {
      res.status(403).send("Forbidden origin");
      return;
    }
    next();
  });
  app.use(express.json({ limit: "2mb" }));

  const transports = new TransportSessionStore<StreamableHTTPServerTransport>({
    maxSessions: options.maxSessions,
    idleTtlMs: options.sessionIdleTtlMs
  });
  const mcpRoutePatterns = buildMcpRoutePatterns(options.publicPathToken);

  app.get("/health", (_req, res) => {
    res.json({ ok: true, name: "gpt-repo-mcp" });
  });

  function createMcpRequestContext(req: Request, abortSignal?: AbortSignal): RequestTelemetryContext {
    const method = typeof req.body?.method === "string" ? req.body.method : undefined;
    const tool = method === "tools/call" && typeof req.body?.params?.name === "string"
      ? req.body.params.name
      : undefined;

    return {
      request_id: createRequestId(),
      ...(abortSignal ? { abort_signal: abortSignal } : {}),
      http_method: req.method,
      route: sanitizeMcpRouteForAudit(req.path),
      mcp_session: typeof req.headers["mcp-session-id"] === "string" ? "present" : "missing",
      mcp_method: method,
      mcp_tool: tool
    };
  }

  function attachMcpRequestAuditing(res: Response, context: RequestTelemetryContext, startedAt: number): void {
    res.on("finish", () => {
      requestAudit({
        event: "mcp_request_finish",
        request_id: context.request_id,
        http_method: context.http_method ?? "UNKNOWN",
        route: context.route ?? "/mcp",
        status_code: res.statusCode,
        duration_ms: Date.now() - startedAt,
        mcp_session: context.mcp_session,
        mcp_method: context.mcp_method,
        mcp_tool: context.mcp_tool
      });
    });
  }

  function rejectUnauthorizedMcpPath(req: Request, res: Response): boolean {
    if (isAuthorizedMcpPath(req.path, options.publicPathToken)) return false;
    res.status(404).send("Not found");
    return true;
  }

  app.post(mcpRoutePatterns, async (req: Request, res: Response) => {
    const requestContext = createMcpRequestContext(req, attachMcpRequestCancellation(req, res));
    const startedAt = Date.now();
    attachMcpRequestAuditing(res, requestContext, startedAt);

    return withRequestTelemetry(requestContext, async () => {
      logRequestStart(requestContext);
      if (rejectUnauthorizedMcpPath(req, res)) return;

      const sessionId = req.headers["mcp-session-id"];
      let transport: StreamableHTTPServerTransport | undefined;
      let reservation: SessionReservation<StreamableHTTPServerTransport> | undefined;
      let errorCategory: McpRequestErrorCategory = "internal";
      try {
        if (typeof sessionId === "string") transport = transports.get(sessionId);
        if (!transport && !sessionId && isInitializeRequest(req.body)) {
          reservation = await transports.reserve();
          if (!reservation) {
            auditMcpRequestError(requestContext, startedAt, "session_capacity", 503);
            res.status(503).json({
              jsonrpc: "2.0",
              error: { code: -32001, message: "MCP session capacity reached" },
              id: (req.body as { id?: unknown }).id ?? null
            });
            return;
          }
          transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: () => randomUUID(),
            onsessioninitialized: (newSessionId) => {
              if (transport && reservation) {
                reservation.commit(newSessionId, transport);
                reservation = undefined;
              }
            }
          });
          errorCategory = "server_initialization";
          transport.onclose = () => {
            const closedSessionId = transport?.sessionId;
            if (closedSessionId) transports.remove(closedSessionId);
          };
          await createMcpServer(requireAdmittedRuntimeContext).connect(transport);
        } else if (!transport) {
          auditMcpRequestError(requestContext, startedAt, "invalid_session", 400);
          res.status(400).json({
            jsonrpc: "2.0",
            error: { code: -32000, message: "Bad Request: no valid MCP session" },
            id: null
          });
          return;
        }

        errorCategory = "transport_request";
        const revision = options.revisionStore.capture();
        await runWithAdmittedRuntimeContext(revision.runtimeContext, async () => {
          await options.afterAdmission?.(revision, req);
          await transport!.handleRequest(req, res, req.body);
        });
      } catch {
        reservation?.release();
        if (transport?.sessionId) await transports.close(transport.sessionId).catch(() => undefined);
        auditMcpRequestError(requestContext, startedAt, errorCategory, 500);
        if (!res.headersSent) {
          res.status(500).json({
            jsonrpc: "2.0",
            error: { code: -32603, message: "Internal server error" },
            id: null
          });
        }
      }
    });
  });

  app.get(mcpRoutePatterns, async (req: Request, res: Response) => {
    const requestContext = createMcpRequestContext(req);
    const startedAt = Date.now();
    attachMcpRequestAuditing(res, requestContext, startedAt);

    return withRequestTelemetry(requestContext, async () => {
      logRequestStart(requestContext);
      if (rejectUnauthorizedMcpPath(req, res)) return;

      try {
        const sessionId = req.headers["mcp-session-id"];
        const transport = typeof sessionId === "string" ? transports.get(sessionId) : undefined;
        if (!transport) {
          auditMcpRequestError(requestContext, startedAt, "invalid_session", 400);
          res.status(400).send("Invalid or missing MCP session id");
          return;
        }
        await transport.handleRequest(req, res);
      } catch {
        auditMcpRequestError(requestContext, startedAt, "transport_request", 500);
        if (!res.headersSent) res.status(500).send("Internal server error");
      }
    });
  });

  app.delete(mcpRoutePatterns, async (req: Request, res: Response) => {
    const requestContext = createMcpRequestContext(req);
    const startedAt = Date.now();
    attachMcpRequestAuditing(res, requestContext, startedAt);

    return withRequestTelemetry(requestContext, async () => {
      logRequestStart(requestContext);
      if (rejectUnauthorizedMcpPath(req, res)) return;

      try {
        const sessionId = req.headers["mcp-session-id"];
        const transport = typeof sessionId === "string" ? transports.get(sessionId) : undefined;
        if (!transport || typeof sessionId !== "string") {
          auditMcpRequestError(requestContext, startedAt, "invalid_session", 400);
          res.status(400).send("Invalid or missing MCP session id");
          return;
        }
        await transport.handleRequest(req, res);
        await transports.close(sessionId);
      } catch {
        auditMcpRequestError(requestContext, startedAt, "transport_close", 500);
        if (!res.headersSent) res.status(500).send("Internal server error");
      }
    });
  });

  const sessionCleanupTimer = setInterval(() => {
    void transports.sweepExpired();
  }, Math.min(options.sessionIdleTtlMs, 60_000));
  sessionCleanupTimer.unref();
  let disposed = false;

  return {
    app,
    reloadConfiguration: () => options.revisionStore.reloadFromFile(),
    async dispose() {
      if (disposed) return;
      disposed = true;
      clearInterval(sessionCleanupTimer);
      await transports.closeAll();
    }
  };
}

function logRequestStart(context: RequestTelemetryContext): void {
  requestAudit({
    event: "mcp_request_start",
    request_id: context.request_id,
    http_method: context.http_method ?? "UNKNOWN",
    route: context.route ?? "/mcp",
    mcp_session: context.mcp_session,
    mcp_method: context.mcp_method,
    mcp_tool: context.mcp_tool
  });
}

function auditMcpRequestError(
  context: RequestTelemetryContext,
  startedAt: number,
  errorCategory: McpRequestErrorCategory,
  statusCode: number
): void {
  requestAudit({
    event: "mcp_request_error",
    request_id: context.request_id,
    http_method: context.http_method ?? "UNKNOWN",
    route: context.route ?? "/mcp",
    status_code: statusCode,
    duration_ms: Date.now() - startedAt,
    error_category: errorCategory,
    mcp_session: context.mcp_session,
    mcp_method: context.mcp_method,
    mcp_tool: context.mcp_tool
  });
}
