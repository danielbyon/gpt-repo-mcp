import type { IncomingMessage, ServerResponse } from "node:http";

/** Creates a signal that aborts when the MCP client leaves before the response completes. */
export function attachMcpRequestCancellation(req: IncomingMessage, res: ServerResponse): AbortSignal {
  const controller = new AbortController();
  const abortForDisconnect = (): void => {
    if (req.aborted || !res.writableFinished) {
      controller.abort(new DOMException("The MCP HTTP request ended before its response completed.", "AbortError"));
    }
  };
  const removeDisconnectListeners = (): void => {
    req.off("aborted", abortForDisconnect);
    res.off("close", abortForDisconnect);
  };

  req.once("aborted", abortForDisconnect);
  res.once("close", abortForDisconnect);
  res.once("finish", removeDisconnectListeners);
  res.once("close", removeDisconnectListeners);
  if (req.aborted) abortForDisconnect();

  return controller.signal;
}
