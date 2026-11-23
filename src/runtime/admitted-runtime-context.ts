import { AsyncLocalStorage } from "node:async_hooks";
import type { RuntimeContext } from "./context.js";

const admittedContexts = new AsyncLocalStorage<RuntimeContext>();

/** Runs transport work with the immutable runtime context captured at admission. */
export function runWithAdmittedRuntimeContext<T>(context: RuntimeContext, work: () => T): T {
  return admittedContexts.run(context, work);
}

/** Returns the context assigned to this request or fails when admission was skipped. */
export function requireAdmittedRuntimeContext(): RuntimeContext {
  const context = admittedContexts.getStore();
  if (!context) throw new Error("No runtime context was admitted for this request.");
  return context;
}
