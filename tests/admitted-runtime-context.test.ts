import { expect, test } from "vitest";
import {
  requireAdmittedRuntimeContext,
  runWithAdmittedRuntimeContext
} from "../src/runtime/admitted-runtime-context.js";
import type { RuntimeContext } from "../src/runtime/context.js";

test("keeps each asynchronous request on the context captured at admission", async () => {
  const contextA = { revision: "A" } as unknown as RuntimeContext;
  const contextB = { revision: "B" } as unknown as RuntimeContext;
  let releaseA!: () => void;
  const gateA = new Promise<void>((resolve) => { releaseA = resolve; });

  const requestA = runWithAdmittedRuntimeContext(contextA, async () => {
    await gateA;
    return requireAdmittedRuntimeContext();
  });
  const requestB = runWithAdmittedRuntimeContext(contextB, async () => requireAdmittedRuntimeContext());

  expect(await requestB).toBe(contextB);
  releaseA();
  expect(await requestA).toBe(contextA);
});

test("fails closed when no request context was admitted", () => {
  expect(() => requireAdmittedRuntimeContext()).toThrow("No runtime context was admitted for this request.");
});
