import { realpath } from "node:fs/promises";
import { tmpdir } from "node:os";
import { expect, test, vi } from "vitest";
import { createCodebaseMemoryClientFactory } from "../src/services/codebase-memory-client.js";
import { createTempDir } from "./fixtures/temp-dir.js";

const { transports, connect, close, callTool } = vi.hoisted(() => ({
  transports: vi.fn(),
  connect: vi.fn(async () => {}),
  close: vi.fn(async () => {}),
  callTool: vi.fn(async () => ({ structuredContent: { projects: [] } }))
}));

vi.mock("@modelcontextprotocol/sdk/client/stdio.js", () => ({
  StdioClientTransport: class {
    constructor(options: unknown) { transports(options); }
  }
}));
vi.mock("@modelcontextprotocol/sdk/client/index.js", () => ({
  Client: class {
    connect = connect;
    close = close;
    callTool = callTool;
  }
}));

test("starts each provider outside the checkout with only that canonical root allowed", async () => {
  const firstRoot = await realpath(await createTempDir("provider-first-"));
  const secondRoot = await realpath(await createTempDir("provider-second-"));
  const factory = createCodebaseMemoryClientFactory(process.execPath);
  const first = await factory(firstRoot);
  const second = await factory(secondRoot);

  try {
    const executable = await realpath(process.execPath);
    for (const [index, root] of [firstRoot, secondRoot].entries()) {
      expect(transports).toHaveBeenNthCalledWith(index + 1, {
        command: executable,
        args: [],
        cwd: tmpdir(),
        env: { CBM_ALLOWED_ROOT: root, CBM_LOG_LEVEL: "error" },
        stderr: "pipe"
      });
    }
    expect(connect).toHaveBeenCalledTimes(2);
    expect(callTool).not.toHaveBeenCalled();
  } finally {
    await Promise.all([first.close(), second.close()]);
  }
  expect(close).toHaveBeenCalledTimes(2);
});
