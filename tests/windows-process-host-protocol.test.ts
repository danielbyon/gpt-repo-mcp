import { describe, expect, test } from "vitest";
import { decodeWindowsHostFrames } from "../src/services/windows-process-host-protocol.js";

describe("decodeWindowsHostFrames", () => {
  test("decodes output and completion frames without treating payload bytes as framing", () => {
    const stdout = frame(1, Buffer.from([0, 10, 13, 255]));
    const stderr = frame(2, Buffer.from("warning\n"));
    const result = frame(3, Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0]));

    const decoded = decodeWindowsHostFrames(Buffer.concat([stdout, stderr, result]));

    expect(decoded.remainder).toHaveLength(0);
    expect(decoded.frames).toEqual([
      { type: "stdout", payload: Buffer.from([0, 10, 13, 255]) },
      { type: "stderr", payload: Buffer.from("warning\n") },
      { type: "result", status: "completed", exit_code: 0, error_code: 0 }
    ]);
  });

  test("retains incomplete headers and payloads for the next read", () => {
    const encoded = frame(1, Buffer.from("partial"));
    const first = decodeWindowsHostFrames(encoded.subarray(0, 7));

    expect(first.frames).toEqual([]);
    expect(first.remainder).toEqual(encoded.subarray(0, 7));

    const second = decodeWindowsHostFrames(Buffer.concat([first.remainder, encoded.subarray(7)]));
    expect(second.frames).toEqual([{ type: "stdout", payload: Buffer.from("partial") }]);
    expect(second.remainder).toHaveLength(0);
  });

  test("rejects unknown, oversized, and malformed result frames", () => {
    expect(() => decodeWindowsHostFrames(frame(9, Buffer.alloc(0)))).toThrow(/unknown frame type/i);
    expect(() => decodeWindowsHostFrames(frame(1, Buffer.alloc(65_537)))).toThrow(/frame length/i);
    expect(() => decodeWindowsHostFrames(frame(3, Buffer.alloc(8)))).toThrow(/result frame/i);
    expect(() => decodeWindowsHostFrames(frame(3, Buffer.from([99, 0, 0, 0, 0, 0, 0, 0, 0])))).toThrow(/result status/i);
  });
});

function frame(type: number, payload: Buffer): Buffer {
  const header = Buffer.alloc(5);
  header.writeUInt8(type, 0);
  header.writeUInt32LE(payload.length, 1);
  return Buffer.concat([header, payload]);
}
