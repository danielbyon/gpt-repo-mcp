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

  test.each([
    [0, 0, 5, "completed result with native error"],
    [1, 0, 0, "launch failure without native error"],
    [2, 0, 0, "unconfirmed cleanup without native error"],
    [3, 1, 0, "pre-start cancellation with an exit code"],
    [4, 0, 0, "confirmed cancellation without the cancellation code"],
    [5, 0, 0, "supervision failure without native error"]
  ])("rejects contradictory terminal metadata: %s", (status, exitCode, errorCode) => {
    expect(() => decodeWindowsHostFrames(resultFrame(status, exitCode, errorCode)))
      .toThrow(/contradictory terminal result/i);
  });


  test.each([
    [0, 0, 0, "completed"],
    [0, 7, 0, "completed"],
    [1, 0, 2, "launch_failed"],
    [2, 0, 5, "cleanup_unconfirmed"],
    [3, 0, 0, "cancelled_before_start"],
    [4, 1_223, 0, "cancelled_confirmed"],
    [5, 0, 87, "supervision_failed"]
  ])("preserves distinct valid supervisor result status %s", (status, exitCode, errorCode, expected) => {
    expect(decodeWindowsHostFrames(resultFrame(status, exitCode, errorCode)).frames).toEqual([{
      type: "result",
      status: expected,
      exit_code: exitCode,
      error_code: errorCode
    }]);
  });

  test("keeps normal nonzero command exits as completed results", () => {
    expect(decodeWindowsHostFrames(resultFrame(0, 7, 0)).frames).toEqual([{
      type: "result",
      status: "completed",
      exit_code: 7,
      error_code: 0
    }]);
  });
});

function frame(type: number, payload: Buffer): Buffer {
  const header = Buffer.alloc(5);
  header.writeUInt8(type, 0);
  header.writeUInt32LE(payload.length, 1);
  return Buffer.concat([header, payload]);
}

function resultFrame(status: number, exitCode: number, errorCode: number): Buffer {
  const payload = Buffer.alloc(9);
  payload.writeUInt8(status, 0);
  payload.writeUInt32LE(exitCode, 1);
  payload.writeUInt32LE(errorCode, 5);
  return frame(3, payload);
}
