const FRAME_HEADER_BYTES = 5;
const MAX_FRAME_BYTES = 65_536;
const RESULT_PAYLOAD_BYTES = 9;
const WINDOWS_ERROR_CANCELLED = 1_223;

export type WindowsHostResultStatus =
  | "completed"
  | "launch_failed"
  | "cleanup_unconfirmed"
  | "cancelled_before_start"
  | "cancelled_confirmed"
  | "supervision_failed";

export type WindowsHostFrame =
  | { type: "stdout"; payload: Buffer }
  | { type: "stderr"; payload: Buffer }
  | { type: "result"; status: WindowsHostResultStatus; exit_code: number; error_code: number };

/** Decodes complete host frames and returns any incomplete trailing bytes for the next read. */
export function decodeWindowsHostFrames(buffer: Buffer): { frames: WindowsHostFrame[]; remainder: Buffer } {
  const frames: WindowsHostFrame[] = [];
  let offset = 0;

  while (buffer.length - offset >= FRAME_HEADER_BYTES) {
    const frameType = buffer.readUInt8(offset);
    const payloadLength = buffer.readUInt32LE(offset + 1);
    if (payloadLength > MAX_FRAME_BYTES) {
      throw new Error(`Windows process host frame length ${payloadLength} exceeds ${MAX_FRAME_BYTES} bytes.`);
    }
    if (buffer.length - offset < FRAME_HEADER_BYTES + payloadLength) break;

    const payloadStart = offset + FRAME_HEADER_BYTES;
    const payload = buffer.subarray(payloadStart, payloadStart + payloadLength);
    if (frameType === 1 || frameType === 2) {
      frames.push(frameType === 1 ? { type: "stdout", payload } : { type: "stderr", payload });
    } else if (frameType === 3) {
      if (payloadLength !== RESULT_PAYLOAD_BYTES) {
        throw new Error(`Windows process host result frame must be ${RESULT_PAYLOAD_BYTES} bytes.`);
      }
      const status = resultStatus(payload.readUInt8(0));
      const result: WindowsHostFrame = {
        type: "result",
        status,
        exit_code: payload.readUInt32LE(1),
        error_code: payload.readUInt32LE(5)
      };
      assertWindowsHostTerminalResult(result);
      frames.push(result);
    } else {
      throw new Error(`Windows process host sent unknown frame type ${frameType}.`);
    }
    offset = payloadStart + payloadLength;
  }

  return { frames, remainder: buffer.subarray(offset) };
}

/** Checks the status-specific exit and native error fields before a result can affect validation. */
export function assertWindowsHostTerminalResult(frame: WindowsHostFrame): void {
  if (frame.type !== "result") return;
  const valid = (() => {
    switch (frame.status) {
      case "completed":
        return frame.error_code === 0;
      case "launch_failed":
      case "cleanup_unconfirmed":
      case "supervision_failed":
        return frame.exit_code === 0 && frame.error_code !== 0;
      case "cancelled_before_start":
        return frame.exit_code === 0 && frame.error_code === 0;
      case "cancelled_confirmed":
        return frame.exit_code === WINDOWS_ERROR_CANCELLED && frame.error_code === 0;
    }
  })();
  if (!valid) {
    throw new Error("Windows process host sent contradictory terminal result metadata.");
  }
}

function resultStatus(value: number): WindowsHostResultStatus {
  switch (value) {
    case 0: return "completed";
    case 1: return "launch_failed";
    case 2: return "cleanup_unconfirmed";
    case 3: return "cancelled_before_start";
    case 4: return "cancelled_confirmed";
    case 5: return "supervision_failed";
    default: throw new Error(`Windows process host sent unknown result status ${value}.`);
  }
}
