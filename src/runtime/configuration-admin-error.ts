/** Describes an IPC failure and whether its request may have reached the server. */
export class ConfigurationAdminIpcError extends Error {
  constructor(
    readonly code: string,
    readonly phase: "pre-dispatch" | "indeterminate",
    message: string
  ) {
    super(message);
    this.name = "ConfigurationAdminIpcError";
  }
}
