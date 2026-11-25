import type { ConfigurationAdminDiscoveryRecord } from "./configuration-admin-client.js";
import type {
  ConfigurationAdminRequest,
  ConfigurationAdminResponse
} from "./configuration-admin-protocol.js";

export type ConfigurationAdminHost = Readonly<{
  record: ConfigurationAdminDiscoveryRecord;
  close: () => Promise<void>;
}>;

/** Starts the platform's owner-local administrative endpoint. */
export async function startConfigurationAdminHost(options: {
  serverPid: number;
  instanceId: string;
  onHelperPid?: (helperPid: number) => void;
  handle: (value: unknown) => Promise<ConfigurationAdminResponse>;
}): Promise<ConfigurationAdminHost> {
  if (process.platform === "win32") {
    const windows = await import("./configuration-admin-windows.js");
    return await windows.startWindowsConfigurationAdminHost(options);
  }
  const posix = await import("./configuration-admin-posix.js");
  const directory = await posix.getPosixConfigurationAdminDirectory();
  return await posix.startPosixConfigurationAdminServer({ ...options, directory });
}

/** Reads discovery records from the platform's protected store. */
export async function readConfigurationAdminRecords(): Promise<ConfigurationAdminDiscoveryRecord[]> {
  if (process.platform === "win32") {
    const windows = await import("./configuration-admin-windows.js");
    return await windows.readWindowsConfigurationAdminRecords();
  }
  const posix = await import("./configuration-admin-posix.js");
  return await posix.readPosixConfigurationAdminRecords(await posix.getPosixConfigurationAdminDirectory());
}

/** Sends one request over the platform's private administrative transport. */
export async function sendConfigurationAdminRequest(
  record: ConfigurationAdminDiscoveryRecord,
  request: ConfigurationAdminRequest
): Promise<ConfigurationAdminResponse> {
  if (process.platform === "win32") {
    const windows = await import("./configuration-admin-windows.js");
    return await windows.requestWindowsConfigurationAdmin(record, request);
  }
  const posix = await import("./configuration-admin-posix.js");
  return await posix.requestPosixConfigurationAdmin(record, request);
}
