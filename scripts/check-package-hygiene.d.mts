export interface PackageBoundaryInput {
  entries: Array<string | { path?: string }>;
  /** Platform spelling rules used by deterministic path checks. */
  platform?: string;
  manifest: {
    name?: string;
    version?: string;
    main?: string;
    bin?: Record<string, string>;
    files?: string[];
  };
}

export interface PackageBoundaryResult {
  ok: boolean;
  entries: string[];
  entry_count: number;
  declared_entry_points: string[];
  blockers: string[];
}

/** Minimal file metadata consumed by package preflight and inspection. */
export interface PackagePathInfo {
  isSymbolicLink(): boolean;
  isDirectory(): boolean;
  isFile(): boolean;
  nlink: number;
  dev?: number;
  ino?: number;
  size?: number;
}

/** Directory entry shape used by the package preflight walk. */
export interface PackageDirectoryEntry {
  name: string;
  isSymbolicLink(): boolean;
  isDirectory(): boolean;
  isFile(): boolean;
}

/** Open handle operations used before package content is inspected. */
export interface PackageReadHandle {
  stat(): Promise<PackagePathInfo>;
  read(
    buffer: Uint8Array,
    offset: number,
    length: number,
    position: number | null
  ): Promise<{ bytesRead: number }>;
  close(): Promise<void>;
}

/** Optional filesystem and package-command seams for deterministic checks. */
export interface PackageHygieneOptions {
  root?: string;
  /** Platform spelling rules used by deterministic path checks. */
  platform?: string;
  lstatPath?: (path: string) => Promise<PackagePathInfo>;
  readFilePath?: (
    path: string,
    options?: { encoding?: string; flag?: number }
  ) => Promise<string | Uint8Array>;
  readDirectory?: (
    path: string,
    options: { withFileTypes: true }
  ) => Promise<PackageDirectoryEntry[]>;
  openPath?: (path: string, flags: number) => Promise<PackageReadHandle>;
  packPackage?: (root: string) => Promise<{ stdout: string }>;
  /** Child-process seam used to verify the finite npm-pack timeout. */
  execFilePath?: (
    executable: string,
    args: string[],
    options: {
      cwd: string;
      encoding: "utf8";
      maxBuffer: number;
      timeout: number;
    }
  ) => Promise<{ stdout: string }>;
}

/** Stable package-hygiene report emitted by the CLI and library entry point. */
export interface PackageHygieneResult {
  schema_version: 1;
  package: { name?: string; version?: string };
  entry_count: number;
  declared_entry_points: string[];
  files_allowlist: string[] | null;
  blockers: string[];
  ok: boolean;
}

export function evaluatePackageBoundary(
  input: PackageBoundaryInput
): PackageBoundaryResult;
export function findHomePathLeaks(text: string): string[];
export function isForbiddenPackagePath(path: unknown, platform?: string): boolean;
export function checkPackageHygiene(
  options?: PackageHygieneOptions
): Promise<PackageHygieneResult>;
