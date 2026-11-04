import { execFile } from "node:child_process";
import { link, lstat, mkdir, mkdtemp, open, readFile, readdir, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, parse, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { describe, expect, test } from "vitest";
import {
  checkPackageHygiene,
  evaluatePackageBoundary,
  findHomePathLeaks,
  isForbiddenPackagePath
} from "../scripts/check-package-hygiene.mjs";

test("Win32 ADS package entries are rejected at the metadata boundary", () => {
  const path = "dist/neutral-sentinel.txt:metadata";
  const result = evaluatePackageBoundary({
    entries: [path],
    manifest: { name: "fixture", version: "1.0.0" },
    platform: "win32"
  });

  expect(result).toMatchObject({
    ok: false,
    entry_count: 0,
    blockers: [`unsupported Windows path alias syntax: ${path}`]
  });
});

async function createTempDirectory(prefix: string): Promise<string> {
  return mkdtemp(join(await realpath(tmpdir()), prefix));
}

const virtualDirectoryInfo = {
  isSymbolicLink: () => false,
  isDirectory: () => true,
  isFile: () => false,
  nlink: 1
};

function withVirtualPackageRoot(
  root: string,
  inspectPath: (path: string) => Promise<{
    isSymbolicLink(): boolean;
    isDirectory(): boolean;
    isFile(): boolean;
    nlink: number;
  }>
) {
  const absoluteRoot = resolve(root);
  const filesystemRoot = parse(absoluteRoot).root;
  const directories = new Set([filesystemRoot]);
  let current = filesystemRoot;
  for (const component of relative(filesystemRoot, absoluteRoot).split(sep).filter(Boolean)) {
    current = join(current, component);
    directories.add(current);
  }
  return async (path: string) => directories.has(resolve(path))
    ? virtualDirectoryInfo
    : inspectPath(path);
}

const execFileAsync = promisify(execFile);
const hygieneChecker = fileURLToPath(
  new URL("../scripts/check-package-hygiene.mjs", import.meta.url)
);

const manifest = {
  name: "gpt-repo-mcp",
  version: "0.2.0",
  main: "dist/server.js",
  bin: { "gpt-repo": "dist/cli/connect-gpt.js" }
};

const cleanEntries = [
  "package.json",
  "README.md",
  "LICENSE",
  ".env.example",
  "dist/server.js",
  "dist/cli/connect-gpt.js"
];

describe("package boundary hygiene", () => {
  test("pins the repository package inventory to its runtime files", async () => {
    const repositoryManifest = JSON.parse(await readFile(
      new URL("../package.json", import.meta.url),
      "utf8"
    )) as typeof manifest & { private?: boolean; files?: string[] };
    const expectedPaths = [
      "package.json",
      "README.md",
      "LICENSE",
      "dist/server.js",
      "dist/cli/connect-gpt.js",
      "dist/windows-process-host.exe"
    ];

    expect(repositoryManifest.private).toBe(true);
    expect(repositoryManifest.files).toEqual(expectedPaths);

    const inventory = evaluatePackageBoundary({
      entries: expectedPaths,
      manifest: repositoryManifest
    });
    expect(inventory.ok).toBe(true);
    expect(inventory.entries).toEqual(expectedPaths);
    expect(inventory.entries).not.toContain("security/oss-security-policy.json");
  });

  test("requires the Windows process host only for Windows package builds", async () => {
    const files = [
      "package.json",
      "README.md",
      "LICENSE",
      "dist/server.js",
      "dist/cli/connect-gpt.js",
      "dist/windows-process-host.exe"
    ];
    const root = await fixturePackage(
      { "README.md": "Setup guide.\n", "LICENSE": "License text.\n" },
      { files }
    );
    const packedEntries = files.slice(0, -1).map((path) => ({ path }));
    let packCalls = 0;
    const packPackage = async () => {
      packCalls += 1;
      return { stdout: JSON.stringify([{ files: packedEntries }]) };
    };

    try {
      const nonWindows = await checkPackageHygiene({ root, platform: "darwin", packPackage });
      expect(nonWindows.ok).toBe(true);
      expect(packCalls).toBe(1);

      const windows = await checkPackageHygiene({ root, platform: "win32", packPackage });
      expect(windows.ok).toBe(false);
      expect(windows.blockers.some((blocker) =>
        blocker.startsWith("package preflight could not inspect dist/windows-process-host.exe: ")
      )).toBe(true);
      expect(packCalls).toBe(1);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("checks the parent route before treating an absent Windows host as optional", async () => {
    const externalRoot = await createTempDirectory("gpt-package-host-external-");
    const root = await fixturePackage({}, {
      files: ["dist/windows-process-host.exe"],
      main: null,
      bin: null
    });
    const hostPath = join(root, "dist", "windows-process-host.exe");
    const inspectedHostPaths: string[] = [];
    try {
      await rm(join(root, "dist"), { recursive: true, force: true });
      await mkdir(join(externalRoot, "dist"), { recursive: true });
      await writeFile(join(externalRoot, "dist", "windows-process-host.exe"), "external host");
      await symlink(externalRoot, join(root, "dist"));

      const result = await checkPackageHygiene({
        root,
        platform: "darwin",
        lstatPath: async (path: string) => {
          if (path === hostPath) inspectedHostPaths.push(path);
          return lstat(path);
        },
        packPackage: async () => {
          throw new Error("npm pack must not run after a symlinked parent is found.");
        }
      });

      expect(result.ok).toBe(false);
      expect(result.blockers).toContain("symlink in package: dist");
      expect(inspectedHostPaths).toEqual([]);
    } finally {
      await rm(root, { recursive: true, force: true });
      await rm(externalRoot, { recursive: true, force: true });
    }
  });

  test("accepts a manifest whose entry points and public resources are packed", () => {
    const result = evaluatePackageBoundary({ entries: cleanEntries, manifest });
    expect(result.ok).toBe(true);
    expect(result.blockers).toEqual([]);
  });

  test("rejects restricted policy, local configuration and build residue", () => {
    for (const forbidden of [
      "security/denied-sentinel.json",
      "security/oss-security-policy.json",
      "nested/Security/OSS-SECURITY-POLICY.JSON",
      "config.local.json",
      "CONFIG.LOCAL.JSON",
      "nested/config.local.backup.json",
      "dist/NESTED.LOCAL.JSON.BACKUP",
      ".env",
      ".env.local",
      ".env.production",
      "nested/.env",
      "nested/.env.local",
      "nested/.env.production",
      "node_modules/express/index.js",
      ".chatgpt/operations/run.json",
      ".CHATGPT/operations/run.json",
      "dist/.CHATGPT/operations/run.json",
      "dist/SECURITY/private.json",
      ".DS_STORE",
      "dist/NESTED.DS_STORE",
      "coverage/index.html"
    ]) {
      const result = evaluatePackageBoundary({
        entries: [...cleanEntries, forbidden],
        manifest
      });
      expect(result.ok, forbidden).toBe(false);
      expect(result.blockers.join(" "), forbidden).toContain(forbidden);
    }
  });

  test("keeps the environment template that the runtime documents", () => {
    const result = evaluatePackageBoundary({ entries: cleanEntries, manifest });
    expect(result.entries).toContain(".env.example");
  });

  test("rejects mixed-case environment files except the exact template", () => {
    for (const forbidden of [".ENV", ".Env.production", "nested/.ENV", ".ENV.LOCAL"]) {
      const result = evaluatePackageBoundary({
        entries: [...cleanEntries, forbidden],
        manifest
      });
      expect(result.ok, forbidden).toBe(false);
      expect(result.blockers.join(" "), forbidden).toContain(forbidden);
    }

    const upperCaseTemplate = evaluatePackageBoundary({
      entries: [...cleanEntries, ".ENV.EXAMPLE"],
      manifest
    });
    expect(upperCaseTemplate.ok).toBe(false);
    expect(upperCaseTemplate.blockers.join(" ")).toContain(".ENV.EXAMPLE");
  });

  test("fails when declared entry points are absent from the package", () => {
    const result = evaluatePackageBoundary({
      entries: ["package.json", "README.md"],
      manifest
    });
    expect(result.ok).toBe(false);
    expect(result.blockers.join(" ")).toContain("dist/server.js");
    expect(result.blockers.join(" ")).toContain("dist/cli/connect-gpt.js");
  });

  test("fails on unsafe archive paths", () => {
    for (const unsafe of [
      "/etc/passwd",
      "../outside.js",
      "./dist/server.js",
      "C:/outside/file.js",
      "C:\\outside\\file.js",
      "C:relative.js",
      "\\\\server\\share\\file.js",
      "//server/share/file.js"
    ]) {
      const result = evaluatePackageBoundary({
        entries: [...cleanEntries, unsafe],
        manifest
      });
      expect(result.ok, unsafe).toBe(false);
      expect(result.blockers.join(" "), unsafe).toContain(unsafe);
    }
  });

  test("accepts only the template environment file at any depth", () => {
    const result = evaluatePackageBoundary({
      entries: [...cleanEntries, "nested/.env.example"],
      manifest
    });
    expect(result.ok).toBe(true);
    expect(result.entries).toContain("nested/.env.example");
  });

  test("classifies package path boundaries by basename", () => {
    for (const forbidden of [
      ".DS_Store",
      "security/denied-sentinel.json",
      "nested/config.local.json"
    ]) {
      const result = evaluatePackageBoundary({
        entries: [...cleanEntries, forbidden],
        manifest
      });
      expect(result.ok, forbidden).toBe(false);
      expect(result.blockers.join(" "), forbidden).toContain(forbidden);
    }
    const allowed = evaluatePackageBoundary({
      entries: [...cleanEntries, "nested/.envrc"],
      manifest
    });
    expect(allowed.ok).toBe(true);
  });

  test("rejects forbidden directory names nested below allowed package roots", () => {
    for (const forbidden of [
      "dist/security/private.json",
      "dist/.chatgpt/operations/run.json",
      "dist/.serena/memory.json",
      "dist/coverage/index.html",
      "dist/nested/node_modules/pkg/index.js"
    ]) {
      const result = evaluatePackageBoundary({
        entries: [...cleanEntries, forbidden],
        manifest
      });
      expect(result.ok, forbidden).toBe(false);
      expect(result.blockers.join(" "), forbidden).toContain(forbidden);
      expect(result.entries, forbidden).not.toContain(forbidden);
    }
  });

  test("rejects environment files at any depth except the template", () => {
    for (const forbidden of [
      ".env.local",
      ".env.production",
      "nested/.env",
      "nested/.env.local",
      "nested/.env.production"
    ]) {
      const result = evaluatePackageBoundary({
        entries: [...cleanEntries, forbidden],
        manifest
      });
      expect(result.ok, forbidden).toBe(false);
      expect(result.blockers.join(" "), forbidden).toContain(
        "forbidden package path: " + forbidden
      );
    }
  });

  test("reports only declared entry points that are present in the manifest", () => {
    const result = evaluatePackageBoundary({
      entries: ["package.json"],
      manifest: {} as never
    });
    expect(result.declared_entry_points).toEqual([]);
    expect(result.ok).toBe(true);
  });

  test("rejects NUL bytes in package entry paths with a deterministic blocker", () => {
    for (const entry of ["dist/server\u0000.js", { path: "dist/other\u0000.js" }]) {
      const path = typeof entry === "string" ? entry : entry.path;
      const result = evaluatePackageBoundary({
        entries: [...cleanEntries, entry],
        manifest
      });
      expect(result.ok, path).toBe(false);
      expect(result.blockers, path).toEqual([
        `NUL byte in package path: ${JSON.stringify(path)}`
      ]);
    }
  });

  test("rejects NUL bytes in declared entry points", () => {
    const nulMain = "dist/server\u0000.js";
    const result = evaluatePackageBoundary({
      entries: cleanEntries,
      manifest: { ...manifest, main: nulMain }
    });
    expect(result.ok).toBe(false);
    expect(result.blockers).toEqual([
      `NUL byte in declared entry point: ${JSON.stringify(nulMain)}`
    ]);
  });

  test("rejects non-string and empty package entries", () => {
    const result = evaluatePackageBoundary({
      entries: [...cleanEntries, null, { path: null }, ""] as never,
      manifest
    });
    expect(result.ok).toBe(false);
    expect(result.blockers).toEqual([
      "unsafe package path: undefined",
      "unsafe package path: null",
      "unsafe package path: "
    ]);
  });

  test("ignores non-string declared entry points and reports missing targets", () => {
    const result = evaluatePackageBoundary({
      entries: ["package.json"],
      manifest: {
        main: 42,
        bin: { bad: 42, good: "dist/cli/connect-gpt.js" }
      } as never
    });
    expect(result.declared_entry_points).toEqual(["dist/cli/connect-gpt.js"]);
    expect(result.blockers).toContain(
      "declared entry point missing from package: dist/cli/connect-gpt.js"
    );
  });

  test("reports home-directory leaks without echoing surrounding file text", () => {
    const sample = [
      "configured at /Users/alice/Projects/private for local use",
      "and at /home/bob/workspace"
    ].join("\n");
    const leaks = findHomePathLeaks(sample);
    expect(leaks).toEqual(["/Users/<user>/", "/home/<user>/"]);
    const serialized = JSON.stringify(leaks);
    expect(serialized).not.toContain("alice");
    expect(serialized).not.toContain("bob");
  });

  test("reports native Windows home-directory paths without echoing accounts", () => {
    const leaks = findHomePathLeaks(
      [
        "C:\\Users\\alice\\Projects\\private",
        "D:\\home\\bob\\workspace",
        "\\\\server\\share\\Users\\carol\\archive"
      ].join("\n")
    );
    expect(leaks).toEqual(["/Users/<user>/", "/home/<user>/"]);
    expect(JSON.stringify(leaks)).not.toContain("alice");
    expect(JSON.stringify(leaks)).not.toContain("bob");
    expect(JSON.stringify(leaks)).not.toContain("carol");
  });

  test("ignores a bare home root that has no account component", () => {
    const sample = [
      "The package never writes to /Users/ or /home/ directly.",
      "Placeholders such as /Users/<user>/Projects stay documentation.",
      "No filesystem paths appear in this sentence."
    ].join("\n");
    expect(findHomePathLeaks(sample)).toEqual([]);
  });
});

test("rejects nested case-insensitive restricted policy path suffixes", () => {
  for (const path of [
    "security/oss-security-policy.json",
    "nested/security/oss-security-policy.json",
    "dist/Security/OSS-SECURITY-POLICY.JSON",
    "dist/SECURITY/OSS-SECURITY-POLICY.JSON",
    "nested\\Security\\OSS-SECURITY-POLICY.JSON",
    "Security\\OSS-SECURITY-POLICY.JSON",
    "nested/Security\\OSS-SECURITY-POLICY.JSON",
    "nested\\Security/OSS-SECURITY-POLICY.JSON",
    "nested/Security/OSS-SECURITY-POLICY.JSON/"
  ]) {
    expect(isForbiddenPackagePath(path), path).toBe(true);
  }
});

test.each([
  ["composed mark", "dist/securíty/oß-security-policy.json"],
  ["decomposed mark", "dist/securi\u0301ty/oß-security-policy.json"],
  ["case-fold", "dist/SECURITY/Oß-SECURITY-POLICY.JSON"],
  ["compatibility-fold", "dist/Ｓecurity/OSS-SECURITY-POLICY.JSON"]
])("rejects %s Unicode aliases of the restricted package path", (_label, path) => {
  expect(isForbiddenPackagePath(path)).toBe(true);
  const result = evaluatePackageBoundary({
    entries: [...cleanEntries, path],
    manifest
  });
  expect(result.ok).toBe(false);
  expect(result.blockers).toContain(`forbidden package path: ${path}`);
});

test.each([
  ["trailing dot", "docs/neutral-denied-sentinel.txt."],
  ["trailing space", "docs/neutral-denied-sentinel.txt "],
  ["short-name shape", "docs/NEUTRA~1/neutral-denied-sentinel.txt"]
])("blocks Win32 alias syntax before package file access: %s", async (_label, relativePath) => {
  const root = "/virtual/package";
  const packageManifestPath = join(root, "package.json");
  const sentinelPath = join(root, relativePath);
  const fileInfo = {
    isSymbolicLink: () => false,
    isDirectory: () => false,
    isFile: () => true,
    nlink: 1
  };
  const directoryInfo = virtualDirectoryInfo;
  const inspectedPaths: string[] = [];
  let packInvoked = false;
  const options = {
    root,
    platform: "win32",
    lstatPath: withVirtualPackageRoot(root, async (path: string) => {
      inspectedPaths.push(path);
      if (path === packageManifestPath) return fileInfo;
      if (path === sentinelPath) return fileInfo;
      return directoryInfo;
    }),
    readFilePath: async (path: string) => {
      if (path !== packageManifestPath) throw new Error(`Unexpected read path: ${path}`);
      return JSON.stringify({ ...manifest, files: [relativePath] });
    },
    readDirectory: async () => [],
    packPackage: async () => {
      packInvoked = true;
      return { stdout: JSON.stringify([{ files: [] }]) };
    }
  };

  const result = await checkPackageHygiene(options);

  expect(result.ok).toBe(false);
  expect(result.blockers).toContain(
    `unsupported Windows path alias syntax: ${relativePath}`
  );
  expect(inspectedPaths).not.toContain(sentinelPath);
  expect(packInvoked).toBe(false);
});

test.each([
  ["trailing dot", "/virtual/package."],
  ["trailing space", "/virtual/package "],
  ["short-name shape", "/virtual/PACKAG~1"]
])("rejects Win32 alias syntax in the package root before metadata access: %s", async (_label, root) => {
  const inspectedPaths: string[] = [];
  await expect(checkPackageHygiene({
    root,
    platform: "win32",
    lstatPath: async (path: string) => {
      inspectedPaths.push(path);
      throw new Error(`Unexpected metadata access: ${path}`);
    }
  })).rejects.toThrow("Package root uses unsupported Windows path alias syntax.");
  expect(inspectedPaths).toEqual([]);
});

test("preflight rejects Unicode restricted aliases before alias metadata or pack", async () => {
  const root = "/virtual/package";
  const packageManifestPath = join(root, "package.json");
  const aliases = [
    "dist/securíty/oß-security-policy.json",
    "dist/securi\u0301ty/oß-security-policy.json",
    "dist/SECURITY/Oß-SECURITY-POLICY.JSON"
  ];

  for (const alias of aliases) {
    const lstatCalls: string[] = [];
    const readCalls: string[] = [];
    let packInvoked = false;
    const result = await checkPackageHygiene({
      root,
      lstatPath: withVirtualPackageRoot(root, async (path: string) => {
        lstatCalls.push(path);
        if (path !== packageManifestPath) {
          throw new Error(`Unicode alias metadata must not be inspected: ${path}`);
        }
        return {
          isSymbolicLink: () => false,
          isDirectory: () => false,
          isFile: () => true,
          nlink: 1
        };
      }),
      readFilePath: async (path: string) => {
        readCalls.push(path);
        if (path !== packageManifestPath) {
          throw new Error(`Unicode alias content must not be read: ${path}`);
        }
        return JSON.stringify({ ...manifest, files: ["dist/"], main: alias });
      },
      readDirectory: async () => {
        throw new Error("A blocked Unicode alias must stop before directory enumeration.");
      },
      packPackage: async () => {
        packInvoked = true;
        throw new Error("npm pack must not run after a Unicode alias is found.");
      }
    });

    expect(result.blockers).toContain(`forbidden package path: ${alias}`);
    expect(lstatCalls).toEqual([packageManifestPath]);
    expect(readCalls).toEqual([packageManifestPath]);
    expect(packInvoked).toBe(false);
  }
});

test("preflight rejects unsupported npm glob families before child metadata or pack", async () => {
  const root = "/virtual/package";
  const packageManifestPath = join(root, "package.json");
  const unsupported = [
    "{dist,other}/",
    "@(dist|other)/",
    "+(dist|other)/",
    "dist/*",
    "dist/?",
    "dist/[ab]",
    "dist/!(*.map)"
  ];

  for (const pattern of unsupported) {
    const calls: Array<[string, string]> = [];
    let packInvoked = false;
    const result = await checkPackageHygiene({
      root,
      lstatPath: withVirtualPackageRoot(root, async (path: string) => {
        calls.push(["lstat", path]);
        if (path !== packageManifestPath) {
          throw new Error(`Child metadata must not be inspected: ${path}`);
        }
        return {
          isSymbolicLink: () => false,
          isDirectory: () => false,
          isFile: () => true,
          nlink: 1
        };
      }),
      readFilePath: async (path: string) => {
        calls.push(["read", path]);
        if (path !== packageManifestPath) {
          throw new Error(`Child contents must not be read: ${path}`);
        }
        return JSON.stringify({ ...manifest, files: [pattern] });
      },
      readDirectory: async () => {
        throw new Error("Directories must not be enumerated for unsupported patterns.");
      },
      packPackage: async () => {
        packInvoked = true;
        throw new Error("npm pack must not run for unsupported patterns.");
      }
    });

    expect(result.ok, pattern).toBe(false);
    expect(result.blockers).toContain(`unsupported package path syntax before pack: ${pattern}`);
    expect(calls).toEqual([["lstat", packageManifestPath], ["read", packageManifestPath]]);
    expect(packInvoked).toBe(false);
  }
});

test("preflight rejects a denied sentinel below a case-variant security directory before file access or npm pack", async () => {
  const root = "/virtual/package";
  const deniedSentinelPath = "dist/Security/denied-sentinel.json";
  const deniedSentinelAbsolutePath = join(root, deniedSentinelPath);
  const packageManifestPath = join(root, "package.json");
  const calls: Array<[string, string]> = [];
  let packInvoked = false;
  const fileInfo = {
    isSymbolicLink: () => false,
    isDirectory: () => false,
    isFile: () => true,
    nlink: 1
  };
  const directoryInfo = {
    isSymbolicLink: () => false,
    isDirectory: () => true,
    isFile: () => false,
    nlink: 1
  };
  const directoryEntry = (name: string) => ({
    name,
    isSymbolicLink: () => false,
    isDirectory: () => true,
    isFile: () => false
  });
  const fileEntry = (name: string) => ({
    name,
    isSymbolicLink: () => false,
    isDirectory: () => {
      if (name.toLowerCase() === "denied-sentinel.json") {
        throw new Error("Denied sentinel metadata must not be inspected.");
      }
      return false;
    },
    isFile: () => true
  });

  const result = await checkPackageHygiene({
    root,
    lstatPath: withVirtualPackageRoot(root, async (path: string) => {
      calls.push(["lstat", path]);
      if (path === deniedSentinelAbsolutePath) {
        throw new Error("Denied sentinel metadata must not be inspected.");
      }
      if (path === packageManifestPath) return fileInfo;
      if (
        path === join(root, "dist") ||
        path === join(root, "dist", "Security") ||
        path === join(root, "dist", "cli")
      ) {
        return directoryInfo;
      }
      if (
        path === join(root, "dist", "server.js") ||
        path === join(root, "dist", "cli", "connect-gpt.js")
      ) {
        return fileInfo;
      }
      throw new Error(`Unexpected lstat path: ${path}`);
    }),
    readFilePath: async (path: string) => {
      calls.push(["read", path]);
      if (path === deniedSentinelAbsolutePath) {
        throw new Error("Denied sentinel contents must not be read.");
      }
      if (path !== packageManifestPath) throw new Error(`Unexpected read path: ${path}`);
      return JSON.stringify({ ...manifest, files: ["dist/"] });
    },
    readDirectory: async (path: string) => {
      if (path === join(root, "dist")) return [directoryEntry("Security")];
      if (path === join(root, "dist", "Security")) {
        return [fileEntry("denied-sentinel.json")];
      }
      return [];
    },
    packPackage: async () => {
      packInvoked = true;
      throw new Error("npm pack must not run after a forbidden path is found.");
    }
  });

  expect(result.ok).toBe(false);
  expect(result.blockers).toContain("forbidden package path: dist/Security");
  expect(calls).not.toContainEqual(["lstat", deniedSentinelAbsolutePath]);
  expect(calls).not.toContainEqual(["read", deniedSentinelAbsolutePath]);
  expect(packInvoked).toBe(false);
});

test.each([
  ["missing declared root", "missing-root/", "ENOENT"],
  ["declared root whose parent is a file", "parent-file/child/", "ENOTDIR"]
])("preflight blocks a %s before npm pack", async (_label, declaredRoot, code) => {
  const root = "/virtual/package";
  const packageManifestPath = join(root, "package.json");
  let packInvoked = false;

  const result = await checkPackageHygiene({
    root,
lstatPath: withVirtualPackageRoot(root, async (path: string) => {
      if (path === packageManifestPath) {
        return {
          isSymbolicLink: () => false,
          isDirectory: () => false,
          isFile: () => true,
          nlink: 1
        };
      }
      const error = new Error(code === "ENOENT" ? "root does not exist" : "parent is a file");
      Object.assign(error, { code });
      throw error;
}),
    readFilePath: async (path: string) => {
      if (path !== packageManifestPath) throw new Error(`Unexpected read path: ${path}`);
      return JSON.stringify({ name: "fixture", version: "1.0.0", files: [declaredRoot] });
    },
    readDirectory: async () => {
      throw new Error("A missing package root must not be enumerated.");
    },
    packPackage: async () => {
      packInvoked = true;
      throw new Error("npm pack must not run after a root preflight failure.");
    }
  });

  expect(result.ok).toBe(false);
  expect(result.blockers).toContain(
    `package preflight could not inspect ${declaredRoot.replace(/\/$/, "")}: ` +
      (code === "ENOENT" ? "root does not exist" : "parent is a file")
  );
  expect(packInvoked).toBe(false);
});

test("rejects a symlinked package root before manifest access or packing", async () => {
  const fixtureRoot = await createTempDirectory("gpt-repo-package-root-link-");
  const targetRoot = join(fixtureRoot, "target");
  const root = join(fixtureRoot, "package-root");
  const manifestPath = join(root, "package.json");
  try {
    await mkdir(targetRoot);
    await writeFile(join(targetRoot, "package.json"), JSON.stringify({
      name: "fixture",
      version: "1.0.0",
      files: ["package.json"]
    }));
    await symlink(targetRoot, root);

    const lstatCalls: string[] = [];
    const readCalls: string[] = [];
    let packInvoked = false;
    await expect(checkPackageHygiene({
      root,
      lstatPath: async (path: string) => {
        lstatCalls.push(path);
        return lstat(path);
      },
      readFilePath: async (path: string) => {
        readCalls.push(path);
        return readFile(path, "utf8");
      },
      packPackage: async () => {
        packInvoked = true;
        return { stdout: JSON.stringify([{ files: [] }]) };
      }
    })).rejects.toThrow(/symlink.*package root/i);

    expect(lstatCalls).not.toContain(manifestPath);
    expect(readCalls).toEqual([]);
    expect(packInvoked).toBe(false);
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true });
  }
});

test("rejects a symlinked package root ancestor before manifest access or packing", async () => {
  const fixtureRoot = await createTempDirectory("gpt-repo-package-root-ancestor-link-");
  const physicalParent = join(fixtureRoot, "physical-parent");
  const linkedParent = join(fixtureRoot, "linked-parent");
  const root = join(linkedParent, "nested-package");
  const manifestPath = join(root, "package.json");
  try {
    await mkdir(join(physicalParent, "nested-package"), { recursive: true });
    await writeFile(join(physicalParent, "nested-package", "package.json"), JSON.stringify({
      name: "fixture",
      version: "1.0.0",
      files: ["package.json"]
    }));
    await symlink(physicalParent, linkedParent);

    const lstatCalls: string[] = [];
    const readCalls: string[] = [];
    let packInvoked = false;
    await expect(checkPackageHygiene({
      root,
      lstatPath: async (path: string) => {
        lstatCalls.push(path);
        return lstat(path);
      },
      readFilePath: async (path: string) => {
        readCalls.push(path);
        return readFile(path, "utf8");
      },
      packPackage: async () => {
        packInvoked = true;
        return { stdout: JSON.stringify([{ files: [] }]) };
      }
    })).rejects.toThrow(/symlink.*package root/i);

    expect(lstatCalls).not.toContain(manifestPath);
    expect(readCalls).toEqual([]);
    expect(packInvoked).toBe(false);
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true });
  }
});

test("accepts a legitimate real nested package root", async () => {
  const fixtureRoot = await createTempDirectory("gpt-repo-package-real-nested-root-");
  const root = join(fixtureRoot, "parent", "nested-package");
  const manifestPath = join(root, "package.json");
  try {
    await mkdir(root, { recursive: true });
    await writeFile(manifestPath, JSON.stringify({
      name: "fixture",
      version: "1.0.0",
      files: ["package.json"]
    }));

    const readCalls: string[] = [];
    let packInvoked = false;
    const result = await checkPackageHygiene({
      root,
      readFilePath: async (path: string) => {
        readCalls.push(path);
        return readFile(path, "utf8");
      },
      packPackage: async () => {
        packInvoked = true;
        return { stdout: JSON.stringify([{ files: [] }]) };
      }
    });

    expect(result.ok).toBe(true);
    expect(readCalls).toEqual([manifestPath]);
    expect(packInvoked).toBe(true);
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true });
  }
});

test("fails the package hygiene check when npm pack reaches its timeout", async () => {
  const root = await createTempDirectory("gpt-repo-package-pack-timeout-");
  await writeFile(join(root, "package.json"), JSON.stringify({
    name: "fixture",
    version: "1.0.0",
    files: ["package.json"]
  }));

  const calls: Array<{ command: string; args: string[]; options: { timeout?: number } }> = [];
  const timeoutError = Object.assign(new Error("npm pack timed out"), {
    code: "ETIMEDOUT"
  });
  try {
    await expect(checkPackageHygiene({
      root,
      execFilePath: async (command: string, args: string[], options: { timeout?: number }) => {
        calls.push({ command, args, options });
        throw timeoutError;
      }
    })).rejects.toMatchObject({ code: "ETIMEDOUT" });

    expect(calls).toHaveLength(1);
    expect(calls[0].command).toBe("npm");
    expect(calls[0].args).toEqual(["pack", "--json", "--dry-run", "--ignore-scripts"]);
    expect(Number.isFinite(calls[0].options.timeout)).toBe(true);
    expect(calls[0].options.timeout).toBeGreaterThan(0);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("preflight rejects a symlinked package parent before inspecting its target or packing", async () => {
  const root = await createTempDirectory("gpt-repo-package-parent-link-");
  const externalRoot = await createTempDirectory("gpt-repo-package-parent-target-");
  const packageManifestPath = join(root, "package.json");
  const nestedPath = join(root, "dist", "nested");
  const sentinel = join(externalRoot, "sentinel.js");
  try {
    await writeFile(sentinel, "synthetic package sentinel\n");
    await writeFile(packageManifestPath, JSON.stringify({
      name: "fixture",
      version: "1.0.0",
      files: ["dist/nested/"]
    }));
    await symlink(externalRoot, join(root, "dist"));

    const lstatCalls: string[] = [];
    const directoryCalls: string[] = [];
    let packInvoked = false;
    const result = await checkPackageHygiene({
      root,
      lstatPath: async (path: string) => {
        lstatCalls.push(path);
        if (path === nestedPath) {
          throw new Error("Symlink target metadata must not be inspected.");
        }
        return lstat(path);
      },
      readFilePath: async (path: string) => readFile(path, "utf8"),
      readDirectory: async (path: string) => {
        directoryCalls.push(path);
        throw new Error("Symlink target must not be enumerated.");
      },
      packPackage: async () => {
        packInvoked = true;
        throw new Error("npm pack must not run after a symlinked parent.");
      }
    });

    expect(result.ok).toBe(false);
    expect(result.blockers).toContain("symlink in package: dist");
    expect(lstatCalls.slice(-2)).toEqual([packageManifestPath, join(root, "dist")]);
    expect(directoryCalls).toEqual([]);
    expect(packInvoked).toBe(false);
    expect(await readFile(sentinel, "utf8")).toBe("synthetic package sentinel\n");
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(externalRoot, { recursive: true, force: true });
  }
});

test("preflight rejects a symlinked final package file before npm pack", async () => {
  const root = await createTempDirectory("gpt-repo-package-file-link-");
  const externalRoot = await createTempDirectory("gpt-repo-package-file-target-");
  const packageManifestPath = join(root, "package.json");
  const sentinel = join(externalRoot, "sentinel.js");
  const packageFile = join(root, "dist", "sentinel.js");
  try {
    await mkdir(join(root, "dist"));
    await writeFile(sentinel, "synthetic package sentinel\n");
    await writeFile(packageManifestPath, JSON.stringify({
      name: "fixture",
      version: "1.0.0",
      files: ["dist/sentinel.js"]
    }));
    await symlink(sentinel, packageFile);

    const lstatCalls: string[] = [];
    let packInvoked = false;
    const result = await checkPackageHygiene({
      root,
      lstatPath: async (path: string) => {
        lstatCalls.push(path);
        if (path === sentinel) {
          throw new Error("Symlink target metadata must not be inspected.");
        }
        return lstat(path);
      },
      readFilePath: async (path: string) => readFile(path, "utf8"),
      readDirectory: async () => {
        throw new Error("A file entry must not be enumerated as a directory.");
      },
      packPackage: async () => {
        packInvoked = true;
        throw new Error("npm pack must not run after a symlinked file.");
      }
    });

    expect(result.ok).toBe(false);
    expect(result.blockers).toContain("symlink in package: dist/sentinel.js");
    expect(lstatCalls.slice(-3)).toEqual([packageManifestPath, join(root, "dist"), packageFile]);
    expect(packInvoked).toBe(false);
    expect(await readFile(sentinel, "utf8")).toBe("synthetic package sentinel\n");
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(externalRoot, { recursive: true, force: true });
  }
});

test.each([
  ["declared file", "dist/sentinel.js"],
  ["enumerated directory", "dist/"]
])("preflight rejects a hard-link alias in a %s before content read or npm pack", async (_label, declaredRoot) => {
  const root = await createTempDirectory("gpt-repo-package-hard-link-");
  const externalRoot = await createTempDirectory("gpt-repo-package-hard-link-target-");
  const packageManifestPath = join(root, "package.json");
  const packageFile = join(root, "dist", "sentinel.js");
  const sentinel = join(externalRoot, "sentinel.js");
  try {
    await mkdir(join(root, "dist"));
    await writeFile(packageManifestPath, JSON.stringify({
      name: "fixture",
      version: "1.0.0",
      files: [declaredRoot]
    }));
    await writeFile(sentinel, "synthetic hard-link sentinel\n");
    await link(sentinel, packageFile);

    const reads: string[] = [];
    let packInvoked = false;
    const result = await checkPackageHygiene({
      root,
      lstatPath: lstat,
      readFilePath: async (path: string) => {
        reads.push(path);
        return readFile(path, "utf8");
      },
      readDirectory: readdir,
      packPackage: async () => {
        packInvoked = true;
        throw new Error("npm pack must not run after a hard-link alias is found.");
      }
    });

    expect(result.ok).toBe(false);
    expect(result.blockers).toContain("multiple hard links in package: dist/sentinel.js");
    expect(reads).toEqual([packageManifestPath]);
    expect(packInvoked).toBe(false);
    expect(await readFile(sentinel, "utf8")).toBe("synthetic hard-link sentinel\n");
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(externalRoot, { recursive: true, force: true });
  }
});

test("multiply linked package manifest is rejected before read or npm pack", async () => {
  const root = await createTempDirectory("gpt-repo-package-manifest-hard-link-");
  const externalRoot = await createTempDirectory("gpt-repo-package-manifest-target-");
  const sentinel = join(externalRoot, "package.json");
  const packageManifestPath = join(root, "package.json");
  try {
    await writeFile(sentinel, JSON.stringify({
      name: "fixture",
      version: "1.0.0",
      files: ["dist/"]
    }));
    await link(sentinel, packageManifestPath);

    let manifestRead = false;
    let packInvoked = false;
    await expect(checkPackageHygiene({
      root,
      lstatPath: lstat,
      readFilePath: async () => {
        manifestRead = true;
        throw new Error("A multiply linked manifest must not be read.");
      },
      readDirectory: readdir,
      packPackage: async () => {
        packInvoked = true;
        throw new Error("npm pack must not run after a manifest hard-link alias is found.");
      }
    })).rejects.toThrow("must not have multiple hard links");
    expect(manifestRead).toBe(false);
    expect(packInvoked).toBe(false);
    expect(await readFile(sentinel, "utf8")).toContain('"fixture"');
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(externalRoot, { recursive: true, force: true });
  }
});

test("preflight rejects traversal and separator aliases before child metadata or npm pack", async () => {
  const root = "/virtual/package";
  const packageManifestPath = join(root, "package.json");
  const unsafePaths = [
    "../outside/",
    "nested/../outside/",
    "/outside/",
    "C:/outside/",
    "dist\\private/",
    "dist/\u0000private/"
  ];

  for (const unsafePath of unsafePaths) {
    const lstatCalls: string[] = [];
    let packInvoked = false;
    const result = await checkPackageHygiene({
      root,
      lstatPath: withVirtualPackageRoot(root, async (path: string) => {
        lstatCalls.push(path);
        if (path !== packageManifestPath) {
          throw new Error(`Unsafe package path reached metadata access: ${path}`);
        }
        return {
          isSymbolicLink: () => false,
          isDirectory: () => false,
          isFile: () => true,
          nlink: 1
        };
      }),
      readFilePath: async (path: string) => {
        if (path !== packageManifestPath) {
          throw new Error(`Unsafe package path reached file access: ${path}`);
        }
        return JSON.stringify({ name: "fixture", version: "1.0.0", files: [unsafePath] });
      },
      readDirectory: async () => {
        throw new Error("Unsafe package roots must not be enumerated.");
      },
      packPackage: async () => {
        packInvoked = true;
        throw new Error("npm pack must not run for an unsafe package path.");
      }
    });

    expect(result.ok, unsafePath).toBe(false);
    expect(lstatCalls).toEqual([packageManifestPath]);
    expect(packInvoked).toBe(false);
  }
});

test("preflight filesystem errors fail closed before npm pack", async () => {
  const root = await createTempDirectory("gpt-repo-package-preflight-error-");
  const packageManifestPath = join(root, "package.json");
  const packageDirectory = join(root, "dist");
  try {
    await mkdir(packageDirectory);
    await writeFile(packageManifestPath, JSON.stringify({
      name: "fixture",
      version: "1.0.0",
      files: ["dist/"]
    }));

    let packInvoked = false;
    const blocked = await checkPackageHygiene({
      root,
      lstatPath: lstat,
      readFilePath: async (path: string) => readFile(path, "utf8"),
      readDirectory: async () => {
        const error = Object.assign(new Error("directory unavailable"), { code: "EIO" });
        throw error;
      },
      packPackage: async () => {
        packInvoked = true;
        throw new Error("npm pack must not run after an enumeration error.");
      }
    });
    expect(blocked.ok).toBe(false);
    expect(blocked.blockers.join(" ")).toContain("directory unavailable");
    expect(packInvoked).toBe(false);

    const denied = Object.assign(new Error("metadata unavailable"), { code: "EACCES" });
    await expect(checkPackageHygiene({
      root,
      lstatPath: async (path: string) => {
        if (path === packageManifestPath) return lstat(path);
        throw denied;
      },
      readFilePath: async (path: string) => readFile(path, "utf8"),
      readDirectory: readdir,
      packPackage: async () => {
        packInvoked = true;
        throw new Error("npm pack must not run after a metadata error.");
      }
    })).rejects.toMatchObject({ code: "EACCES" });
    expect(packInvoked).toBe(false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("preflight rejects a restricted entry point before metadata or npm pack", async () => {
  const root = "/virtual/package";
  const restrictedPath = "Security/denied-sentinel.json";
  const restrictedAbsolutePath = join(root, restrictedPath);
  const packageManifestPath = join(root, "package.json");
  const calls: Array<[string, string]> = [];
  let directoryEnumerated = false;
  let packInvoked = false;
  const fileInfo = {
    isSymbolicLink: () => false,
    isDirectory: () => false,
    isFile: () => true,
    nlink: 1
  };

  const result = await checkPackageHygiene({
    root,
    lstatPath: withVirtualPackageRoot(root, async (path: string) => {
      calls.push(["lstat", path]);
      if (path === packageManifestPath) return fileInfo;
      if (path === restrictedAbsolutePath) {
        throw new Error("Restricted policy metadata must not be inspected.");
      }
      throw new Error(`Unexpected lstat path: ${path}`);
    }),
    readFilePath: async (path: string) => {
      calls.push(["read", path]);
      if (path === packageManifestPath) {
        return JSON.stringify({
          ...manifest,
          files: ["dist/"],
          main: restrictedPath
        });
      }
      throw new Error(`Unexpected read path: ${path}`);
    },
    readDirectory: async () => {
      directoryEnumerated = true;
      throw new Error("Package paths must be checked before enumeration.");
    },
    packPackage: async () => {
      packInvoked = true;
      throw new Error("npm pack must not run after a forbidden path is found.");
    }
  });

  expect(result.ok).toBe(false);
  expect(result.blockers).toContain(`forbidden package path: ${restrictedPath}`);
  expect(calls).not.toContainEqual(["lstat", restrictedAbsolutePath]);
  expect(calls).not.toContainEqual(["read", restrictedAbsolutePath]);
  expect(directoryEnumerated).toBe(false);
  expect(packInvoked).toBe(false);
});

async function fixturePackage(
  files: Record<string, string | Buffer>,
  manifestOverrides: Record<string, unknown> = {}
) {
  const root = await createTempDirectory("gpt-repo-package-");
  await mkdir(join(root, "dist", "cli"), { recursive: true });
  await writeFile(
    join(root, "package.json"),
    JSON.stringify({
      name: "package-hygiene-fixture",
      version: "1.0.0",
      files: ["dist/"],
      main: "dist/server.js",
      bin: { fixture: "dist/cli/connect-gpt.js" },
      ...manifestOverrides
    })
  );
  await writeFile(join(root, "dist", "server.js"), "export {};\n");
  await writeFile(join(root, "dist", "cli", "connect-gpt.js"), "#!/usr/bin/env node\n");
  for (const [path, contents] of Object.entries(files)) {
    await writeFile(join(root, path), contents);
  }
  return root;
}

async function runHygieneChecker(root: string) {
  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, [hygieneChecker], {
      cwd: root,
      encoding: "utf8"
    });
    return { code: 0, stdout, stderr };
  } catch (error) {
    const failure = error as { code?: number; stdout?: string; stderr?: string };
    return { code: failure.code ?? 1, stdout: failure.stdout ?? "", stderr: failure.stderr ?? "" };
  }
}

async function runHygieneCheckerWithNpm(root: string, stdout: string) {
  const bin = await createTempDirectory("gpt-repo-fake-npm-");
  const npmPath = join(bin, "npm");
  await writeFile(
    npmPath,
    `#!/usr/bin/env node\nprocess.stdout.write(${JSON.stringify(stdout)});\n`,
    { mode: 0o755 }
  );
  try {
    const { stdout: commandStdout, stderr } = await execFileAsync(
      process.execPath,
      [hygieneChecker],
      {
        cwd: root,
        encoding: "utf8",
        env: { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}` }
      }
    );
    return { code: 0, stdout: commandStdout, stderr };
  } catch (error) {
    const failure = error as { code?: number; stdout?: string; stderr?: string };
    return {
      code: failure.code ?? 1,
      stdout: failure.stdout ?? "",
      stderr: failure.stderr ?? ""
    };
  } finally {
    await rm(bin, { recursive: true, force: true });
  }
}

describe("package content inspection", () => {

  test.skipIf(process.platform === "win32")(
    "rejects a missing denied sentinel below a case-variant security directory before filesystem access",
    async () => {
      const root = await fixturePackage({});
      const restrictedPath = "dist/Security/denied-sentinel.json";
      try {
        await mkdir(join(root, "dist", "Security"), { recursive: true });
        await writeFile(
          join(root, "dist", "Security", "ordinary.js"),
          "configured at /Users/alice/private\n"
        );
        const report = JSON.stringify([
          {
            files: [
              { path: "package.json" },
              { path: "dist/server.js" },
              { path: "dist/cli/connect-gpt.js" },
              { path: restrictedPath },
              { path: "dist/Security/ordinary.js" }
            ]
          }
        ]);

        const result = await runHygieneCheckerWithNpm(root, report);

        expect(result.code).toBe(1);
        expect(result.stderr).toBe("");
        const output = JSON.parse(result.stdout);
        expect(output.blockers).toContain("forbidden package path: dist/Security");
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    }
  );


  test("rejects NUL bytes in a packaged binary file", async () => {
    const root = await fixturePackage({});
    const binaryDirectory = join(root, "dist", "assets");
    try {
      await mkdir(binaryDirectory, { recursive: true });
      await writeFile(join(binaryDirectory, "data.bin"), Buffer.from([0xcf, 0xfa, 0x00]));
      const result = await runHygieneChecker(root);
      expect(result.code).toBe(1);
      expect(result.stdout).toContain("NUL-byte content in package file: dist/assets/data.bin");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("rejects a symlinked root package.json before following it", async () => {
  const externalRoot = await createTempDirectory("gpt-repo-package-external-");
  const root = await createTempDirectory("gpt-repo-package-symlink-");
    try {
      const externalManifest = join(externalRoot, "package.json");
      await writeFile(
        externalManifest,
        JSON.stringify({
          name: "external-manifest-sentinel",
          version: "1.0.0",
          files: ["dist/"],
          main: "dist/server.js"
        })
      );
      await symlink(externalManifest, join(root, "package.json"));

      const result = await runHygieneCheckerWithNpm(
        root,
        JSON.stringify([{ files: [] }]) + "\n"
      );

      expect(result.code).toBe(1);
      expect(result.stderr).toContain("package.json must not be a symbolic link");
      expect(result.stdout).not.toContain("external-manifest-sentinel");
    } finally {
      await rm(root, { recursive: true, force: true });
      await rm(externalRoot, { recursive: true, force: true });
    }
  });

  test("inspection rejects a hard-link alias reported by npm before opening it", async () => {
    const root = await fixturePackage({}, {
      files: ["dist/server.js", "dist/cli/connect-gpt.js"]
    });
  const externalRoot = await createTempDirectory("gpt-repo-package-inspect-hard-link-target-");
    const sentinel = join(externalRoot, "sentinel.txt");
    const hardLink = join(root, "dist", "unlisted.txt");
    try {
      await writeFile(sentinel, "configured at /Users/alice/private\n");
      await link(sentinel, hardLink);

      const opened: string[] = [];
      const result = await checkPackageHygiene({
        root,
        lstatPath: lstat,
        readFilePath: async (path: string) => readFile(path, "utf8"),
        readDirectory: readdir,
        openPath: async (path: string, flags: number) => {
          opened.push(path);
          return open(path, flags);
        },
        packPackage: async () => ({
          stdout: JSON.stringify([{
            files: [
              { path: "package.json" },
              { path: "dist/server.js" },
              { path: "dist/cli/connect-gpt.js" },
              { path: "dist/unlisted.txt" }
            ]
          }])
        })
      });

      expect(result.ok).toBe(false);
      expect(result.blockers).toContain("multiple hard links in package: dist/unlisted.txt");
      expect(result.blockers.join(" ")).not.toContain("home-directory");
      expect(opened).not.toContain(hardLink);
      expect(await readFile(sentinel, "utf8")).toBe("configured at /Users/alice/private\n");
    } finally {
      await rm(root, { recursive: true, force: true });
      await rm(externalRoot, { recursive: true, force: true });
    }
  });

  test("inspection rejects descriptor link changes before content read", async () => {
    const root = await fixturePackage({
      "dist/race.js": "synthetic race sentinel\n"
    });
    const packedPath = join(root, "dist", "race.js");
    let contentRead = false;
    try {
      const pending = checkPackageHygiene({
        root,
        openPath: async (path: string, flags: number) => {
          const handle = await open(path, flags);
          if (path !== packedPath) return handle;
          const before = await handle.stat();
          return {
            stat: async () => ({
              isSymbolicLink: () => before.isSymbolicLink(),
              isDirectory: () => before.isDirectory(),
              isFile: () => before.isFile(),
              nlink: 2,
              dev: before.dev,
              ino: before.ino,
              size: before.size
            }),
            read: async () => {
              contentRead = true;
              return { bytesRead: 0 };
            },
            close: async () => handle.close()
          };
        },
        packPackage: async () => ({
          stdout: JSON.stringify([{ files: [
            { path: "package.json" },
            { path: "dist/server.js" },
            { path: "dist/cli/connect-gpt.js" },
            { path: "dist/race.js" }
          ] }])
        })
      });

      await expect(pending).rejects.toThrow("changed or is multiply linked");
      expect(contentRead).toBe(false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("inspection rejects descriptor identity changes before content read", async () => {
    const root = await fixturePackage({
      "dist/identity-race.js": "synthetic identity sentinel\n"
    });
    const packedPath = join(root, "dist", "identity-race.js");
    let packedContentRead = false;
    try {
      const pending = checkPackageHygiene({
        root,
        openPath: async (path: string, flags: number) => {
          const handle = await open(path, flags);
          if (path !== packedPath) return handle;
          const before = await handle.stat();
          return {
            stat: async () => ({
              isSymbolicLink: () => before.isSymbolicLink(),
              isDirectory: () => before.isDirectory(),
              isFile: () => before.isFile(),
              nlink: before.nlink,
              dev: before.dev,
              ino: before.ino + 1,
              size: before.size
            }),
            read: async () => {
              packedContentRead = true;
              return { bytesRead: 0 };
            },
            close: async () => handle.close()
          };
        },
        packPackage: async () => ({
          stdout: JSON.stringify([{ files: [
            { path: "package.json" },
            { path: "dist/server.js" },
            { path: "dist/cli/connect-gpt.js" },
            { path: "dist/identity-race.js" }
          ] }])
        })
      });

      await expect(pending).rejects.toThrow("changed or is multiply linked");
      expect(packedContentRead).toBe(false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("inspects a packed text file larger than the legacy 256 KiB cap", async () => {
    const root = await fixturePackage({
      "dist/large.txt": Buffer.concat([
        Buffer.alloc(300 * 1024, "a"),
        Buffer.from("\nconfigured at /Users/alice/private\n")
      ])
    });
    try {
      const result = await runHygieneChecker(root);
      expect(result.code).toBe(1);
      expect(result.stdout).toContain("home-directory");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("inspects a leak marker split across an inspection chunk boundary", async () => {
    const prefix = Buffer.alloc(64 * 1024 - 7, "b");
    const marker = Buffer.from("/Users/alice/private\n");
    const root = await fixturePackage({
      "dist/split.txt": Buffer.concat([
        prefix,
        marker,
        Buffer.alloc(300 * 1024 - prefix.length - marker.length, "c")
      ])
    });
    try {
      const result = await runHygieneChecker(root);
      expect(result.code).toBe(1);
      expect(result.stdout).toContain("home-directory");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("accepts a large packed text file without home-directory markers", async () => {
    const root = await fixturePackage({ "dist/large.txt": Buffer.alloc(300 * 1024, "d") });
    try {
      const result = await runHygieneChecker(root);
      expect(result.code, result.stdout + result.stderr).toBe(0);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("rejects mixed NUL content without hiding home-directory paths", async () => {
    const root = await fixturePackage({
      "dist/mixed.bin": Buffer.concat([
        Buffer.from("before /Users/alice/private\n"),
        Buffer.from([0]),
        Buffer.alloc(100 * 1024, "e"),
        Buffer.from("\nafter /home/bob/workspace\n")
      ])
    });
    try {
      const result = await runHygieneChecker(root);
      expect(result.code).toBe(1);
      expect(result.stdout).toContain("NUL");
      expect(result.stdout).toContain("/Users/<user>/");
      expect(result.stdout).toContain("/home/<user>/");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("CLI reports the same NUL blocker as the package boundary", async () => {
    const nulMain = "dist/server\u0000.js";
    const root = await fixturePackage({}, { main: nulMain });
    try {
      const result = await runHygieneChecker(root);
      expect(result.code).toBe(1);
      expect(result.stderr).toBe("");
      const report = JSON.parse(result.stdout);
      expect(report.ok).toBe(false);
      expect(report.blockers).toEqual([
        `NUL byte in declared entry point: ${JSON.stringify(nulMain)}`
      ]);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("CLI rejects a package manifest that is not a regular file", async () => {
  const root = await createTempDirectory("gpt-repo-package-");
    await mkdir(join(root, "package.json"));
    try {
      const result = await runHygieneChecker(root);
      expect(result.code).toBe(1);
      expect(result.stderr).toContain("package.json is not a file.");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("CLI rejects a package without a files allowlist", async () => {
    const root = await fixturePackage({}, { files: [] });
    try {
      const result = await runHygieneChecker(root);
      expect(result.code).toBe(1);
      const report = JSON.parse(result.stdout);
      expect(report.blockers).toContain("package.json must declare a files allowlist");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test.skipIf(process.platform === "win32")(
    "CLI rejects forbidden and unsafe archive path classes",
    async () => {
      const root = await fixturePackage({});
      try {
        const report = JSON.stringify([
          {
            files: [
              { path: "package.json" },
              { path: "dist/server.js" },
              { path: "dist/cli/connect-gpt.js" },
              { path: ".env.local" },
              { path: "security/denied-sentinel.json" },
              { path: "config.local.json" },
              { path: "../escape.js" },
              { path: "C:/escape.js" },
              { path: "//server/share.js" },
              null
            ]
          }
        ]);
        const nulPath = "dist/nul\u0000.js";
        const reportWithNul = JSON.stringify([
          {
            files: [
              ...JSON.parse(report)[0].files,
              { path: nulPath }
            ]
          }
        ]);
        const result = await runHygieneCheckerWithNpm(root, reportWithNul);
        expect(result.code).toBe(1);
        expect(result.stderr).toBe("");
        const output = JSON.parse(result.stdout);
        expect(output.blockers).toEqual(
          expect.arrayContaining([
            "forbidden package path: .env.local",
            "forbidden package path: security/denied-sentinel.json",
            "forbidden package path: config.local.json",
            "unsafe package path: ../escape.js",
            "unsafe package path: C:/escape.js",
            "unsafe package path: //server/share.js",
            "unsafe package path: undefined",
            `NUL byte in package path: ${JSON.stringify(nulPath)}`
          ])
        );
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    }
  );

  test("CLI accepts a manifest without a bin map", async () => {
    const root = await fixturePackage({}, { bin: null });
    try {
      const result = await runHygieneChecker(root);
      expect(result.code).toBe(0);
      expect(result.stderr).toBe("");
      expect(JSON.parse(result.stdout).ok).toBe(true);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test.skipIf(process.platform === "win32")(
    "rejects symlink and non-regular entries reported by npm",
    async () => {
      const root = await fixturePackage({}, {
        files: ["dist/server.js", "dist/cli/connect-gpt.js"]
      });
      try {
        await symlink("server.js", join(root, "dist", "linked.js"));
        await mkdir(join(root, "dist", "dir.js"), { recursive: true });
        const report = JSON.stringify([
          {
            files: [
              { path: "package.json" },
              { path: "dist/server.js" },
              { path: "dist/cli/connect-gpt.js" },
              { path: "dist/linked.js" },
              { path: "dist/dir.js" }
            ]
          }
        ]);
        const result = await runHygieneCheckerWithNpm(root, report);
        expect(result.code).toBe(1);
        expect(result.stdout).toContain("symlink in package: dist/linked.js");
        expect(result.stdout).toContain("non-regular file in package: dist/dir.js");
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    }
  );

  test.skipIf(process.platform === "win32")(
    "reports a malformed npm package report",
    async () => {
      const root = await fixturePackage({});
      try {
        const result = await runHygieneCheckerWithNpm(root, "not-json");
        expect(result.code).toBe(1);
        expect(result.stderr).toContain("Package hygiene check failed:");
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    }
  );

  test.skipIf(process.platform === "win32")(
    "treats a report without files as an empty package",
    async () => {
      const root = await fixturePackage({}, { files: null });
      try {
        const result = await runHygieneCheckerWithNpm(root, JSON.stringify([{}]));
        expect(result.code).toBe(1);
        const report = JSON.parse(result.stdout);
        expect(report.files_allowlist).toBeNull();
        expect(report.blockers).toContain(
          "package.json must declare a files allowlist"
        );
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    }
  );

  test.skipIf(process.platform === "win32")(
    "importing the checker ignores a colliding argv entrypoint filename",
    async () => {
      const root = await fixturePackage({});
  const sandbox = await createTempDirectory("gpt-repo-package-import-");
  const bin = await createTempDirectory("gpt-repo-fake-npm-import-");
      const collisionPath = join(sandbox, "check-package-hygiene.mjs");
      const wrapperPath = join(sandbox, "import-checker.mjs");
      const markerPath = join(sandbox, "npm-pack-invoked");
      try {
        const packReport = JSON.stringify([
          {
            files: [
              { path: "package.json" },
              { path: "dist/server.js" },
              { path: "dist/cli/connect-gpt.js" }
            ]
          }
        ]);
        await writeFile(collisionPath, "export {};\n");
        await writeFile(
          wrapperPath,
          [
            `process.argv[1] = ${JSON.stringify(collisionPath)};`,
            `await import(${JSON.stringify(pathToFileURL(hygieneChecker).href)});`,
            `process.stdout.write("import sentinel complete\\n");`
          ].join("\n")
        );
        await writeFile(
          join(bin, "npm"),
          [
            "#!/usr/bin/env node",
            `require("node:fs").writeFileSync(${JSON.stringify(markerPath)}, "invoked\\n");`,
            `process.stdout.write(${JSON.stringify(packReport)});`
          ].join("\n"),
          { mode: 0o755 }
        );

        const { stdout, stderr } = await execFileAsync(
          process.execPath,
          [wrapperPath],
          {
            cwd: root,
            encoding: "utf8",
            env: { ...process.env, PATH: `${bin}:${process.env.PATH ?? ""}` }
          }
        );

        expect(stdout.trim()).toBe("import sentinel complete");
        expect(stderr).toBe("");
        await expect(lstat(markerPath)).rejects.toMatchObject({ code: "ENOENT" });
      } finally {
        await rm(sandbox, { recursive: true, force: true });
        await rm(bin, { recursive: true, force: true });
        await rm(root, { recursive: true, force: true });
      }
    }
  );
});
