import { execFile } from "node:child_process";
import { lstatSync, realpathSync } from "node:fs";
import { chmod, copyFile, link, mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, parse, relative, resolve, sep } from "node:path";
import { promisify } from "node:util";
import { describe, expect, test } from "vitest";
import { manifestFiles, readScannableText } from "../scripts/check-public.mjs";
import {
  foldPathForRestrictedComparison,
  hasUnsupportedWindowsPathAlias
} from "../scripts/restricted-policy-path.mjs";

async function createTempDirectory(prefix: string): Promise<string> {
  return mkdtemp(join(await realpath(tmpdir()), prefix));
}

const execFileAsync = promisify(execFile);

function withRealApprovedRootComponents<T>(
  injectedLstat: (path: string) => T,
  root = process.cwd()
): (path: string) => T {
  const absoluteRoot = resolve(root);
  const filesystemRoot = parse(absoluteRoot).root;
  const rootComponents = new Set([filesystemRoot]);
  let current = filesystemRoot;
  for (const component of relative(filesystemRoot, absoluteRoot).split(sep).filter(Boolean)) {
    current = join(current, component);
    rootComponents.add(current);
  }
  return (path: string) => rootComponents.has(path)
    ? lstatSync(path) as T
    : injectedLstat(path);
}

describe("public hygiene", () => {
  test("Git ignores bounded local config backup names", async () => {
const sandbox = await createTempDirectory("public-hygiene-ignore-");
    try {
      await execFileAsync("git", ["init", "--quiet"], { cwd: sandbox });
      await copyFile(resolve(process.cwd(), ".gitignore"), join(sandbox, ".gitignore"));
      const { stdout } = await execFileAsync("git", [
        "check-ignore",
        "--no-index",
        "--",
        "config.local.json.backup-before-release",
        "team.local.json.bak"
      ], { cwd: sandbox });

      expect(stdout.trim().split("\n")).toEqual([
        "config.local.json.backup-before-release",
        "team.local.json.bak"
      ]);
    } finally {
      await rm(sandbox, { recursive: true, force: true });
    }
  });

  test("public check accepts an explicit source manifest without Git metadata", async () => {
  const sandbox = await createTempDirectory("public-hygiene-manifest-");
    const scriptPath = resolve(process.cwd(), "scripts/check-public.mjs");
    const manifestPath = join(sandbox, "source-manifest.json");
    try {
      await writeFile(join(sandbox, "README.md"), "Public project description.\n");
      await writeFile(manifestPath, JSON.stringify({ entries: [{ path: "README.md" }] }));

      const { stdout } = await execFileAsync(
        process.execPath,
        [scriptPath, "--manifest", manifestPath],
        { cwd: sandbox }
      );

      expect(stdout.trim()).toBe("Public hygiene check passed.");
    } finally {
      await rm(sandbox, { recursive: true, force: true });
    }
  });

test("public check runs when invoked through a symlinked entrypoint", async () => {
  const sandbox = await createTempDirectory("public-hygiene-entrypoint-link-");
  const scriptPath = resolve(process.cwd(), "scripts/check-public.mjs");
  const linkedScriptPath = join(sandbox, "linked-check-public.mjs");
  const manifestPath = join(sandbox, "source-manifest.json");
  try {
    await writeFile(join(sandbox, "README.md"), "Public project description.\n");
    await writeFile(manifestPath, JSON.stringify({ entries: [{ path: "README.md" }] }));
    await symlink(scriptPath, linkedScriptPath);

    const { stdout, stderr } = await execFileAsync(
      process.execPath,
      [linkedScriptPath, "--manifest", manifestPath],
      { cwd: sandbox }
    );

    expect(stderr).toBe("");
    expect(stdout.trim()).toBe("Public hygiene check passed.");
  } finally {
    await rm(sandbox, { recursive: true, force: true });
  }
});

test("public scan excludes only the exact canonical policy path before filesystem access", () => {
  const unexpectedPathAccess = (file: string) => {
    throw new Error(`Excluded scan path reached filesystem access: ${file}`);
  };
  const unexpectedDescriptorAccess = (descriptor: number) => {
    throw new Error(`Excluded scan path reached descriptor access: ${descriptor}`);
  };

  expect(readScannableText("security/oss-security-policy.json", {
    lstat: unexpectedPathAccess,
    open: unexpectedPathAccess,
    fstat: unexpectedDescriptorAccess,
    readFile: unexpectedDescriptorAccess,
    close: unexpectedDescriptorAccess
  })).toEqual({ status: "excluded" });
});

test("public scan blocks noncanonical restricted path aliases before filesystem access", () => {
  const unexpectedPathAccess = (file: string) => {
    throw new Error(`Restricted path alias reached filesystem access: ${file}`);
  };
  const unexpectedDescriptorAccess = (descriptor: number) => {
    throw new Error(`Restricted path alias reached descriptor access: ${descriptor}`);
  };
  const restrictedPathAliases = [
    "security/OSS-SECURITY-POLICY.JSON",
    "security/Oss-Security-Policy.Json",
    "Security/OSS-SECURITY-POLICY.JSON",
    "nested/security/oss-security-policy.json",
    "nested/Security/OSS-SECURITY-POLICY.JSON",
    "Docs/Nested/SECURITY/OSS-SECURITY-POLICY.JSON",
    "nested/securíty/oß-security-policy.json",
    "nested/securi\u0301ty/oß-security-policy.json",
    "nested/Ｓecurity/OSS-SECURITY-POLICY.JSON",
    "security\\oss-security-policy.json",
    "nested//security/oss-security-policy.json",
    "nested/../security/oss-security-policy.json"
  ];

  for (const alias of restrictedPathAliases) {
    expect(readScannableText(alias, {
      lstat: unexpectedPathAccess,
      open: unexpectedPathAccess,
      fstat: unexpectedDescriptorAccess,
      readFile: unexpectedDescriptorAccess,
      close: unexpectedDescriptorAccess
    }).status).toBe("unsafe");
  }
});

test("public scan uses the injected lstat seam to reject an approved-root component", () => {
  const root = process.cwd();
  const rootComponent = parse(root).root;
  const calls: string[] = [];

  const outcome = readScannableText("README.md", {
    root,
    lstat: (file: string) => {
      calls.push(file);
      return {
        isSymbolicLink: () => file === rootComponent,
        isDirectory: () => file === rootComponent,
        isFile: () => file !== rootComponent,
        nlink: 1,
        dev: 1,
        ino: 2
      };
    },
    open: () => 7,
    fstat: () => ({
      isSymbolicLink: () => false,
      isDirectory: () => false,
      isFile: () => true,
      nlink: 1,
      dev: 1,
      ino: 2
    }),
    readFile: () => "fixture text\n",
    close: () => undefined
  });

  expect(outcome).toEqual({
    status: "unsafe",
    reason: "symlinked or non-directory approved root"
  });
  expect(calls).toEqual([rootComponent]);
});

test("public command blocks a case-variant restricted path marker without opening the target", async () => {
  const sandbox = await createTempDirectory("public-hygiene-policy-alias-");
  const scriptPath = resolve(process.cwd(), "scripts/check-public.mjs");
  const alias = "Security/OSS-SECURITY-POLICY.JSON";
  const aliasPath = join(sandbox, "Security", "OSS-SECURITY-POLICY.JSON");
  const manifestPath = join(sandbox, "source-manifest.json");
  const auditPath = join(sandbox, "policy-access.log");
  const auditModulePath = join(sandbox, "policy-access-audit.mjs");
  const auditModule = String.raw`
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";

const restrictedSuffix = "/security/oss-security-policy.json";
for (const method of ["lstatSync", "statSync", "realpathSync", "openSync", "readFileSync", "accessSync", "existsSync"]) {
  const original = fs[method];
  fs[method] = function (path, ...args) {
    const normalized = typeof path === "string" ? path.replaceAll("\\", "/").toLowerCase() : "";
    if (normalized === restrictedSuffix.slice(1) || normalized.endsWith(restrictedSuffix)) {
      fs.appendFileSync(process.env.PUBLIC_POLICY_ACCESS_LOG, method + ":" + path + "\n");
    }
    return original.call(this, path, ...args);
  };
}
syncBuiltinESMExports();
`;

  try {
    await mkdir(join(sandbox, "Security"), { recursive: true });
    await writeFile(join(sandbox, "README.md"), "Public project description.\n");
    await writeFile(aliasPath, "Do not add write tools.\n");
    await writeFile(
      manifestPath,
      JSON.stringify({ entries: [{ path: "README.md" }, { path: alias }] })
    );
    await writeFile(auditPath, "");
    await writeFile(auditModulePath, auditModule);

    await expect(execFileAsync(
      process.execPath,
      ["--import", auditModulePath, scriptPath, "--manifest", manifestPath],
      {
        cwd: sandbox,
        env: { ...process.env, PUBLIC_POLICY_ACCESS_LOG: auditPath }
      }
    )).rejects.toMatchObject({
      code: 1,
      stderr: expect.stringContaining(
        `${alias}: unsafe public scan entry (restricted policy path alias)`
      )
    });

    expect(await readFile(auditPath, "utf8")).toBe("");
  } finally {
    await rm(sandbox, { recursive: true, force: true });
  }
});

test("public scan reports successfully read text as a scanned outcome", () => {
  const fileInfo = {
    isSymbolicLink: () => false,
    isFile: () => true,
    isDirectory: () => false,
    nlink: 1,
    dev: 1,
    ino: 2
  };

  expect(readScannableText("README.md", {
    lstat: withRealApprovedRootComponents(() => fileInfo),
    open: () => 7,
    fstat: () => fileInfo,
    readFile: () => "safe public text\n",
    close: () => undefined
  })).toEqual({ status: "scanned", text: "safe public text\n" });
});

test.each([
  ["trailing dot", "docs/neutral-denied-sentinel.txt."],
  ["trailing space", "docs/neutral-denied-sentinel.txt "],
  ["short-name shape", "docs/NEUTRA~1/neutral-denied-sentinel.txt"]
])("rejects Win32 alias syntax before public file access: %s", (_label, file) => {
  const calls: string[] = [];
  const failOnAccess = (path: string): never => {
    calls.push(path);
    throw new Error(`Alias path reached file access: ${path}`);
  };
  const failOnDescriptorAccess = (descriptor: number): never => {
    calls.push(String(descriptor));
    throw new Error(`Alias path reached descriptor access: ${descriptor}`);
  };
  const access = {
    root: process.cwd(),
    platform: "win32",
    lstat: failOnAccess,
    open: failOnAccess,
    fstat: failOnDescriptorAccess,
    readFile: failOnDescriptorAccess,
    close: failOnDescriptorAccess
  };

  expect(readScannableText(file, access)).toEqual({
    status: "unsafe",
    reason: "unsupported Windows path alias syntax"
  });
  expect(calls).toEqual([]);
});

test("rejects an alias-shaped public root before filesystem access", () => {
  let accessCount = 0;
  const failOnAccess = (path: string): never => {
    accessCount += 1;
    throw new Error(`Alias root reached file access: ${path}`);
  };
  const failOnDescriptorAccess = (descriptor: number): never => {
    accessCount += 1;
    throw new Error(`Alias root reached descriptor access: ${descriptor}`);
  };
  const access = {
    root: "/fixture/NEUTRA~1",
    platform: "win32",
    lstat: failOnAccess,
    open: failOnAccess,
    fstat: failOnDescriptorAccess,
    readFile: failOnDescriptorAccess,
    close: failOnDescriptorAccess
  };

  expect(readScannableText("docs/neutral-denied-sentinel.txt", access)).toEqual({
    status: "unsafe",
    reason: "unsupported Windows path alias syntax"
  });
  expect(accessCount).toBe(0);
});

test("accepts a normal Win32 spelling and folds Win32 trailing aliases lexically", () => {
  const fileInfo = {
    isSymbolicLink: () => false,
    isFile: () => true,
    isDirectory: () => false,
    nlink: 1,
    dev: 1,
    ino: 2
  };
  const directoryInfo = {
    isSymbolicLink: () => false,
    isFile: () => false,
    isDirectory: () => true,
    nlink: 1,
    dev: 1,
    ino: 1
  };
  const access = {
    root: process.cwd(),
    platform: "win32",
    lstat: (path: string) => path.endsWith("neutral-denied-sentinel.txt")
      ? fileInfo
      : directoryInfo,
    open: () => 7,
    fstat: () => fileInfo,
    readFile: () => "neutral denied sentinel\n",
    close: () => undefined
  };

  expect(hasUnsupportedWindowsPathAlias("docs/NEUTRA~1/sentinel.txt", "win32")).toBe(true);
  expect(hasUnsupportedWindowsPathAlias(
    "DOCS/ＮＥＵＴＲＡ～１/NEUTRAL-DENIED-SENTINEL.TXT. ",
    "win32"
  )).toBe(true);
  expect(hasUnsupportedWindowsPathAlias("docs/neutral/sentinel.txt", "win32")).toBe(false);
  expect(foldPathForRestrictedComparison(
    "DOCS/ＮＥＵＴＲＡ～１/NEUTRAL-DENIED-SENTINEL.TXT. ",
    "win32"
  )).toBe("docs/neutra~1/neutral-denied-sentinel.txt");
  expect(readScannableText("docs/neutral-denied-sentinel.txt", access)).toEqual({
    status: "scanned",
    text: "neutral denied sentinel\n"
  });
});

test.each(["darwin", "linux"])("preserves literal trailing and tilde names on %s", (platform) => {
  for (const path of [
    "docs/neutral-name.",
    "docs/neutral-name ",
    "docs/neutral~1/name.txt"
  ]) {
    expect(hasUnsupportedWindowsPathAlias(path, platform)).toBe(false);
    expect(foldPathForRestrictedComparison(path, platform)).toBe(path);
  }
});

test.each([
  ["trailing dot", "/fixture/docs./neutral-denied-sentinel.json"],
  ["trailing space", "/fixture/docs /neutral-denied-sentinel.json"],
  ["short-name shape", "/fixture/NEUTRA~1/neutral-denied-sentinel.json"]
])("rejects Win32 manifest aliases before file access: %s", (_label, manifestPath) => {
  const calls: string[] = [];
  const failOnAccess = (path: string): never => {
    calls.push(path);
    throw new Error(`Alias manifest reached file access: ${path}`);
  };
  const failOnDescriptorAccess = (descriptor: number): never => {
    calls.push(String(descriptor));
    throw new Error(`Alias manifest reached descriptor access: ${descriptor}`);
  };
  const access = {
    root: "/fixture",
    platform: "win32",
    realpath: (path: string) => path,
    lstat: failOnAccess,
    open: failOnAccess,
    fstat: failOnDescriptorAccess,
    readFile: failOnDescriptorAccess,
    close: failOnDescriptorAccess
  };

  expect(() => manifestFiles(manifestPath, access)).toThrow(
    "unsupported Windows path alias syntax"
  );
  expect(calls).toEqual([]);
});

test("rejects an alias-shaped manifest root before filesystem access", () => {
  const calls: string[] = [];
  const failOnAccess = (path: string): never => {
    calls.push(path);
    throw new Error(`Alias root reached file access: ${path}`);
  };
  const failOnDescriptorAccess = (descriptor: number): never => {
    calls.push(String(descriptor));
    throw new Error(`Alias root reached descriptor access: ${descriptor}`);
  };
  expect(() => manifestFiles("/fixture/source-manifest.json", {
    root: "/fixture/NEUTRA~1",
    platform: "win32",
    realpath: failOnAccess,
    lstat: failOnAccess,
    open: failOnAccess,
    fstat: failOnDescriptorAccess,
    readFile: failOnDescriptorAccess,
    close: failOnDescriptorAccess
  })).toThrow("unsupported Windows path alias syntax");
  expect(calls).toEqual([]);
});

test("manifest policy suffix is rejected before any filesystem access", () => {
  const calls: string[] = [];
  const unexpectedPathAccess = (path: string) => {
    calls.push(path);
    throw new Error(`Protected manifest path reached filesystem access: ${path}`);
  };
  const unexpectedDescriptorAccess = (descriptor: number) => {
    calls.push(String(descriptor));
    throw new Error(`Protected manifest path reached descriptor access: ${descriptor}`);
  };

  for (const path of [
    "/fixture/nested\\Security/OSS-SECURITY-POLICY.JSON",
    "/fixture/security/OSS-SECURITY-POLICY.JSON/.",
    "/fixture/securíty/oß-security-policy.json",
    "/fixture/securi\u0301ty/oß-security-policy.json",
    "/fixture/Ｓecurity/OSS-SECURITY-POLICY.JSON"
  ]) {
    expect(() => manifestFiles(path, {
      root: "/fixture",
      lstat: unexpectedPathAccess,
      open: unexpectedPathAccess,
      fstat: unexpectedDescriptorAccess,
      readFile: unexpectedDescriptorAccess,
      close: unexpectedDescriptorAccess
    })).toThrow("Restricted policy manifest path is forbidden");
  }
  expect(calls).toEqual([]);
});

test("manifest symlink alias is rejected without opening or reading its synthetic target", () => {
  const aliasPath = "/fixture/source-manifest.json";
  const syntheticTarget = "/fixture/denied-sentinel.json";
  const calls: string[] = [];
  const symlinkInfo = {
    isSymbolicLink: () => true,
    isFile: () => false,
    isDirectory: () => false,
    nlink: 1,
    dev: 1,
    ino: 2
  };
  const rootInfo = {
    isSymbolicLink: () => false,
    isFile: () => false,
    isDirectory: () => true,
    nlink: 1,
    dev: 1,
    ino: 1
  };
  const rejectTargetPathAccess = (path: string) => {
    calls.push(path);
    if (path === syntheticTarget) throw new Error("Synthetic target must not be followed.");
    if (path === "/" || path === "/fixture") return rootInfo;
    return symlinkInfo;
  };
  const rejectTargetOpenAccess = (path: string): number => {
    calls.push(path);
    throw new Error("A rejected manifest must not be opened.");
  };
  const rejectTargetDescriptorAccess = (descriptor: number) => {
    calls.push(String(descriptor));
    throw new Error("A rejected manifest must not reach descriptor access.");
  };

  expect(() => manifestFiles(aliasPath, {
    root: "/fixture",
    realpath: (path: string) => path,
    lstat: rejectTargetPathAccess,
    open: rejectTargetOpenAccess,
    fstat: rejectTargetDescriptorAccess,
    readFile: rejectTargetDescriptorAccess,
    close: rejectTargetDescriptorAccess
  })).toThrow("Source manifest must not be a symbolic link");
  expect(calls).toEqual(["/", "/fixture", aliasPath]);
  expect(calls).not.toContain(syntheticTarget);
});

test("Win32 ADS manifest spelling is rejected before path metadata or open", () => {
  const calls: string[] = [];
  const rejectPathAccess = (path: string) => {
    calls.push(path);
    throw new Error(`Unexpected manifest access: ${path}`);
  };
  const rejectDescriptorAccess = (descriptor: number) => {
    calls.push(String(descriptor));
    throw new Error(`Unexpected manifest descriptor access: ${descriptor}`);
  };
  const manifestPath = "/fixture/source-manifest.json::$DATA";

  expect(() => manifestFiles(manifestPath, {
    root: "/fixture",
    platform: "win32",
    lstat: rejectPathAccess,
    realpath: rejectPathAccess,
    open: rejectPathAccess,
    fstat: rejectDescriptorAccess,
    readFile: rejectDescriptorAccess,
    close: rejectDescriptorAccess
  })).toThrow("Source manifest path uses unsupported Windows path alias syntax.");
  expect(calls).toEqual([]);
});

test("manifest parent-directory symlink is rejected before target metadata or open", async () => {
  const sandbox = await createTempDirectory("public-hygiene-manifest-parent-link-");
  const approvedRoot = join(sandbox, "approved");
  const externalRoot = join(sandbox, "external");
  const targetManifest = join(externalRoot, "source-manifest.json");
  const manifestPath = join(approvedRoot, "linked", "source-manifest.json");
  try {
    await mkdir(approvedRoot);
    await mkdir(externalRoot);
    await writeFile(targetManifest, JSON.stringify({ entries: [] }));
    await symlink(externalRoot, join(approvedRoot, "linked"));

    const calls: string[] = [];
    const unexpectedPathAccess = (path: string) => {
      calls.push(path);
      throw new Error(`Symlink target metadata must not be inspected: ${path}`);
    };
    const unexpectedDescriptorAccess = (descriptor: number) => {
      calls.push(String(descriptor));
      throw new Error(`Symlink target descriptor must not be inspected: ${descriptor}`);
    };

    expect(() => manifestFiles(manifestPath, {
      root: approvedRoot,
      lstat: (path: string) => {
        calls.push(path);
        return lstatSync(path);
      },
      open: unexpectedPathAccess,
      fstat: unexpectedDescriptorAccess,
      readFile: unexpectedDescriptorAccess,
      close: unexpectedDescriptorAccess
    })).toThrow("symlinked or non-directory parent");
    const canonicalRoot = realpathSync(approvedRoot);
    expect(calls).toContain(join(canonicalRoot, "linked"));
    expect(calls).not.toContain(manifestPath);
    expect(calls).not.toContain(targetManifest);
    expect(await readFile(targetManifest, "utf8")).toBe(JSON.stringify({ entries: [] }));
  } finally {
    await rm(sandbox, { recursive: true, force: true });
  }
});

test("manifest root symlink is rejected before its neutral manifest is opened", async () => {
  const sandbox = await createTempDirectory("public-hygiene-root-link-");
  const targetRoot = join(sandbox, "target-root");
  const approvedAlias = join(sandbox, "approved-alias");
  const targetManifest = join(targetRoot, "source-manifest.json");
  const manifestPath = join(approvedAlias, "source-manifest.json");
  const openedPaths: string[] = [];
  const unexpectedOpen = (path: string) => {
    openedPaths.push(path);
    throw new Error(`Invalid root manifest must not be opened: ${path}`);
  };
  const unexpectedDescriptorAccess = (descriptor: number) => {
    throw new Error(`Invalid root manifest must not be inspected: ${descriptor}`);
  };
  try {
    await mkdir(targetRoot);
    await writeFile(targetManifest, JSON.stringify({ entries: [{ path: "README.md" }] }));
    await symlink(targetRoot, approvedAlias);

    expect(() => manifestFiles(manifestPath, {
      root: approvedAlias,
      lstat: (path: string) => lstatSync(path),
      open: unexpectedOpen,
      fstat: unexpectedDescriptorAccess,
      readFile: unexpectedDescriptorAccess,
      close: unexpectedDescriptorAccess
    })).toThrow("Approved source root must be a real directory");
    expect(openedPaths).toEqual([]);
  } finally {
    await rm(sandbox, { recursive: true, force: true });
  }
});

test("manifest root ancestor symlink is rejected before the neutral manifest is opened", async () => {
  const sandbox = await createTempDirectory("public-hygiene-root-ancestor-link-");
  const physicalParent = join(sandbox, "physical-parent");
  const linkedParent = join(sandbox, "linked-parent");
  const root = join(linkedParent, "project");
  const manifestPath = join(root, "source-manifest.json");
  const openedPaths: string[] = [];
  try {
    await mkdir(join(physicalParent, "project"), { recursive: true });
    await writeFile(
      join(physicalParent, "project", "source-manifest.json"),
      JSON.stringify({ entries: [{ path: "README.md" }] })
    );
    await symlink(physicalParent, linkedParent);

    expect(() => manifestFiles(manifestPath, {
      root,
      lstat: (path: string) => lstatSync(path),
      open: (path: string) => {
        openedPaths.push(path);
        throw new Error("A symlinked root ancestor must stop before manifest open.");
      }
    })).toThrow("Approved source root must be a real directory");
    expect(openedPaths).toEqual([]);
  } finally {
    await rm(sandbox, { recursive: true, force: true });
  }
});

test("public check rejects empty and unscannable manifest inventories", async () => {
  const sandbox = await createTempDirectory("public-hygiene-empty-inventory-");
  const scriptPath = resolve(process.cwd(), "scripts/check-public.mjs");
  const manifestPath = join(sandbox, "source-manifest.json");
  try {
    await writeFile(manifestPath, JSON.stringify({ entries: [] }));
    await expect(execFileAsync(
      process.execPath,
      [scriptPath, "--manifest", manifestPath],
      { cwd: sandbox }
    )).rejects.toMatchObject({
      stderr: expect.stringContaining("must contain at least one entry")
    });

    await writeFile(
      manifestPath,
      JSON.stringify({ entries: [{ path: "node_modules/neutral-sentinel.js" }] })
    );
    await expect(execFileAsync(
      process.execPath,
      [scriptPath, "--manifest", manifestPath],
      { cwd: sandbox }
    )).rejects.toMatchObject({
      code: 1,
      stdout: "",
      stderr: expect.stringContaining("no public files to scan")
    });
  } finally {
    await rm(sandbox, { recursive: true, force: true });
  }
});

test("public inventory is rooted at the discovered Git root from a nested working directory", async () => {
  const sandbox = await createTempDirectory("public-hygiene-rooted-inventory-");
  const repoRoot = join(sandbox, "repo");
  const nestedWorkingDirectory = join(repoRoot, "tools", "nested");
  const wrongRoot = join(sandbox, "wrong-root");
  const fakeBin = join(sandbox, "fake-bin");
  const fakeGit = join(fakeBin, "git");
  const gitLog = join(sandbox, "git-arguments.jsonl");
  const scriptPath = resolve(process.cwd(), "scripts/check-public.mjs");
  try {
    await mkdir(join(repoRoot, "docs"), { recursive: true });
    await mkdir(nestedWorkingDirectory, { recursive: true });
    await mkdir(wrongRoot);
    await mkdir(fakeBin);
    await writeFile(join(repoRoot, "docs", "marker.md"), ["Prom", "ptiva"].join("") + "\n");
    await writeFile(fakeGit, `#!/usr/bin/env node
const fs = require("node:fs");
const args = process.argv.slice(2);
fs.appendFileSync(process.env.FAKE_GIT_LOG, JSON.stringify(args) + "\\n");
const root = process.env.FAKE_GIT_ROOT;
const directoryIndex = args.indexOf("-C");
const command = args.slice(directoryIndex + 2);
if (command[0] === "rev-parse" && command[1] === "--show-toplevel") {
  process.stdout.write(root + "\\n");
} else if (command[0] === "ls-files" && command[1] === "-z" && args[directoryIndex + 1] === root) {
  if (process.env.FAKE_GIT_EMPTY !== "1") process.stdout.write("docs/marker.md\\0");
} else {
  process.exit(78);
}
`);
    await chmod(fakeGit, 0o755);

    await expect(execFileAsync(process.execPath, [scriptPath], {
      cwd: nestedWorkingDirectory,
      env: {
        ...process.env,
        PATH: `${fakeBin}:${process.env.PATH ?? ""}`,
        FAKE_GIT_ROOT: repoRoot,
        FAKE_GIT_LOG: gitLog
      }
    })).rejects.toMatchObject({
      code: 1,
      stderr: expect.stringContaining("docs/marker.md: blocked public-release marker found")
    });

    const commands = (await readFile(gitLog, "utf8"))
      .trim()
      .split("\n")
      .map((line: string) => JSON.parse(line));
    expect(commands).toEqual([
      ["-C", nestedWorkingDirectory, "rev-parse", "--show-toplevel"],
      ["-C", repoRoot, "ls-files", "-z"]
    ]);

    await expect(execFileAsync(process.execPath, [scriptPath], {
      cwd: nestedWorkingDirectory,
      env: {
        ...process.env,
        PATH: `${fakeBin}:${process.env.PATH ?? ""}`,
        FAKE_GIT_ROOT: repoRoot,
        FAKE_GIT_EMPTY: "1",
        FAKE_GIT_LOG: gitLog
      }
    })).rejects.toMatchObject({
      code: 1,
      stderr: expect.stringContaining("Source inventory is empty")
    });

    await expect(execFileAsync(process.execPath, [scriptPath], {
      cwd: nestedWorkingDirectory,
      env: {
        ...process.env,
        PATH: `${fakeBin}:${process.env.PATH ?? ""}`,
        FAKE_GIT_ROOT: wrongRoot,
        FAKE_GIT_LOG: gitLog
      }
    })).rejects.toMatchObject({
      code: 1,
      stderr: expect.stringContaining("Starting directory is outside the discovered Git root")
    });
  } finally {
    await rm(sandbox, { recursive: true, force: true });
  }
});

test("manifest outside its approved root is rejected before filesystem access", () => {
  const calls: string[] = [];
  const unexpectedPathAccess = (path: string) => {
    calls.push(path);
    throw new Error(`Outside-root manifest reached filesystem access: ${path}`);
  };
  const unexpectedDescriptorAccess = (descriptor: number) => {
    calls.push(String(descriptor));
    throw new Error(`Outside-root manifest reached descriptor access: ${descriptor}`);
  };

  expect(() => manifestFiles("/outside/source-manifest.json", {
    root: "/fixture",
    lstat: unexpectedPathAccess,
    open: unexpectedPathAccess,
    fstat: unexpectedDescriptorAccess,
    readFile: unexpectedDescriptorAccess,
    close: unexpectedDescriptorAccess
  })).toThrow("outside the approved root");
  expect(calls).toEqual([]);
});

test("candidate symlink alias is rejected without following its synthetic target", () => {
  const aliasPath = "README.md";
  const syntheticTarget = "/fixture/denied-sentinel.json";
  const calls: string[] = [];
  const symlinkInfo = {
    isSymbolicLink: () => true,
    isFile: () => false,
    isDirectory: () => false,
    nlink: 1,
    dev: 1,
    ino: 3
  };
  const inspectAliasOnly = (path: string) => {
    calls.push(path);
    if (path === syntheticTarget) throw new Error("Synthetic target must not be followed.");
    return symlinkInfo;
  };
  const inspectAliasOpen = (path: string): number => {
    calls.push(path);
    throw new Error("A rejected final symlink must not be opened.");
  };
  const inspectDescriptorOnly = (descriptor: number) => {
    calls.push(String(descriptor));
    throw new Error("A rejected final symlink must not reach descriptor access.");
  };

  expect(readScannableText(aliasPath, {
    lstat: withRealApprovedRootComponents(inspectAliasOnly),
    open: inspectAliasOpen,
    fstat: inspectDescriptorOnly,
    readFile: inspectDescriptorOnly,
    close: inspectDescriptorOnly
  })).toEqual({ status: "unsafe", reason: "symbolic link" });
  expect(calls).toEqual([resolve(process.cwd(), aliasPath)]);
  expect(calls).not.toContain(syntheticTarget);
});

test("regular hard-link alias is rejected without opening or reading its twin", async () => {
  const sandbox = await createTempDirectory("public-hygiene-hard-link-");
  const originalDirectory = process.cwd();
  const original = join(sandbox, "docs", "sentinel.md");
  const alias = join(sandbox, "docs", "hard-link.md");
  try {
    await mkdir(join(sandbox, "docs"), { recursive: true });
    await writeFile(original, "synthetic hard-link sentinel\n");
    await link(original, alias);
    process.chdir(sandbox);

    const calls: string[] = [];
    const result = readScannableText("docs/hard-link.md", {
      lstat: withRealApprovedRootComponents((path: string) => {
        calls.push(`lstat:${path}`);
        return lstatSync(path);
      }),
      open: (path: string) => {
        calls.push(`open:${path}`);
        throw new Error("A multiply linked file must not be opened.");
      },
      fstat: (descriptor: number) => {
        calls.push(`fstat:${descriptor}`);
        throw new Error("A multiply linked file must not be inspected through a descriptor.");
      },
      readFile: (descriptor: number) => {
        calls.push(`read:${descriptor}`);
        throw new Error("A multiply linked file must not be read.");
      },
      close: (descriptor: number) => {
        calls.push(`close:${descriptor}`);
      }
    });

    expect(result).toEqual({ status: "unsafe", reason: "multiple hard links" });
    expect(calls).toEqual([
      `lstat:${join(process.cwd(), "docs")}`,
      `lstat:${join(process.cwd(), "docs", "hard-link.md")}`
    ]);
    expect(await readFile(original, "utf8")).toBe("synthetic hard-link sentinel\n");
  } finally {
    process.chdir(originalDirectory);
    await rm(sandbox, { recursive: true, force: true });
  }
});

test("public check reports a hard-link alias as an unsafe failure", async () => {
  const sandbox = await createTempDirectory("public-hygiene-hard-link-cli-");
  const scriptPath = resolve(process.cwd(), "scripts/check-public.mjs");
  const target = join(sandbox, "docs", "sentinel.md");
  const alias = join(sandbox, "docs", "hard-link.md");
  const manifestPath = join(sandbox, "source-manifest.json");
  try {
    await mkdir(join(sandbox, "docs"), { recursive: true });
    await writeFile(target, "synthetic hard-link sentinel\n");
    await link(target, alias);
    await writeFile(
      manifestPath,
      JSON.stringify({ entries: [{ path: "docs/hard-link.md" }] })
    );

    await expect(execFileAsync(
      process.execPath,
      [scriptPath, "--manifest", manifestPath],
      { cwd: sandbox }
    )).rejects.toMatchObject({
      code: 1,
      stdout: "",
      stderr: expect.stringContaining(
        "docs/hard-link.md: unsafe public scan entry (multiple hard links)."
      )
    });
    expect(await readFile(target, "utf8")).toBe("synthetic hard-link sentinel\n");
  } finally {
    await rm(sandbox, { recursive: true, force: true });
  }
});

test.each([
  "docs/../README.md",
  "docs/../../outside.md",
  "node_modules/../README.md",
  "dist/../README.md",
  "package-lock.json/../README.md",
  "docs\\README.md",
  "docs/\u0000README.md",
  "nested\\Security\\OSS-SECURITY-POLICY.JSON",
  "Docs/Nested/SECURITY/OSS-SECURITY-POLICY.JSON/"
])("rejects unsafe public scan path before filesystem access: %s", (path) => {
  const calls: string[] = [];
  const unexpectedPathAccess = (file: string) => {
    calls.push(file);
    throw new Error(`Unsafe scan path reached filesystem access: ${file}`);
  };
  const unexpectedDescriptorAccess = (descriptor: number) => {
    calls.push(String(descriptor));
    throw new Error(`Unsafe scan path reached descriptor access: ${descriptor}`);
  };

  expect(readScannableText(path, {
    lstat: unexpectedPathAccess,
    open: unexpectedPathAccess,
    fstat: unexpectedDescriptorAccess,
    readFile: unexpectedDescriptorAccess,
    close: unexpectedDescriptorAccess
  })).toEqual({ status: "unsafe", reason: "unsafe relative path" });
  expect(calls).toEqual([]);
});

test("rejects a symlinked public scan parent before inspecting its target", async () => {
  const sandbox = await createTempDirectory("public-hygiene-parent-link-");
  const originalDirectory = process.cwd();
  const externalRoot = join(sandbox, "external");
  const sentinel = join(externalRoot, "sentinel.md");
  try {
    await mkdir(join(sandbox, "docs"), { recursive: true });
    await mkdir(externalRoot);
    await writeFile(sentinel, "synthetic sentinel\n");
    await symlink(externalRoot, join(sandbox, "docs", "linked"));
    process.chdir(sandbox);

    const calls: string[] = [];
    const result = readScannableText("docs/linked/sentinel.md", {
      lstat: withRealApprovedRootComponents((path: string) => {
        calls.push(`lstat:${path}`);
        if (path === "docs/linked/sentinel.md" || path === sentinel) {
          throw new Error("Symlink target metadata must not be inspected.");
        }
        return lstatSync(path);
      }),
      open: (path: string) => {
        calls.push(`open:${path}`);
        throw new Error("Symlink target must not be opened.");
      },
      fstat: (descriptor: number) => {
        calls.push(`fstat:${descriptor}`);
        throw new Error("Symlink target must not be inspected.");
      },
      readFile: (descriptor: number) => {
        calls.push(`read:${descriptor}`);
        throw new Error("Symlink target must not be read.");
      },
      close: (descriptor: number) => {
        calls.push(`close:${descriptor}`);
      }
    });

    expect(result).toEqual({
      status: "unsafe",
      reason: "symlinked or non-directory parent"
    });
    expect(calls).toEqual([
    `lstat:${join(process.cwd(), "docs")}`,
    `lstat:${join(process.cwd(), "docs", "linked")}`
    ]);
    expect(await readFile(sentinel, "utf8")).toBe("synthetic sentinel\n");
  } finally {
    process.chdir(originalDirectory);
    await rm(sandbox, { recursive: true, force: true });
  }
});

test("rejects a symlinked public scan file before opening its target", async () => {
  const sandbox = await createTempDirectory("public-hygiene-file-link-");
  const originalDirectory = process.cwd();
  const externalRoot = join(sandbox, "external");
  const sentinel = join(externalRoot, "sentinel.md");
  try {
    await mkdir(join(sandbox, "docs"), { recursive: true });
    await mkdir(externalRoot);
    await writeFile(sentinel, "synthetic sentinel\n");
    await symlink(sentinel, join(sandbox, "docs", "linked.md"));
    process.chdir(sandbox);

    const calls: string[] = [];
    const result = readScannableText("docs/linked.md", {
      lstat: withRealApprovedRootComponents((path: string) => {
        calls.push(`lstat:${path}`);
        if (path === sentinel) throw new Error("Symlink target metadata must not be inspected.");
        return lstatSync(path);
      }),
      open: (path: string) => {
        calls.push(`open:${path}`);
        throw new Error("Symlink target must not be opened.");
      },
      fstat: (descriptor: number) => {
        calls.push(`fstat:${descriptor}`);
        throw new Error("Symlink target must not be inspected.");
      },
      readFile: (descriptor: number) => {
        calls.push(`read:${descriptor}`);
        throw new Error("Symlink target must not be read.");
      },
      close: (descriptor: number) => {
        calls.push(`close:${descriptor}`);
      }
    });

    expect(result).toEqual({ status: "unsafe", reason: "symbolic link" });
    expect(calls).toEqual([
      `lstat:${join(process.cwd(), "docs")}`,
      `lstat:${join(process.cwd(), "docs", "linked.md")}`
    ]);
    expect(await readFile(sentinel, "utf8")).toBe("synthetic sentinel\n");
  } finally {
    process.chdir(originalDirectory);
    await rm(sandbox, { recursive: true, force: true });
  }
});

test.each(["lstat", "open"] as const)(
  "public scan does not skip a %s failure as an excluded path",
  (stage) => {
    const failure = Object.assign(new Error(`${stage} unavailable`), {
      code: stage === "lstat" ? "EACCES" : "EIO"
    });
    const fileInfo = {
      isSymbolicLink: () => false,
      isFile: () => true,
      isDirectory: () => false,
      nlink: 1,
      dev: 1,
      ino: 2
    };

    expect(() => readScannableText("README.md", {
      lstat: withRealApprovedRootComponents(() => {
        if (stage === "lstat") throw failure;
        return fileInfo;
      }),
      open: () => {
        if (stage === "open") throw failure;
        throw new Error("The fixture only exercises the failing operation.");
      },
      fstat: () => {
        throw new Error("The fixture only exercises the failing operation.");
      },
      readFile: () => {
        throw new Error("The fixture only exercises the failing operation.");
      },
      close: () => undefined
    })).toThrow(failure.message);
  }
);

test("public scan rejects descriptor identity changes before content read", () => {
  const before = {
    isSymbolicLink: () => false,
    isFile: () => true,
    isDirectory: () => false,
    nlink: 1,
    dev: 1,
    ino: 2
  };
  const opened = { ...before, ino: 3 };
  const calls: string[] = [];

  const outcome = readScannableText("README.md", {
    lstat: withRealApprovedRootComponents(() => before),
    open: (path: string) => {
      calls.push(`open:${path}`);
      return 7;
    },
    fstat: (descriptor: number) => {
      calls.push(`fstat:${descriptor}`);
      return opened;
    },
    readFile: (descriptor: number) => {
      calls.push(`read:${descriptor}`);
      throw new Error("A changed descriptor must not be read.");
    },
    close: (descriptor: number) => {
      calls.push(`close:${descriptor}`);
    }
  });

  expect(outcome).toEqual({ status: "unsafe", reason: "file changed during inspection" });
  expect(calls).toEqual([
    `open:${join(process.cwd(), "README.md")}`,
    "fstat:7",
    "close:7"
  ]);
});

test("public check fails closed when a manifest entry is unavailable", async () => {
  const sandbox = await createTempDirectory("public-hygiene-missing-entry-");
  const scriptPath = resolve(process.cwd(), "scripts/check-public.mjs");
  const manifestPath = join(sandbox, "source-manifest.json");
  try {
    await writeFile(manifestPath, JSON.stringify({ entries: [{ path: "README.md" }] }));
    await expect(execFileAsync(
      process.execPath,
      [scriptPath, "--manifest", manifestPath],
      { cwd: sandbox }
    )).rejects.toMatchObject({
      stderr: expect.stringMatching(/ENOENT|no such file/i)
    });
  } finally {
    await rm(sandbox, { recursive: true, force: true });
  }
});

test("public check scans ordinary files below a case-variant Security root", async () => {
  const sandbox = await createTempDirectory("public-hygiene-security-root-");
  const scriptPath = resolve(process.cwd(), "scripts/check-public.mjs");
  const manifestPath = join(sandbox, "source-manifest.json");
  try {
    await mkdir(join(sandbox, "Security"), { recursive: true });
    await writeFile(join(sandbox, "Security", "public.md"), "Do not add write tools.\n");
    await writeFile(
      manifestPath,
      JSON.stringify({ entries: [{ path: "Security/public.md" }] })
    );

    await expect(execFileAsync(
      process.execPath,
      [scriptPath, "--manifest", manifestPath],
      { cwd: sandbox }
    )).rejects.toMatchObject({
      stderr: expect.stringContaining(
        "Security/public.md: blocked public-release marker found"
      )
    });
  } finally {
    await rm(sandbox, { recursive: true, force: true });
  }
});

test("public check rejects case variants of private artifacts outside scan roots", async () => {
  const sandbox = await createTempDirectory("public-hygiene-private-cases-");
  const scriptPath = resolve(process.cwd(), "scripts/check-public.mjs");
  const manifestPath = join(sandbox, "source-manifest.json");
  try {
    await writeFile(manifestPath, JSON.stringify({
      entries: [
        { path: "CONFIG.LOCAL.JSON" },
        { path: ".CHATGPT/operations/run.json" },
        { path: "artifacts/NESTED.DS_STORE" }
      ]
    }));

    await expect(execFileAsync(
      process.execPath,
      [scriptPath, "--manifest", manifestPath],
      { cwd: sandbox }
    )).rejects.toMatchObject({
      code: 1,
      stderr: expect.stringMatching(
        /CONFIG\.LOCAL\.JSON[\s\S]*\.CHATGPT[\s\S]*NESTED\.DS_STORE/
      )
    });
  } finally {
    await rm(sandbox, { recursive: true, force: true });
  }
});

test("public checker scans its own source and rejects an added release marker", async () => {
  const sandbox = await createTempDirectory("public-hygiene-self-scan-");
  const scriptPath = resolve(process.cwd(), "scripts/check-public.mjs");
  const fixturePath = join(sandbox, "scripts", "check-public.mjs");
  const manifestPath = join(sandbox, "source-manifest.json");
  const source = await readFile(scriptPath, "utf8");
  try {
    await mkdir(join(sandbox, "scripts"));
    await writeFile(fixturePath, source);
    await writeFile(
      manifestPath,
      JSON.stringify({ entries: [{ path: "scripts/check-public.mjs" }] })
    );

    const clean = await execFileAsync(
      process.execPath,
      [scriptPath, "--manifest", manifestPath],
      { cwd: sandbox }
    );
    expect(clean.stdout.trim()).toBe("Public hygiene check passed.");

    await writeFile(
      fixturePath,
      source + "\nconst syntheticReleaseMarker = " +
        JSON.stringify(["/Us", "ers/"].join("")) + ";\n"
    );
    await expect(execFileAsync(
      process.execPath,
      [scriptPath, "--manifest", manifestPath],
      { cwd: sandbox }
    )).rejects.toMatchObject({
      code: 1,
      stderr: expect.stringContaining(
        "scripts/check-public.mjs: blocked public-release marker found:"
      )
    });
  } finally {
    await rm(sandbox, { recursive: true, force: true });
  }
});

  test("public check rejects malformed manifests and unsupported arguments", async () => {
  const sandbox = await createTempDirectory("public-hygiene-invalid-manifest-");
    const scriptPath = resolve(process.cwd(), "scripts/check-public.mjs");
    const manifestPath = join(sandbox, "source-manifest.json");
    try {
      const invalidRequests = [
        { args: ["--manifest", "source-manifest.json"], manifest: { entries: [] }, message: "must be absolute" },
        { args: ["--manifest", manifestPath], manifest: { files: [] }, message: "entries array" },
        { args: ["--manifest", manifestPath], manifest: { entries: [{ path: "../private.md" }] }, message: "unsafe relative path" },
        { args: ["--manifest", manifestPath], manifest: { entries: [{ path: "C:/outside.md" }] }, message: "unsafe relative path" },
        { args: ["--manifest", manifestPath], manifest: { entries: [{ path: "docs/\\outside.md" }] }, message: "unsafe relative path" },
        { args: ["--manifest", manifestPath], manifest: { entries: [{ path: "docs/\u0000entry.md" }] }, message: "unsafe relative path" },
        { args: ["--manifest", manifestPath], manifest: { entries: [{ path: "README.md" }, { path: "README.md" }] }, message: "duplicate path" },
        { args: ["--unsupported"], message: "Usage:" }
      ];

      for (const request of invalidRequests) {
        if (request.manifest) {
          await writeFile(manifestPath, JSON.stringify(request.manifest));
        }
        await expect(execFileAsync(process.execPath, [scriptPath, ...request.args], { cwd: sandbox }))
          .rejects.toMatchObject({ stderr: expect.stringContaining(request.message) });
      }
    } finally {
      await rm(sandbox, { recursive: true, force: true });
    }
  });

  test("public check rejects an already tracked local config backup", async () => {
  const sandbox = await createTempDirectory("public-hygiene-");
    try {
      const scriptPath = resolve(process.cwd(), "scripts/check-public.mjs");
      await execFileAsync("git", ["init", "--quiet"], { cwd: sandbox });
      await writeFile(join(sandbox, "config.local.json.backup-before-release"), "{}\n");
      await execFileAsync("git", ["add", "--", "config.local.json.backup-before-release"], { cwd: sandbox });

      await expect(execFileAsync(process.execPath, [scriptPath], { cwd: sandbox })).rejects.toMatchObject({
        stderr: expect.stringContaining("tracked local-only/private artifact is forbidden")
      });
    } finally {
      await rm(sandbox, { recursive: true, force: true });
    }
  });
});
