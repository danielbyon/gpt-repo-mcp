import { spawnSync } from "node:child_process";
import { mkdir, rm } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

if (process.platform === "win32") {
  const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const outputDirectory = join(repositoryRoot, "dist");
  const testBuild = process.argv.includes("--test");
  const architecture = process.arch;
  const architectureDefine = {
    x64: "/DGPT_REPO_CONFIGURATION_ADMIN_EXPECT_X64=1",
    arm64: "/DGPT_REPO_CONFIGURATION_ADMIN_EXPECT_ARM64=1",
    ia32: "/DGPT_REPO_CONFIGURATION_ADMIN_EXPECT_X86=1"
  }[architecture];
  if (!architectureDefine) {
    throw new Error(`Windows administrative host does not support Node architecture ${architecture}.`);
  }
  const suffix = testBuild ? ".test" : "";
  const outputPath = join(outputDirectory, `windows-configuration-admin-host${suffix}.exe`);
  const objectPath = join(outputDirectory, `windows-configuration-admin-host${suffix}.obj`);
  const sourcePath = join(repositoryRoot, "native", "windows", "configuration-admin-host.cpp");
  const args = [
    "/nologo",
    "/std:c++17",
    "/EHsc",
    "/W4",
    "/WX",
    "/O2",
    "/MT",
    "/DUNICODE",
    "/D_UNICODE",
    "/DWIN32_LEAN_AND_MEAN",
    "/D_WIN32_WINNT=0x0A00",
    architectureDefine,
    ...(testBuild ? ["/DGPT_REPO_CONFIGURATION_ADMIN_TESTING=1"] : []),
    `/Fo${objectPath}`,
    `/Fe${outputPath}`,
    sourcePath,
    "/link",
    "Kernel32.lib",
    "Advapi32.lib"
  ];

  await mkdir(outputDirectory, { recursive: true });
  await Promise.all([rm(outputPath, { force: true }), rm(objectPath, { force: true })]);
  const result = spawnSync("cl.exe", args, {
    cwd: repositoryRoot,
    stdio: "inherit",
    windowsHide: true
  });
  if (result.error || result.status !== 0) {
    const reason = result.error?.message ?? `compiler exited with status ${result.status}`;
    throw new Error(
      `Could not build the Windows administrative host (${reason}). ` +
      `Run from a Visual Studio C++ developer shell for Node architecture ${architecture}.`
    );
  }
}
