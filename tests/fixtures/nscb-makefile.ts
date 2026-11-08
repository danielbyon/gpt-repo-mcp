import { copyFile, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";

export const NSCB_MAKEFILE_SHA256 = "8eded0c720bc790118b1b793ba5b26c065616f046afa80c41e1c856f977d778e";
export const NSCB_RUST_TOOLCHAIN_SHA256 = "c910997cb152c6dc8ed13b1fdf9fa28a4ed30d6776123e27dd6170e5c66067a0";

const NSCB_FIXTURE_FILES = [
  "Makefile",
  "rust-toolchain.toml",
  "scripts/check_content_policy.py",
  "scripts/clean.py",
  "tests/test_content_policy.py",
  "tests/test_content_policy_git.py",
  "tests/test_cleanup.py",
  "tests/test_cleanup_git.py"
] as const;

export async function copyNscbMakefileFixture(root: string): Promise<void> {
  const fixtureRoot = join(process.cwd(), "tests", "fixtures", "nscb-makefile");
  for (const path of NSCB_FIXTURE_FILES) {
    const destination = join(root, path);
    await mkdir(dirname(destination), { recursive: true });
    await copyFile(join(fixtureRoot, path), destination);
  }
}
