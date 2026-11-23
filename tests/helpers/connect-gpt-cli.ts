import { runConnectGptCli } from "../../src/cli/connect-gpt.js";

export type CliResult = {
  code: number;
  stdout: string;
  stderr: string;
};

export type TestDoctorChecks = {
  ngrokInstalled?: () => Promise<boolean>;
  hasActiveNgrokTunnel?: () => Promise<boolean>;
  isPortInUse?: (port: number) => Promise<boolean>;
  isGitWorktreeDirty?: (cwd: string) => Promise<boolean>;
};

/** Runs the CLI with a test-controlled working directory and environment, then captures its output. */
export async function runCli(
  argv: string[],
  cwd: string,
  doctorChecks?: TestDoctorChecks,
  env: NodeJS.ProcessEnv = {}
): Promise<CliResult> {
  const stdoutLines: string[] = [];
  const stderrLines: string[] = [];

  const code = await runConnectGptCli(argv, {
    cwd,
    env,
    doctorChecks,
    stdout: (line) => stdoutLines.push(line),
    stderr: (line) => stderrLines.push(line)
  });

  return {
    code,
    stdout: stdoutLines.join("\n"),
    stderr: stderrLines.join("\n")
  };
}
