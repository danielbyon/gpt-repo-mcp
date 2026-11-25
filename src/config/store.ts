import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { atomicWriteJson, isNotFoundError } from "../runtime/fs-helpers.js";
import { RepoReaderConfigSchema, type RepoReaderConfig } from "./schema.js";

/** Preserves GPT_REPO_CONFIG precedence, including when its value is empty. */
export function selectServerConfigPath(env: NodeJS.ProcessEnv): string | undefined {
  return env.GPT_REPO_CONFIG ?? env.REPO_READER_CONFIG;
}

export function resolveConfigPath(options: {
  cliConfigPath?: string;
  env: NodeJS.ProcessEnv;
  cwd: string;
}): string {
  return resolveConfigPathSelection(options).path;
}

export type ConfigPathSelection = Readonly<{
  path: string;
  selected_value: string;
  selected_by: "cli" | "GPT_REPO_CONFIG" | "REPO_READER_CONFIG" | "default";
}>;

export function resolveConfigPathSelection(options: {
  cliConfigPath?: string;
  env: NodeJS.ProcessEnv;
  cwd: string;
}): ConfigPathSelection {
  if (options.cliConfigPath !== undefined) {
    return { path: resolve(options.cwd, options.cliConfigPath), selected_value: options.cliConfigPath, selected_by: "cli" };
  }
  if (options.env.GPT_REPO_CONFIG !== undefined) {
    return {
      path: resolve(options.cwd, options.env.GPT_REPO_CONFIG),
      selected_value: options.env.GPT_REPO_CONFIG,
      selected_by: "GPT_REPO_CONFIG"
    };
  }
  if (options.env.REPO_READER_CONFIG !== undefined) {
    return {
      path: resolve(options.cwd, options.env.REPO_READER_CONFIG),
      selected_value: options.env.REPO_READER_CONFIG,
      selected_by: "REPO_READER_CONFIG"
    };
  }
  const selectedValue = "./config.local.json";
  return { path: resolve(options.cwd, selectedValue), selected_value: selectedValue, selected_by: "default" };
}

export async function loadConfig(configPath: string): Promise<RepoReaderConfig> {
  try {
    const raw = await readFile(configPath, "utf8");
    return RepoReaderConfigSchema.parse(JSON.parse(raw));
  } catch (error) {
    if (isNotFoundError(error)) {
      return RepoReaderConfigSchema.parse({});
    }
    throw error;
  }
}

export async function readConfigDocument(configPath: string): Promise<unknown> {
  const raw = await readFile(configPath, "utf8");
  return JSON.parse(raw);
}

export async function writeConfigAtomic(configPath: string, config: RepoReaderConfig): Promise<void> {
  await atomicWriteJson(configPath, config);
}
