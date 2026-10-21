import { mkdir, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, test } from "vitest";
import {
  ADOPTION_CONTROL_ROOT,
  MAX_ADOPTION_ID_LENGTH,
  adoptionArtifactPath,
  assertAdoptionId,
  isAdoptionControlArtifact
} from "../src/policies/adoption-artifacts.js";
import { IgnoreEngine } from "../src/services/ignore-engine.js";
import { PathSandbox } from "../src/services/path-sandbox.js";
import { createTempDir } from "./fixtures/temp-dir.js";

describe("adoption control artifacts", () => {
  test("recognizes the normalized adoption namespace and rejects lookalike siblings", () => {
    expect(isAdoptionControlArtifact(ADOPTION_CONTROL_ROOT)).toBe(true);
    expect(isAdoptionControlArtifact("./.CHATGPT/Adoptions/adoption-1/candidate.json")).toBe(true);
    expect(isAdoptionControlArtifact(".chatgpt\\adoptions\\adoption-1\\candidate.json")).toBe(true);
    expect(isAdoptionControlArtifact("/.chatgpt/adoptions/adoption-1/candidate.json")).toBe(true);
    expect(isAdoptionControlArtifact(".chatgpt/adoptions-other/candidate.json")).toBe(false);
    expect(isAdoptionControlArtifact(".chatgpt/control/adoptions/candidate.json")).toBe(false);
    expect(isAdoptionControlArtifact("docs/adoptions/candidate.json")).toBe(false);
  });

  test("validates identifiers and artifact names before constructing paths", () => {
    expect(adoptionArtifactPath("adoption-1", "candidate.json"))
      .toBe(".chatgpt/adoptions/adoption-1/candidate.json");

    for (const invalidId of ["", "-adoption", "adoption_1", "Adoption-1", "adoption/1",
      "a".repeat(MAX_ADOPTION_ID_LENGTH + 1)]) {
      expect(() => assertAdoptionId(invalidId)).toThrow("ADOPTION_ID_INVALID");
    }

    for (const invalidName of ["", "../candidate.json", "Candidate.json", "candidate/child.json",
      "candidate name.json", "candidate..json", "a".repeat(81)]) {
      expect(() => adoptionArtifactPath("adoption-1", invalidName))
        .toThrow("ADOPTION_ARTIFACT_NAME_INVALID");
    }

    expect(() => adoptionArtifactPath("adoption/1", "candidate.json"))
      .toThrow("ADOPTION_ID_INVALID");
  });

  test("classifies adoption artifacts as internal and permits neighboring paths", () => {
    const engine = new IgnoreEngine();

    expect(engine.isInternalArtifact(".chatgpt/adoptions/adoption-1/candidate.json")).toBe(true);
    expect(engine.isInternalArtifact(".CHATGPT\\ADOPTIONS\\adoption-1\\candidate.json")).toBe(true);
    expect(engine.isSensitiveCandidate(".chatgpt/adoptions/adoption-1/candidate.json")).toBe(true);
    expect(engine.isInternalArtifact(".chatgpt/adoptions-other/candidate.json")).toBe(false);
    expect(engine.isInternalArtifact("src/adoption/adoption-service.ts")).toBe(false);
    expect(engine.isSensitiveCandidate("src/adoption/adoption-service.ts")).toBe(false);
  });

  test("blocks direct and normalized adoption paths while allowing neighboring files", async () => {
    const root = await createTempDir("adoption-artifacts-");
    await mkdir(join(root, ".chatgpt", "adoptions", "adoption-1"), { recursive: true });
    await writeFile(join(root, ".chatgpt", "adoptions", "adoption-1", "candidate.json"), "{}\n");
    await mkdir(join(root, ".chatgpt", "adoptions-other"), { recursive: true });
    await writeFile(join(root, ".chatgpt", "adoptions-other", "candidate.json"), "{}\n");
    const sandbox = new PathSandbox(root);

    await expect(sandbox.resolve(".chatgpt/adoptions/adoption-1/candidate.json"))
      .rejects.toMatchObject({ code: "INTERNAL_ARTIFACT_BLOCKED" });
    await expect(sandbox.resolve(".CHATGPT\\ADOPTIONS\\adoption-1\\candidate.json"))
      .rejects.toMatchObject({ code: "INTERNAL_ARTIFACT_BLOCKED" });
    await expect(sandbox.resolve("./.chatgpt/./adoptions/adoption-1/./candidate.json"))
      .rejects.toMatchObject({ code: "INTERNAL_ARTIFACT_BLOCKED" });
    await expect(sandbox.resolve(".chatgpt/adoptions-other/candidate.json"))
      .resolves.toMatchObject({ repoPath: ".chatgpt/adoptions-other/candidate.json" });
  });

  test("blocks symlink aliases to the adoption namespace and resolves neighboring symlinks", async () => {
    const root = await createTempDir("adoption-symlinks-");
    await mkdir(join(root, ".chatgpt", "adoptions", "adoption-1"), { recursive: true });
    await writeFile(join(root, ".chatgpt", "adoptions", "adoption-1", "candidate.json"), "{}\n");
    await writeFile(join(root, "public.txt"), "public\n");
    await symlink(join(root, ".chatgpt", "adoptions"), join(root, "adoptions-alias"));
    await symlink(
      join(root, ".chatgpt", "adoptions", "adoption-1", "candidate.json"),
      join(root, "candidate-alias.json")
    );
    await symlink(join(root, "public.txt"), join(root, "public-alias.txt"));
    const sandbox = new PathSandbox(root);

    await expect(sandbox.resolve("adoptions-alias/adoption-1/candidate.json"))
      .rejects.toMatchObject({ code: "INTERNAL_ARTIFACT_BLOCKED" });
    await expect(sandbox.resolve("candidate-alias.json"))
      .rejects.toMatchObject({ code: "INTERNAL_ARTIFACT_BLOCKED" });
    await expect(sandbox.resolve("public-alias.txt"))
      .resolves.toMatchObject({ repoPath: "public-alias.txt" });
  });
});
