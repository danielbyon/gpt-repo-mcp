import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, test } from "vitest";
import { DelegationInteractionStore } from "../src/delegation/interaction-store.js";
import { runPaths } from "../src/delegation/run-store.js";
import { AgentReplyService } from "../src/services/agent-reply-service.js";
import { PathSandbox } from "../src/services/path-sandbox.js";
import { createTempDir } from "./fixtures/temp-dir.js";

describe("AgentReplyService", () => {
  test("writes a reply bound to the current question and returns the run detail", async () => {
    const { root, service, input } = await seedReplyableAgentRun();
    const { repo_id, run_id, turn_index, expected_question_sha256, answers } = input;
    const writtenPath = `.chatgpt/codex-runs/${run_id}/interactions/turn-0001.reply.json`;

    const result = await service.write(input);

    expect(result).toMatchObject({
      ok: true,
      repo_id,
      run_id,
      turn_index,
      written_path: writtenPath,
      agent_run: {
        ok: true,
        repo_id,
        mode: "detail",
        run: { run_id, effective_status: "awaiting_input" }
      },
      next_tool_payloads: { repo_agent_runs: { repo_id, run_id } },
      warnings: []
    });
    const artifact = JSON.parse(await readFile(join(root, writtenPath), "utf8"));
    expect(artifact).toMatchObject({
      schema_version: 1,
      repo_id,
      run_id,
      turn_index,
      question_sha256: expected_question_sha256,
      answers
    });
  });

  test("rejects a reply for a prior turn without writing it", async () => {
    const { service, input, interactions } = await seedReplyableAgentRun(2);
    const { repo_id, run_id } = input;
    const priorTurn = 1;
    const priorQuestion = await interactions.writeQuestion({
      repo_id,
      run_id,
      turn_index: priorTurn,
      questions: [{ question_id: "q-confirm", prompt: "Confirm the previous question." }]
    });

    await expect(service.write({
      ...input,
      turn_index: priorTurn,
      expected_question_sha256: priorQuestion.sha256
    })).rejects.toMatchObject({ code: "RUNNER_REPLY_STALE" });
    await expect(interactions.readReply(repo_id, run_id, priorTurn)).resolves.toBeUndefined();
    await expect(interactions.readReply(repo_id, run_id, input.turn_index)).resolves.toBeUndefined();
  });

  test.each([
    ["a stale question hash", { expected_question_sha256: "0".repeat(64) }],
    ["a mismatched answer ID", { answers: [{ question_id: "q-other", answer: "Confirmed." }] }]
  ])("rejects %s without writing a reply", async (_case, override) => {
    const { service, input, interactions } = await seedReplyableAgentRun();

    await expect(service.write({ ...input, ...override })).rejects.toMatchObject({
      code: "RUNNER_REPLY_STALE"
    });
    await expect(interactions.readReply(input.repo_id, input.run_id, input.turn_index)).resolves.toBeUndefined();
  });
});

async function seedReplyableAgentRun(turnIndex = 1) {
  const root = await createTempDir("agent-reply-");
  const repoId = "fixture";
  const runId = "2026-11-01T120000Z-reply-fixture";
  const createdAt = "2026-11-01T12:00:00.000Z";
  const paths = runPaths(runId);
  await mkdir(join(root, paths.run_dir), { recursive: true });
  await writeFile(join(root, paths.prompt_path), "# Reply fixture\n");
  await writeFile(join(root, paths.manifest_path), `${JSON.stringify({
    schema_version: 1,
    repo_id: repoId,
    run_id: runId,
    title: "Reply fixture",
    prompt_path: paths.prompt_path,
    result_path: paths.legacy_result_path,
    result_json_path: paths.result_json_path,
    created_at: createdAt,
    runner: { mode: "manual" }
  })}\n`);
  await writeFile(join(root, paths.status_path), `${JSON.stringify({
    schema_version: 1,
    repo_id: repoId,
    run_id: runId,
    runner: "codex_sdk",
    status: "awaiting_input",
    revision: 1,
    started_at: createdAt,
    updated_at: createdAt,
    completed_at: null,
    prompt_path: paths.prompt_path,
    result_path: paths.legacy_result_path,
    result_found: false,
    head_before: null,
    head_after: null,
    worktree_fingerprint_before: null,
    worktree_fingerprint_after: null,
    changed_paths: [],
    validation: { status: "missing", profile: null, artifact_path: null },
    commit: { attempted: false, allowed: false, status: "skipped", commit_sha: null },
    warnings: []
  })}\n`);

  const interactions = new DelegationInteractionStore(root);
  await interactions.writeSession({
    repo_id: repoId,
    run_id: runId,
    provider: "codex_sdk",
    thread_id: "fixture-thread",
    turn_index: turnIndex,
    last_consumed_reply_turn_index: null,
    created_at: createdAt
  });
  const question = await interactions.writeQuestion({
    repo_id: repoId,
    run_id: runId,
    turn_index: turnIndex,
    questions: [{ question_id: "q-confirm", prompt: "Confirm fixture." }],
    created_at: createdAt
  });

  return {
    root,
    interactions,
    service: new AgentReplyService(root, new PathSandbox(root)),
    input: {
      repo_id: repoId,
      run_id: runId,
      turn_index: turnIndex,
      expected_question_sha256: question.sha256,
      answers: [{ question_id: "q-confirm", answer: "Confirmed." }]
    }
  };
}
