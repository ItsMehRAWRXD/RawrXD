---
description: >-
  RawrXD passive agent coordinator and MOTD execution policy.
  Enforces per-turn acknowledgment, single-worker delegation,
  fail-closed certification, verified handoffs, and continued
  execution until real end-to-end completion. Not roleplay.
alwaysApply: true
---

# PassiveRoleNotRoleplay

## Governing purpose

This document defines execution policy, not character roleplay.

The parent is a coordinator for delegated tasks and an executor
for ordinary tasks that have not been delegated.

Delegation does not constitute completion.

## Per-turn MOTD acknowledgment

At the start of each new user turn:

MOTD_ACK=0

Before any gated engineering tool operation, the execution
controller MUST verify a successful MOTD read for this turn.

After verification:

MOTD_ACK=1

ACK must be bound to:
- session_id
- turn_id
- motd_version_or_hash

An ACK from an earlier turn is invalid.

If MOTD loading fails:
MOTD_STATUS=BLOCKED

Do not infer successful acknowledgment from model text.

This behavior must be enforced by the host tool dispatcher.
These Markdown instructions alone are not an enforcement boundary.

## Continue-ensure triggers

Exact recognized commands:

"Please continue ensuring"

"Please continue ensuring that the streamer is complete and can run agentic"

On either command:

1. Validate MOTD acknowledgment.
2. Load StreamerAgenticContinueEnsure.mdc.
3. Load MultitaskMode.mdc.
4. Recover the latest unfinished task and evidence ledger.
5. Identify the real implementation owner.
6. Check for an existing active worker for the task.
7. Reuse the existing worker when appropriate.
8. Otherwise dispatch exactly one worker.
9. Require acknowledgment with a real worker_id.
10. Persist a handoff receipt.
11. End the parent execution turn.

Never claim dispatch before the runtime confirms it.

## Execution invariants

WORKER_COUNT_MAX=1
PARENT_EXECUTES_DELEGATED_WORK=0
PROMOTE=0
TIP_CLIMB=HOLD

These defaults remain enforced unless an authorized,
evidence-backed policy change explicitly permits otherwise.

Only one active continue-ensure worker is permitted
per task. A repeated trigger must not create a duplicate.

## Worker ownership

Every delegated task MUST have:

- task_id
- parent_session_id
- worker_id
- repository
- baseline_commit
- task_scope
- allowed_paths
- allowed_tools
- expected_deliverables
- evidence_directory
- completion_criteria

A worker cannot silently expand its authority.

Delegated workers must follow the same safety,
workspace, and certification rules as the coordinator.

## Handoff protocol

The parent emits:

CONTINUE_ENSURE=DISPATCHED
BACKGROUND_WORKERS=1
PARENT_MODE=PASSIVE_COORDINATOR
PARENT_EXECUTES_DELEGATED_WORK=0
MOTD_ACK=1
TASK_ID=<actual task id>
WORKER_ID=<actual worker id>
HANDOFF_STATUS=ACKNOWLEDGED

Only emit these fields with their successful values
after the runtime confirms their corresponding events.

Otherwise emit:
CONTINUE_ENSURE=DISPATCH_BLOCKED
BACKGROUND_WORKERS=0
HANDOFF_STATUS=FAILED
BLOCKER=<actual reason>

## Completion law

HANDOFF_TO_AGENT != DONE

SOURCE_WIRED != RUNTIME_REACHED
RUNTIME_REACHED != TOKEN_SURVIVED
TOKEN_SURVIVED != PERFORMANCE_PASS

NOT_RUN != PASS
BUILD_PASS != E2E_PASS
SMOKE_PASS != PRODUCTION_PASS

Documentation, source presence, and agent messages
are not substitutes for executable evidence.

## Worker completion criteria

For delegated Deep2 engineering work, evaluate:

1. Source changes exist in the intended repository.
2. Required components are integrated.
3. The product builds.
4. Regression tests pass.
5. The actual runtime path executes.
6. Real model tokens are generated when applicable.
7. SNAP tool calls execute when applicable.
8. Tool outputs are verified.
9. Failure and cancellation paths are tested.
10. Evidence receipts identify the tested revision.

Use NOT_APPLICABLE only with an explicit reason.

If a mandatory applicable gate fails or is untested,
the task remains incomplete.

## Continue-ensure recovery

When work is:

- gapped
- incomplete
- partially implemented
- unverified
- delegated but not landed
- landed but not wired
- wired but not exercised
- exercised but not end-to-end
- end-to-end but not dispositioned

Then the designated executor MUST:

RESUME_IT
TRACE_TO_REAL_OWNER
IMPLEMENT_MISSING_PIECES
WIRE_REAL_PRODUCT_PATH
BUILD
RUN
VERIFY
CLOSE_END_TO_END

The coordinator must not duplicate delegated execution.

If the worker fails:
- Preserve the last successful checkpoint.
- Record the actual failure.
- Release or expire its worker lease.
- Keep the task OPEN.
- Resume through a subsequent authorized dispatch.

No infinite retry loop.

## Certification authority

Preserve existing evidence and gate authority.

R27=LIVE_E2E_PASS
R28=APPLY_HELD
PROMOTE=0
TIP_CLIMB=HOLD

These are baseline ledger claims, not newly verified
results. Do not rewrite or promote evidence based solely
on this MOTD.

Only reproducible evidence against the required
product path may change certification status.

## Forbidden

- Character roleplay or persona improvisation
- Claiming an unconfirmed worker dispatch
- Multiple active workers for the same continue-ensure task
- Parent execution of delegated work
- Inventing PASS, completion, or performance results
- Modifying sealed certification evidence
- Silently converting failure into fallback success
- Treating worker handoff as task completion
- Destructive cleanup outside explicitly authorized scope
- Claiming an autonomous action was performed when
  the runtime did not execute it