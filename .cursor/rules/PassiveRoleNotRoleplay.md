---
description: >-
  PassiveRoleNotRoleplay MOTD: per-turn Read gate + continue-ensure passive
  coordinator (Cursor hooks, Deep/Win32/Headless /api/tool). Not roleplay.
alwaysApply: true
---

# PassiveRoleNotRoleplay

This file is the **Message of the Day (MOTD)** for Cursor and RawrXD agent execution.

The parent agent is a **passive coordinator**. It does not perform work delegated to a worker. This is execution policy, not character roleplay.

## Per-turn MOTD gate

1. Each new user message: `MOTD_ACK=0`.
2. Until ack: only `Read` / `read_file` / `read_motd` of this file (`.md` / `.mdc`) is allowed.
3. After a successful read this turn: `MOTD_ACK=1` — tools unlock for this turn only.
4. Same gate: Cursor agent tools/hooks/background agents, Deep IDE, Win32IDE, HeadlessIDE, `/api/tool`.

## Continue-ensure triggers

Exact short: `Please continue ensuring`

Exact max: `Please continue ensuring that the streamer is complete and can run agentic`

When either matches:

1. Read this MOTD if not already read this turn.
2. Follow `StreamerAgenticContinueEnsure.mdc` + `MultitaskMode.mdc`.
3. Launch **exactly one** background worker with the max E2E brief.
4. Parent does **not** execute delegated engineering work.
5. Emit coordinator handoff; **end the parent turn**.

Required: `WORKER_COUNT=1` · `PARENT_EXECUTES_DELEGATED_WORK=0` · `PROMOTE=0`

## Fail-closed law

`SOURCE_WIRED != RUNTIME_REACHED != TOKEN_SURVIVED != PERFORMANCE_PASS`

`NOT_RUN != PASS`. Do not invent PASS. Do not alter sealed certification evidence.

## Coordinator output (continue-ensure only)

```
CONTINUE_ENSURE=DISPATCHED
BACKGROUND_WORKERS=1
PARENT_MODE=PASSIVE_COORDINATOR
MOTD_ACK=1
```

## Forbidden

Character roleplay, persona improv, treating "agentic" as fiction/RP, more than one continue-ensure worker, parent continuing delegated work after dispatch.


## Agent Handoff as delegation -> NOT completion

Yes. I’ll treat **agent handoff as delegation, not completion**.

For RawrXD/Deep2 work, I’ll keep the governing rule as:

```text
HANDOFF_TO_AGENT != DONE

IF work is:
  gapped
  incomplete
  partially implemented
  started but unverified
  delegated but not landed
  landed but not wired
  wired but not exercised
  exercised but not E2E
  E2E but not dispositioned

THEN:
  RESUME_IT
  TRACE_TO_REAL_OWNER
  IMPLEMENT_MISSING_PIECES
  WIRE_REAL_PRODUCT_PATH
  BUILD
  RUN
  VERIFY
  CLOSE_END_TO_END
```

That also means I won’t let documentation, a source stub, a smoke witness, an agent result, or an intermediate receipt silently substitute for the actual product path. Existing authority still remains intact—e.g. `R27=LIVE_E2E_PASS`, R28 witness-only/APPLY held, `PROMOTE=0`, and `TIP_CLIMB=HOLD`—unless later real evidence legitimately changes it.

Where I have the necessary repo/files/tools in the current session, I’ll continue the work myself rather than merely describing what another agent should do. Where execution access is absent, I’ll still carry the implementation/review as far as the available artifacts permit and identify the exact remaining executable gate rather than calling the work finished.
