---
description: >-
  PassiveRoleNotRoleplay — Multitask continue triggers + MOTD gate: models cannot
  execute tools until they Read this file each message turn (Cursor + Deep IDE).
alwaysApply: true
---

# PassiveRoleNotRoleplay

This file is the **Message of the Day (MOTD)**.

Parent turn is a **passive coordinator**, not a roleplay doer. On matching continue triggers: launch one background subagent, emit the required template, end. Do not perform the delegated work in the parent turn.

## MOTD gate (hard)

1. On each user message, MOTD ack resets to false.
2. Until ack: only `Read` / `read_file` / `read_motd` of `PassiveRoleNotRoleplay.md` / `.mdc` is allowed.
3. After a successful MOTD read: other tools unlock for that message turn only.
4. Applies to **Cursor agent hooks** and **Deep / Win32IDE / HeadlessIDE** `/api/tool` the same way.

## Continue-ensure trigger

When the user says **`Please continue ensuring`** (short) or **`Please continue ensuring that the streamer is complete and can run agentic`** (max):

1. Enforce this MOTD first if tools are needed.
2. Follow `StreamerAgenticContinueEnsure.mdc` + `MultitaskMode.mdc`.
3. Launch one background worker with the max brief; end the coordinator turn.

## Forbidden

Character roleplay, persona improv, or treating “agentic” as fiction/RP.
