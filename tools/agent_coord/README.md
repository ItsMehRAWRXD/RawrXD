# RawrXD Agent Development Coordination

This directory implements **agent-level development isolation** so independent
coding agents (IDE, Deep2, compression, Vulkan, validation tracks) can progress
simultaneously without overwriting one another's source, build state, or test
evidence.

## Why

Two agents editing the same file and running against the same test workspace
compromise both implementation integrity and certification evidence. The fix is
structural: **one exclusive owner per implementation package**, each working in
its own git worktree, build directory, and test workspace.

## Model

- A **package** is one backlog item in `backlog.json` (e.g. `chat-smoke`,
  `interactive-cert`, `deep2-parity`).
- **Ownership** is acquired atomically via an exclusive lock-file create
  (`FileMode.CreateNew`). Two agents racing for the same package cannot both win;
  the loser gets `CLAIM_FAILED`.
- The **lock file** (`locks/<item>.lock`) is the source of truth. `registry.json`
  mirrors ownership (owner, worktree, branch, pid, timestamps) for `status`.
- **Stale** claims (heartbeat older than `-StaleMinutes`, or owner PID gone) are
  reclaimable via `reclaim`, so a crashed agent never blocks a package forever.
- The tool **never** touches source, build output, git, or the network. It only
  arbitrates ownership.

## Usage

```powershell
# See all packages and who owns what
pwsh tools/agent_coord/coord.ps1 status

# Pick the next unclaimed (or stale) package
pwsh tools/agent_coord/coord.ps1 next

# Atomically claim a package for this agent (do this FIRST, before editing)
pwsh tools/agent_coord/coord.ps1 claim -Agent agent-ide -Item interactive-cert `
    -Worktree F:\rawrxd\.kilo\worktrees\ide -Branch feat/ide-interactive-cert -OwnerPid $PID

# Periodically prove liveness while working
pwsh tools/agent_coord/coord.ps1 heartbeat -Agent agent-ide -Item interactive-cert

# Release when done (or the package is handed off)
pwsh tools/agent_coord/coord.ps1 release -Agent agent-ide -Item interactive-cert

# If a previous owner crashed and left a stale lock
pwsh tools/agent_coord/coord.ps1 reclaim -Agent agent-ide -Item chat-smoke -OwnerPid $PID
```

## Agent protocol (per package)

1. `next` -> choose an unclaimed package.
2. Create/enter your **own** worktree + build dir + test workspace (unique
   `RAWRXD_*_RECEIPT` paths / ports / instance ids).
3. `claim` the package atomically. If `CLAIM_FAILED`, pick another.
4. Implement, build, run acceptance, capture a **commit-specific receipt**.
5. `heartbeat` while working (so others see you are alive).
6. Commit on your branch; open a reviewed PR (non-destructive integration).
7. `release` the package.

## Guarantees

- **Exclusive ownership** â€” atomic lock create; no double-claim.
- **Liveness** â€” heartbeat + PID check; stale claims are reclaimable.
- **Isolation** â€” one worktree / build dir / test workspace per package.
- **Non-destructive** â€” integration only through reviewed commits; no force-push,
  no reset, no shared mutable build state.
- **Commit-specific receipts** â€” acceptance evidence is bound to a commit, never
  to a shared workspace.