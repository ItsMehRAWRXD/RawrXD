# GIT_CHECKOUT_STALL_ROOT_001 — process tree

Read-only samples on 2026-11-02. No process was terminated or suspended.

| Role | PID | PPID | Command | Start | State |
|---|---:|---:|---|---|---|
| Existing worktree add wrapper | 21892 | 15148 | `git ... worktree add -b ext-host-candidate-20261102 ...` | 01:28:47 | responding |
| Existing worktree add child | 20432 | 21892 | same worktree add | 01:28:48 | responding |
| Existing checkout reset | 9272 | 20432 | `git reset --hard --no-recurse-submodules` | 01:28:48 | responding |
| New worktree add wrapper | 4100 | 21752 | `git ... worktree add --detach ...-clean 273924f…` | 01:32:06 | responding |
| New worktree add child | 6628 | 4100 | same worktree add | 01:32:06 | responding |
| New checkout reset | 14112 | 6628 | `git reset --hard --no-recurse-submodules` | 01:32:06 | responding |
| Primary fsmonitor | 22332 | 4644 | `git fsmonitor--daemon run --detach --ipc-threads=8` | 01:24:38 | responding |
| Existing-candidate fsmonitor | 22632 | 7200 | `git fsmonitor--daemon run --detach --ipc-threads=8` | 01:28:48 | responding |
| New-candidate fsmonitor | 1992 | 21764 | `git fsmonitor--daemon run --detach --ipc-threads=8` | 01:32:06 | responding |

The two checkout reset processes are the relevant workers. The fsmonitor processes are background Git services, not evidence of a failed source checkout by themselves.

