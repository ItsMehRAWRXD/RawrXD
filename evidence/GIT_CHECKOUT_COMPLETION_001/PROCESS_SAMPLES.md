# GIT_CHECKOUT_COMPLETION_001 — process samples

Read-only monitoring only. No process was terminated or suspended.

| Sample | PID | PPID | Command | CPU | Working set | State |
|---|---:|---:|---|---:|---:|---|
| T0 01:38:36 | 9272 | 20432 | `git reset --hard --no-recurse-submodules` | — | — | already exited |
| T0 01:38:36 | 14112 | 6628 | `git reset --hard --no-recurse-submodules` | 84.484s | 908,861,440 | active |
| T60 01:39:40 | 14112 | 6628 | same | 100.594s | 931,348,480 | active |
| T60 01:39:46 | 14112 | 6628 | same | 104.375s | 969,416,704 | active |
| T120 01:40:54 | 14112 | 6628 | same | unknown | unknown | exited |

Exit codes: `EXIT_CODE=UNKNOWN`; process disappearance was not treated as success without post-completion verification.

