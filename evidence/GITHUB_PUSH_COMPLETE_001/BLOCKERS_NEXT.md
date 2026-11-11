# Blockers after GitHub tip sync

`PROMOTE=0` · `REBUILD=0` · `CERTIFIED=0` · `NEW_PRODUCT_E2E=HELD`

| Priority | Gate | Status | Next |
|----------|------|--------|------|
| 1 | Native `cmd` outside Cursor | PENDING_OPERATOR | `AGENT_SHELL_CHANNEL_RECOVERY_001/NATIVE_CMD_OPERATOR_BRIEF.md` |
| 2 | Parent Agent Shell | FAIL (no Tee) | After native result: Cursor launch/stdout/lifecycle |
| 3 | ChatWindow product E2E | FAIL | Fresh same-SHA after parent shell recovered |
| 4 | GhostText | NOT_VERIFIED | Independent after ChatWindow |
| 5 | 64-token product | NOT_VERIFIED | Missing product path / independent |
| 6 | Product binary authority | NOT_VERIFIED | Candidate `CB34EF4E…` ≠ authority |
| 7 | Clean worktree | NOT_VERIFIED | Generated `.spv` + dirty KEEP_BRANCH |

Subagent shell PASS ≠ parent shell recovery. Shell recovery ≠ product certification.
