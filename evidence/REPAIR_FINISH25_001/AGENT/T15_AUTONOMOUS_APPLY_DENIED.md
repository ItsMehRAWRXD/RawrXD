# T15 - Autonomous apply DENIED (permission resolver) -> workspace-scoped APPLY PASS

ASOF_UTC=2026-11-08T23:48:14Z
PROMOTE=0
CERTIFIED=0
INVENT_PASS=0
PRODUCT_DEFECT_T15=NOT_PROVEN
FINISH_25_PASS=19
T24_INSTALLER=NOT_RUN

## Sealed interpretation (user + source + rebuilt CLI)

```
T15_EDIT_CONTENT=CONTRACT_ARGS_OK_WHEN_COMPLETE
T15_TIMEOUT=PASS
T15_AUTONOMOUS_APPLY=DENIED_IMPROVED
T15_APPROVE_FLAG_APPLY=PASS
T15_GUI_ENV_ALIAS=PASS
ROOT_LAYER=MUTATION_APPROVAL_NOT_MODE_AUTHORITY
PATH_OUTSIDE_WORKSPACE=CLEARED_BY_--workspace_AFTER_tools
CANONICAL_ENV=RAWRXD_TOOLS_APPROVE_MUTATIONS=YES
GUI_ENV_ALIAS=RAWRXD_GUI_APPROVE_MUTATIONS=YES
CANONICAL_FLAG=--approve-mutations
CLI=F:\rawrxd\build_repair_candidate\bin-msvc\rawr.exe
CLI_SHA=4F815E1D0B44BD1CC233316BC03FD88958E07517E785DDD95B4C77AB6B641164
FILE_SHA=146E968B36E17AA998CEB5D5BB9CBCC5DA9C0964DD78FC0A5AD745575D3FA488
DISK_MARKER=T15_EDITED_T15ARG_da5080bd
```

## Trial table (post-rebuild, workspace-scoped)

| Trial | Result | Class |
|-------|--------|-------|
| `tools run editFiles --mode autonomous` (no approve) | DENIED exit 3 | Mode Full; approval callback false; ExplainDenial now appends `mutation approval missing (--approve-mutations or RAWRXD_TOOLS_APPROVE_MUTATIONS=YES)` |
| `tools run editFiles --workspace <fixture> --mode autonomous --approve-mutations` | PASS exit 0 | Disk has exact marker + `T15_EDITED_…` replacement |
| `RAWRXD_GUI_APPROVE_MUTATIONS=YES` (no flag) | PASS exit 0 | Alias honored on NEW CLI |
| `rawr --workspace … tools …` (flag before command) | Unknown command | Global flags must follow `tools` (ParseOptions start_index=2) |

## Resolver fact (source)

`PermissionGate::AllowsWithApproval` (`AgentMode.cpp`): Controlled/Full **still** requires `approver(tool,req)`.
`ApproveMutation` (`rawrxd_cli_v2.cpp`): returns false unless `RAWRXD_TOOLS_APPROVE_MUTATIONS=YES`, `RAWRXD_GUI_APPROVE_MUTATIONS=YES`, or `--approve-mutations`.
`ExplainDenial` now surfaces the approval layer (tip patch retained).

Autonomous mode does **not** auto-waive mutation approval (boundary preserved).

## Workspace note

`--workspace`/`--root` are discovered via `ParseOptions` after the top-level command token.
Required shape: `rawr tools run editFiles --workspace <dir> …`
Fixture workspace must contain `.cursor/rules/PassiveRoleNotRoleplay.md(.mdc)` (CLI auto-reads MOTD for direct tools).

## T24

`T24_INSTALLER=NOT_RUN` / `GAP` remains — no installer PASS.

## Next

T15 apply gate closed under workspace + approve. FINISH_25 stays 19. Parallel T08/T07 Unicode tip fix remains separate. PROMOTE=0.
