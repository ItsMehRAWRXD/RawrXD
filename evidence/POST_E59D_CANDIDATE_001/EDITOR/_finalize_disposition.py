# -*- coding: utf-8 -*-
from pathlib import Path
import re

asof = "2026-11-03T13:58:46Z"
root = Path(r"F:\rawrxd\evidence\POST_E59D_CANDIDATE_001")

(root / "NEXT_ACTION.md").write_text(
    f"""# NEXT_ACTION - Independent certification (Cancel classification sealed)

ASOF_UTC={asof}

```
CANCEL_CLASSIFICATION=SEALED
STALE_GHOSTTEXT=PASS
EDITOR_GHOSTTEXT_ACCEPT=PASS
GHOSTTEXT_REOPEN=0
CRASH_SIGNATURE=PROVEN
CRASH_ROOT_CAUSE=NOT_PROVEN
PRODUCT_DEFECT=NOT_PROVEN
CAUSAL_CLOSURE=DEFERRED
BATCH1_CANCEL_RECOVERY=OPEN
REBUILD=HELD
PROMOTE=0
CERTIFIED=0
NEXT_ACTION=BATCH1_CANCEL_RECOVERY_REMAINS_OPEN
REOPEN_CANCEL=ONLY_IF_REQUIRED_BY_CERTIFICATION
NEXT_GATE=BATCH1_CANCEL_RECOVERY_DEFERRED
```

## Seal law

- Cancel classification remains SEALED under CANCEL\\CLASSIFY_HARNESS_VS_PRODUCT_STACK_CALLSITE.md.
- Preserve CERT EXE SHA 3B720981..., dumps 070906/073409, stack parses, harness config.
- No Cancel reopen / rebuild / promote.

## Independent gates

1. Stale-GhostText - PASS (EDITOR\\STALE_GHOSTTEXT_RECEIPT.md).
2. BATCH1_CANCEL_RECOVERY - OPEN/deferred; do not invent PASS.
3. Further independent non-Cancel gates - NONE_FOUND.

NOT_RUN != PASS. PROMOTE=0.
""",
    encoding="utf-8",
)

disp = root / "DISPOSITION.md"
d = disp.read_text(encoding="utf-8")
d = re.sub(r"ASOF_UTC=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", f"ASOF_UTC={asof}", d, count=1)
d = d.replace(
    "NEXT_GATE=BATCH1_CANCEL_RECOVERY_OR_NONE_INDEPENDENT",
    "NEXT_GATE=BATCH1_CANCEL_RECOVERY_DEFERRED",
)
d = d.replace(
    "NEXT_GATE=STALE_GHOSTTEXT_SAME_SHA",
    "NEXT_GATE=BATCH1_CANCEL_RECOVERY_DEFERRED",
)
d = d.replace(
    "NEXT_ACTION=CONTINUE_INDEPENDENT_CERTIFICATION_GATES",
    "NEXT_ACTION=BATCH1_CANCEL_RECOVERY_REMAINS_OPEN",
)
if "STALE_GHOSTTEXT=PASS" not in d:
    d = d.replace(
        "EDITOR_GHOSTTEXT_ACCEPT=PASS",
        "EDITOR_GHOSTTEXT_ACCEPT=PASS\nSTALE_GHOSTTEXT=PASS",
    )
d = re.sub(
    r"Independent next: Stale-GhostText[^\n]*",
    "Independent Stale-GhostText PASS on SHA 3B720981.... Cancel remains SEALED. BATCH1_CANCEL_RECOVERY stays OPEN/deferred.",
    d,
)
if "| Stale-GhostText | **PASS** |" not in d and "| Stale-GhostText |" in d:
    d = re.sub(
        r"\| Stale-GhostText \|[^\n]*\|",
        "| Stale-GhostText | **PASS** | EDITOR\\STALE_GHOSTTEXT_RECEIPT.md; A eligible=0 not RENDERED; B RENDERED |",
        d,
    )
disp.write_text(d, encoding="utf-8")
print("FINALIZED")
for line in d.splitlines():
    if "Stale-GhostText" in line or line.startswith(
        ("STALE_GHOSTTEXT", "NEXT_GATE", "BATCH1", "NEXT_ACTION=")
    ):
        print(line)
