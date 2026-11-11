# -*- coding: utf-8 -*-
from pathlib import Path

p = Path(r"F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\EDITOR\t10_verified_restore_freeze.ps1")
text = p.read_text(encoding="utf-8")

# Cut before any NEXT_ACTION footer variant
cut_markers = [
    "# Update NEXT_ACTION without touching T08 reconcile",
    "# NEXT_ACTION updated by post-seal step",
]
idx = -1
for m in cut_markers:
    i = text.find(m)
    if i >= 0:
        idx = i if idx < 0 else min(idx, i)
if idx < 0:
    raise SystemExit("cut marker missing")

# Prefer cutting after both BOARD_RETURN writes if present before footer
board_write = "Set-Content -LiteralPath (Join-Path $PostDir 'T10_BOARD_RETURN.md') -Value $board -Encoding UTF8"
bidx = text.rfind(board_write)
if bidx >= 0 and bidx < idx:
    head = text[: bidx + len(board_write)].rstrip() + "\r\n\r\n"
else:
    head = text[:idx]

footer = r'''# NEXT_ACTION updated by post-seal step (avoid here-string parse hazards).
$nextLines = New-Object System.Collections.Generic.List[string]
[void]$nextLines.Add('# NEXT_ACTION - T08 sealed; T10 dispositioned')
[void]$nextLines.Add('')
[void]$nextLines.Add(('ASOF_UTC=' + $asof))
[void]$nextLines.Add('')
[void]$nextLines.Add('T08_DUMP=RESIDUAL_PARSED')
[void]$nextLines.Add('T08_EXCEPTION=NONE')
[void]$nextLines.Add('T08_CAUSALITY=UNPROVEN')
[void]$nextLines.Add('T08_RESTRESS=8/8_SURVIVED')
[void]$nextLines.Add('T08_TIP_FIX=0')
[void]$nextLines.Add('T08_EVIDENCE=SEALED')
[void]$nextLines.Add('T08_RECONCILE=T08_TERMINATE_DUMP_RECONCILED.md')
[void]$nextLines.Add('T08_FILE_IMMUTABLE=1')
[void]$nextLines.Add('')
[void]$nextLines.Add('NEXT_GATE=T10_VERIFIED_RESTORE_ON_FREEZE')
[void]$nextLines.Add(('T10_STATUS=' + $T10))
[void]$nextLines.Add('T10_TARGET_SHA=9C91059940A49C970586FF18FC92B1B7BA422AF09E8D579B1C8606387E74A9C8')
[void]$nextLines.Add(('T10_TIP_FIX=' + $TIP_FIX))
[void]$nextLines.Add('T10_REPAIR_ON_TIP_ONLY=1')
[void]$nextLines.Add('T10_FREEZE_IMMUTABLE=1')
[void]$nextLines.Add('T10_SEAL=T10_VERIFIED_RESTORE_SEAL.md')
[void]$nextLines.Add('')
[void]$nextLines.Add('PROMOTE=0')
[void]$nextLines.Add('CERTIFIED=0')
[void]$nextLines.Add('PRODUCT_PASS=0')
[void]$nextLines.Add('FINISH_25_PASS=19')
[void]$nextLines.Add('NO_CROSS_SHA_PASS_INHERITANCE=1')
[void]$nextLines.Add('')
[void]$nextLines.Add('## T10 acceptance')
[void]$nextLines.Add(('A1_SHA_VERIFIED=' + $A1_SHA_VERIFIED))
[void]$nextLines.Add(('A2_SCENARIO_TRIGGERED=' + $A2_SCENARIO_TRIGGERED))
[void]$nextLines.Add(('A3_CLEAN_TERMINATION=' + $A3_CLEAN_TERMINATION))
[void]$nextLines.Add(('A4_RESTORE_OK=' + $A4_RESTORE_OK))
[void]$nextLines.Add(('A5_EVIDENCE_CAPTURED=' + $A5_EVIDENCE_CAPTURED))
[void]$nextLines.Add(('RESULT=' + $T10))
[void]$nextLines.Add('')
[void]$nextLines.Add('## Isolation')
[void]$nextLines.Add('Do not modify T08_TERMINATE_DUMP_RECONCILED.md.')
[void]$nextLines.Add('Any T10 repair lands on a separate tip, never the frozen executable.')
Set-Content -LiteralPath (Join-Path $PostDir 'NEXT_ACTION.md') -Value ($nextLines -join [Environment]::NewLine) -Encoding UTF8

Write-Host ('FINAL T10=' + $T10 + ' SHA=' + $script:actualSha + ' TIP_FIX=' + $TIP_FIX + ' PROMOTE=0')
if ($T10 -eq 'PASS') { exit 0 } else { exit 1 }
'''

p.write_text(head + footer, encoding="utf-8", newline="\r\n")
print("patched", p, "bytes", p.stat().st_size)
print("head_ends", repr(head[-80:]))
