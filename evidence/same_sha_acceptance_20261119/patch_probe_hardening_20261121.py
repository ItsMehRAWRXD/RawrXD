#!/usr/bin/env python3
"""Sprint 5: harden defective GUI probes.

Defect: SendMessageTimeoutW's RETURN VALUE is a success flag; the message
result is in the OUT param. These probes used the return value as the result
(CB_GETCOUNT / CB_GETCURSEL / CB_GETLBTEXTLEN), producing false readings such
as gui5's CB_COUNT=1 CB_CURSEL=1.

Fix pattern: perform the call, then read the OUT param. Transport success and
message result stay separate; signed results (CB_ERR=-1) are preserved because
the out param carries the raw signed value.

Fail-closed: each old string must appear exactly once in its file.
"""
import sys

BASE = r"F:\rawrxd\evidence\same_sha_acceptance_20261119"

PATCHES = [
    ("gui_chat3.ps1",
     "function TO([IntPtr]$h,[uint32]$m) { $r=[IntPtr]::Zero; return [G.Api]::SendTO($h,$m,[IntPtr]::Zero,[IntPtr]::Zero,$flags,4000,[ref]$r) }",
     "function TO([IntPtr]$h,[uint32]$m) { $r=[IntPtr]::Zero; [void][G.Api]::SendTO($h,$m,[IntPtr]::Zero,[IntPtr]::Zero,$flags,4000,[ref]$r); return $r }"),
    ("gui_chat2.ps1",
     "$count = [W.Api]::SendTO($modelCombo, 0x0146, [IntPtr]::Zero, [IntPtr]::Zero, $flags, $MsgTimeoutMs, [ref]$res)",
     "[void][W.Api]::SendTO($modelCombo, 0x0146, [IntPtr]::Zero, [IntPtr]::Zero, $flags, $MsgTimeoutMs, [ref]$res); $count = $res.ToInt64()"),
    ("gui_model_selector_probe.ps1",
     "    $n = [MP.Api]::SendTO($h, 0x0150, [IntPtr]$index, [IntPtr]::Zero, 0x12, 4000, [ref]$r0)  # CB_GETLBTEXTLEN",
     "    [void][MP.Api]::SendTO($h, 0x0150, [IntPtr]$index, [IntPtr]::Zero, 0x12, 4000, [ref]$r0); $n = $r0  # CB_GETLBTEXTLEN result via out-param"),
    ("gui_repro2.ps1",
     "    $n = [R2.Api]::SendTO($h, 0x0150 + 0x10, [IntPtr]$index, [IntPtr]::Zero, 0x12, 4000, [ref]$r0)  # CB_GETLBTEXTLEN 0x0150",
     "    [void][R2.Api]::SendTO($h, 0x0150, [IntPtr]$index, [IntPtr]::Zero, 0x12, 4000, [ref]$r0); $n = $r0.ToInt64()  # CB_GETLBTEXTLEN"),
    ("gui_repro2.ps1",
     "    $o = [R2.Api]::SendTOGetText($h, 0x0148 + 0x0200, [IntPtr]$index, $sb, 0x12, 4000, [ref]$r0)  # CB_GETLBTEXT 0x0148",
     "    $o = [R2.Api]::SendTOGetText($h, 0x0148, [IntPtr]$index, $sb, 0x12, 4000, [ref]$r0)  # CB_GETLBTEXT 0x0148"),
]

# group by file
from collections import defaultdict
by_file = defaultdict(list)
for fname, old, new in PATCHES:
    by_file[fname].append((old, new))

ok = True
for fname, reps in by_file.items():
    p = BASE + "\\" + fname
    with open(p, "rb") as fh:
        text = fh.read().decode("utf-8")
    for old, _ in reps:
        c = text.count(old)
        if c != 1:
            print(f"[anchor] {fname}: count={c} for: {old[:70]}")
            ok = False
    if not ok:
        continue

if not ok:
    print("ABORT: one or more anchors not unique; no write")
    sys.exit(2)

for fname, reps in by_file.items():
    p = BASE + "\\" + fname
    with open(p, "rb") as fh:
        text = fh.read().decode("utf-8")
    for old, new in reps:
        text = text.replace(old, new, 1)
    with open(p, "wb") as fh:
        fh.write(text.encode("utf-8"))
    print(f"patched {fname} ({len(reps)} replacement(s))")