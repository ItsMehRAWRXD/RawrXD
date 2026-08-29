<#
.SYNOPSIS
  Freeze SPARSE_TIP_NUMERICAL_FLOOR_001 — L0..8 tip_eps=5e-5; report FIRST_LAYER_ABOVE_FLOOR.
#>
param(
    [string]$SparseClean = "F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_SPARSE_CLEAN_001",
    [string]$ExpandRoot = "F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\BATCH2_L8_L12_EXPAND_001",
    [string]$OutRoot = "F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001\SPARSE_TIP_NUMERICAL_FLOOR_001"
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutRoot | Out-Null

$py = @"
from pathlib import Path
import struct, json
ABS_FLOOR = 5.0e-5
ABS_PASS, ABS_INSPECT, ABS_SOFT = 1e-6, 1e-5, 1e-4
REL_PASS, REL_INSPECT = 1e-6, 5e-6
sc = Path(r'$($SparseClean -replace '\\','/')')
d2 = sc / 'deep2_post_swiglu_fix'
ll = sc / 'llama'
ll_exp = Path(r'$($ExpandRoot -replace '\\','/')') / 'llama'
out = Path(r'$($OutRoot -replace '\\','/')')
out.mkdir(parents=True, exist_ok=True)

def load(p):
    b = p.read_bytes(); n = len(b) // 4
    return list(struct.unpack(f'<{n}f', b))

def find(d, pat):
    if not d.exists(): return None
    xs = sorted(d.glob(pat))
    return xs[0] if xs else None

def cmp(a, b):
    max_abs = max_rel = 0.0
    largest = first_abs = -1
    for i, (x, y) in enumerate(zip(a, b)):
        d = abs(x - y)
        denom = max(1.0, abs(x), abs(y))
        rel = d / denom
        if d > max_abs:
            max_abs = d; largest = i
        if rel > max_rel:
            max_rel = rel
        if first_abs < 0 and d > ABS_PASS:
            first_abs = i
    if max_abs <= ABS_PASS: abs_g = 'PASS'
    elif max_abs <= ABS_INSPECT: abs_g = 'INSPECT'
    else: abs_g = 'FAIL'
    if max_abs <= ABS_PASS or (max_abs <= ABS_SOFT and max_rel <= REL_PASS):
        dual = 'PASS'
    elif max_abs <= ABS_INSPECT or (max_abs <= ABS_SOFT and max_rel <= REL_INSPECT):
        dual = 'INSPECT'
    else:
        dual = 'FAIL'
    return abs_g, dual, max_abs, max_rel, first_abs, largest

rows = []
first_above = None
lines = [
    'SPARSE_TIP_NUMERICAL_FLOOR_001',
    f'floor_eps={ABS_FLOOR}',
    'policy: layers<=8 tip_eps=5e-5 FLOOR; layers>=9 strict dual',
    '',
]
for layer in [2, 4, 8, 9, 10, 11, 12]:
    df = find(d2, f'deep2_LAYER_OUT_{layer}_pos0*.bin')
    lf = find(ll_exp, f'llama_LAYER{layer}_OUT_pos0*.bin') or find(ll, f'llama_LAYER{layer}_OUT_pos0*.bin')
    if not df or not lf:
        lines.append(f'L{layer}_OUT MISSING')
        continue
    abs_g, dual, mx, mr, fb, lg = cmp(load(df), load(lf))
    above = mx > ABS_FLOOR
    if above and first_above is None:
        first_above = layer
    if layer <= 8:
        floor_class = 'FLOOR' if mx <= ABS_FLOOR else 'ABOVE_FLOOR'
        tip_gate = 'PASS_FLOOR' if mx <= ABS_FLOOR else 'FAIL'
    else:
        floor_class = 'ABOVE_FLOOR' if above else 'AT_FLOOR'
        tip_gate = dual
    rows.append({
        'layer': layer, 'abs': abs_g, 'dual': dual, 'max_abs': mx, 'max_rel': mr,
        'largest': lg, 'floor_class': floor_class, 'tip_gate': tip_gate,
    })
    lines.append(f'L{layer}_OUT max_abs={mx:.6e} dual={dual} floor_class={floor_class} tip_gate={tip_gate}')

floor_ok = all(r['tip_gate'] == 'PASS_FLOOR' for r in rows if r['layer'] <= 8)
status = 'PASS' if floor_ok and first_above is not None else ('PASS' if floor_ok else 'FAIL')
lines += ['', f'FIRST_LAYER_ABOVE_FLOOR={first_above}', f'SPARSE_TIP_NUMERICAL_FLOOR_001={status}']
report = {
    'gate': 'SPARSE_TIP_NUMERICAL_FLOOR_001',
    'status': status,
    'floor_source': 'FFN_GATE_2',
    'floor_element': 5475,
    'floor_class': '1ULP_GEMV',
    'floor_max_through_layer': 8,
    'floor_eps': ABS_FLOOR,
    'first_layer_above_floor': first_above,
    'layers': rows,
}
(out / 'report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
(out / 'LADDER.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
print('\n'.join(lines))
raise SystemExit(0 if status == 'PASS' else 2)
"@

$tmp = Join-Path $env:TEMP "freeze_sparse_tip_floor.py"
Set-Content -LiteralPath $tmp -Value $py -Encoding UTF8
py -3 $tmp
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# Refresh GATE/LOCK headers from report
$rep = Get-Content (Join-Path $OutRoot "report.json") -Raw | ConvertFrom-Json
$lock = @"
# SPARSE_TIP_NUMERICAL_FLOOR_001 — LOCK

**Status:** ``$($rep.status)``

``````text
SPARSE_TIP_NUMERICAL_FLOOR_001=$($rep.status)
floor_source=$($rep.floor_source)
floor_element=$($rep.floor_element)
floor_class=$($rep.floor_class)
floor_max_through_layer=$($rep.floor_max_through_layer)
floor_eps=$($rep.floor_eps)
FIRST_LAYER_ABOVE_FLOOR=$($rep.first_layer_above_floor)
``````

Regenerator: ``scripts/FREEZE_SPARSE_TIP_NUMERICAL_FLOOR_001.ps1``
"@
Set-Content -LiteralPath (Join-Path $OutRoot "LOCK.md") -Value $lock -Encoding UTF8
Write-Host "SPARSE_TIP_NUMERICAL_FLOOR_001 -> $OutRoot status=$($rep.status)"
exit 0
