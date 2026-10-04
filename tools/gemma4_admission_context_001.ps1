# RAWRXD_GEMMA4_ADMISSION_CONTEXT_001
#
# Read-only. Produces the exact reject-site context required before any binder patch.
# A patch cannot be written from "gemma4 is rejected"; it needs the admission function,
# the architecture string's origin, the metadata fields consulted, and the fail-closed path.
#
# Output: F:\~dev\audit_tombstone_001\gemma4_admission_context.txt

$ErrorActionPreference = 'Continue'
$Rawrxd = 'F:\~dev\rawrxd'
$Out    = 'F:\~dev\audit_tombstone_001\gemma4_admission_context.txt'
$lines  = New-Object System.Collections.Generic.List[string]
function W($m) { $lines.Add($m); }

W "===== RAWRXD_GEMMA4_ADMISSION_CONTEXT_001 ====="
W "generated $(Get-Date -Format o)"
W ""

# ---- 1. where MODEL_ADMISSION_REJECTED is emitted -------------------------
W "===== 1. MODEL_ADMISSION_REJECTED emission sites ====="
$rej = @(rg -n --no-heading "MODEL_ADMISSION_REJECTED" "$Rawrxd\src" "$Rawrxd\tools" 2>&1)
if ($rej) { $rej | ForEach-Object { W "  $_" } } else { W "  (none found in src/ or tools/)" }
W ""

# ---- 2. the admission gate itself ----------------------------------------
W "===== 2. admission / architecture-gate symbols ====="
foreach ($p in @('ADMISSION_REJECTED','admission','Admission','archMismatch','unsupportedArch','unknownArch','ModelArch','Architecture')) {
    $h = @(rg -n --no-heading $p "$Rawrxd\src\deep2" --glob '*.h' --glob '*.hpp' 2>&1 | Select-Object -First 6)
    if ($h) { W "  --- $p ---"; $h | ForEach-Object { W "    $_" } }
}
W ""

# ---- 3. gemma / gemma4 anywhere ------------------------------------------
W "===== 3. gemma / gemma4 references ====="
$g = @(rg -n --no-heading -i "gemma" "$Rawrxd\src\deep2" "$Rawrxd\tools" 2>&1 | Select-Object -First 20)
if ($g) { $g | ForEach-Object { W "  $_" } } else { W "  (no gemma reference in deep2/ or tools/)" }
W ""

# ---- 4. arch string comparisons ------------------------------------------
W "===== 4. architecture string comparisons in deep2 ====="
$a = @(rg -n --no-heading '"(llama|qwen|gemma|phi|falcon|mistral|olmo|deepseek)[a-z0-9_]*"' "$Rawrxd\src\deep2" 2>&1 | Select-Object -First 40)
if ($a) { $a | ForEach-Object { W "  $_" } } else { W "  (none)" }
W ""

# ---- 5. header surface the user asked for --------------------------------
W "===== 5. header hits: Deep2Engine|ModelContext|Architecture|Admission|gemma|qwen|llama|bind|metadata ====="
$h = @(rg -n --no-heading "Deep2Engine|ModelContext|Architecture|Admission|gemma|qwen|llama|bind|metadata" "$Rawrxd\src\deep2" --glob '*.h' --glob '*.hpp' 2>&1 | Select-Object -First 120)
if ($h) { $h | ForEach-Object { W "  $_" } } else { W "  (none)" }
W ""

# ---- 6. cert phases (why the run hung at BEFORE_LOADMODEL) ---------------
W "===== 6. LAST_CERT_PHASE instrumentation in the cert ====="
$c = @(rg -n --no-heading "LAST_CERT_PHASE" "$Rawrxd\tools\deep2_streamer_cert.cpp" 2>&1 | Select-Object -First 12)
if ($c) { $c | ForEach-Object { W "  $_" } } else { W "  (not found in tools/deep2_streamer_cert.cpp)" }
W ""

# ---- 7. what model does the cert try to load? ----------------------------
W "===== 7. model path / admission call in the cert ====="
$m = @(rg -n --no-heading "loadModel|LoadModel|modelPath|--model|MODEL_PATH|RAWRXD_MODEL" "$Rawrxd\tools\deep2_streamer_cert.cpp" 2>&1 | Select-Object -First 15)
if ($m) { $m | ForEach-Object { W "  $_" } } else { W "  (none)" }
W ""

$lines | Set-Content -Path $Out -Encoding UTF8
Write-Output "WROTE=$Out  ($($lines.Count) lines)"