# Atomic N2 CMakeLists patcher: revert to HEAD, port MASM obj population from dec168513,
# insert runtime_symbol_bridge TU. Deterministic, verifiable.
$ErrorActionPreference = "Stop"
Set-Location "F:\~dev\rawrxd"

# 1. Restore CMakeLists from the pre-mangle commit 964eed96f (clean, 0 AUTO-REMOVED)
git show "964eed96f:rawrxd/CMakeLists.txt" | Out-File "F:\~dev\rawrxd\CMakeLists.txt" -Encoding UTF8
$c = Get-Content "F:\~dev\rawrxd\CMakeLists.txt"
$autoCount = @($c | Select-String -SimpleMatch 'AUTO-REMOVED').Count
Write-Host "BASE_AUTO_COUNT=$autoCount TOTAL=$($c.Count)"
if ($autoCount -ne 0) { Write-Host "FATAL: base commit has AUTO-REMOVED"; exit 1 }

# 2. MASM population splice (lines 3891..4077 in 1-based = 3890..4076 in 0-idx)
$dec = Get-Content "F:\~dev\_n2_dec_populate.txt"
if ($dec.Count -lt 710) { Write-Host "FATAL: populate section missing"; exit 1 }
$decCore = $dec[3..($dec.Count-3)]   # drop 3 prebuilt-dir lines + 2 trailing (Collect/MASM_OBJECTS)

$anchorIdx = ($c | Select-String -SimpleMatch "# Collect all MASM objects").LineNumber
$firstEmpty = ($c | Select-String -SimpleMatch 'set(ASM_REQUANTIZE_OBJ ""').LineNumber
Write-Host "FIRST_EMPTY=$firstEmpty ANCHOR=$anchorIdx"
if (-not $firstEmpty -or -not $anchorIdx) { Write-Host "FATAL: anchors missing"; exit 1 }

$before = $c[0..($firstEmpty-2)]          # up to line before set(ASM_REQUANTIZE_OBJ "")
$after  = $c[($anchorIdx-1)..($c.Count-1)] # from "# Collect all MASM objects" onward
$new = $before + $decCore + $after

# 3. Insert runtime_symbol_bridge before add_executable(RawrXD-Win32IDE
$idx = ($new | Select-String -SimpleMatch "add_executable(RawrXD-Win32IDE").LineNumber
if (-not $idx) { Write-Host "FATAL: IDE target not found"; exit 1 }
$insert = @(
"    # BATCH N2 (RAWRXD_WIN32IDE_REAL_LINK_001): real C implementations for ASM-linked symbols.",
"    # runtime_symbol_bridge.cpp contains real function bodies (camellia/kquant/native_speed/",
"    # sgemm/FlashAttention/Enterprise/Swarm/DiskRecovery + Dbg_CaptureContext/Read/WriteMemory).",
"    # The checked-in .asm kernels are 26-byte scaffolds that assemble to empty .obj,",
"    # so the C symbols have NO other provider. Taxonomy: REAL_IMPLEMENTATION_EXISTS.",
"    list(APPEND WIN32IDE_SOURCES src/core/runtime_symbol_bridge.cpp)",
"    # Self-host engine ASM symbols: real C bodies (asm_selfhost_*).",
"    list(APPEND WIN32IDE_SOURCES src/core/inference_link_production.cpp)",
"    # Hotpatch/snapshot/GGUF-stats bridge: real bodies (asm_hotpatch_*, asm_snapshot_*).",
"    list(APPEND WIN32IDE_SOURCES src/core/win32ide_asm_kernel_bridge.cpp)",
"    # KQuant dequant + Quant_DequantQ4_0/Q8_0 real C++ bodies.",
"    list(APPEND WIN32IDE_SOURCES src/core/kquant_nonmsvc.cpp)"
)
$before2 = $new[0..($idx-2)]
$after2 = $new[($idx-1)..($new.Count-1)]
$new = $before2 + $insert + $after2

$new | Set-Content "F:\~dev\rawrxd\CMakeLists.txt" -Encoding UTF8

# 4. Verify balance + counts
$depth = 0
foreach ($l in $new) {
  if ($l -match "^\s*(if|foreach|while|function|macro)\s*\(") { $depth++ }
  if ($l -match "^\s*(endif|endforeach|endwhile|endfunction|endmacro)\s*\(") { $depth-- }
}
$autoAfter = @($new | Select-String -SimpleMatch 'AUTO-REMOVED').Count
$emptyObjs = ([regex]::Matches(($new -join "`n"), 'set\((ASM_[A-Z0-9_]+_OBJ) ""\)')).Count
$bridge = @($new | Select-String -SimpleMatch 'runtime_symbol_bridge.cpp').Count
Write-Host "BALANCE=$depth AUTO=$autoAfter EMPTY_OBJS=$emptyObjs BRIDGE_REFS=$bridge TOTAL=$($new.Count)"
if ($depth -ne 0 -or $emptyObjs -gt 2) { Write-Host "FATAL: post-patch verify failed"; exit 1 }
Write-Host "PATCH_OK"