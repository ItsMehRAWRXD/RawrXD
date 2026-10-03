<#
RAWRXD_PHANTOM_COHORT_TRIAGE_001 -- post-batch link-input equivalence check.

The 18-file batch removed 36 bare CMake lines (18 append entries + 18 REMOVE_ITEM
entries). This measures whether that changed what `rawr-server` is linked from.

A relink happened, so the binary hash necessarily changed: MSVC stamps a fresh PE
TimeDateStamp on every link. The raw hash is therefore NOT the equivalence authority.
The link INPUT SET is.

Method:
  1. capture ninja's link/compile command set for target rawr-server   (repaired state)
  2. swap in CMakeLists.PRE_BATCH.txt, reconfigure, capture again      (pre-batch state)
  3. restore the batch state, reconfigure
  4. diff the two input sets, and restore-verify both mutated files
#>

$ErrorActionPreference = 'Stop'
$Rawrxd = 'F:\~dev\rawrxd'
$Cml    = Join-Path $Rawrxd 'CMakeLists.txt'
$Build  = 'F:\~dev\build_rawr_ninja'
$Val    = 'F:\~dev\build_tombstone_val'
$Log    = 'F:\~dev\audit_tombstone_001'
$Vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
$PreBatch = Join-Path $Log 'CMakeLists.PRE_BATCH.txt'

function Say($m) { Write-Information $m -InformationAction Continue }

function Invoke-Msvc([string]$inner, [string]$tag) {
    $out = Join-Path $Log "$tag.out.txt"
    $cmd = "call `"$Vcvars`" >nul 2>&1 && $inner"
    $p = Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', $cmd `
         -RedirectStandardOutput $out -RedirectStandardError (Join-Path $Log "$tag.err.txt") `
         -NoNewWindow -PassThru -Wait
    return $p.ExitCode
}

function Get-Inputs {
    # Delete first, then run, then read. A pre-run existence guard would fire before
    # the command has had any chance to create the file.
    $out = Join-Path $Log 'cmds.out.txt'
    Remove-Item $out -Force -ErrorAction SilentlyContinue
    $null = Invoke-Msvc "ninja -C `"$Build`" -t commands rawr-server", 'cmds'
    if (-not (Test-Path $out)) { throw "ninja -t commands produced no output at $out" }
    $txt = Get-Content $out -Raw
    if ($txt -match 'ninja: error' -or $txt -match 'ninja: unknown') { throw "ninja -t failed: $($txt.Trim())" }
    return [pscustomobject]@{
        Objs = @([regex]::Matches($txt,'[^\s"]*\.obj') | ForEach-Object { $_.Value } | Sort-Object -Unique)
        Srcs = @([regex]::Matches($txt,'[^\s"]*\.cpp') | ForEach-Object { $_.Value } | Sort-Object -Unique)
        Raw  = $txt
    }
}

$batchCmlHash = (Get-FileHash $Cml -Algorithm SHA256).Hash
# Save the POST-batch file BEFORE swapping, so the restore puts the tree back
# where it actually is rather than into the pre-batch state.
$PostBatch = Join-Path $Log 'CMakeLists.POST_BATCH.txt'
Copy-Item $Cml $PostBatch -Force

Say "BATCH_CMAKE_SHA256=$batchCmlHash"
Say "PRE_BATCH_CMAKE_SHA256=$((Get-FileHash $PreBatch -Algorithm SHA256).Hash)"
Say "A_B_INPUTS_DISTINCT=$(if ((Get-FileHash $PreBatch -Algorithm SHA256).Hash -ne $batchCmlHash) { 1 } else { 0 })"
Say ''

Say '--- capture BATCH state inputs ---'
$rc = Invoke-Msvc "cmake -S `"$Rawrxd`" -B `"$Val`" -G Ninja -DCMAKE_BUILD_TYPE=Release", 'cfg_batch'
if ($rc -ne 0) { Say "ABORT: batch-state configure failed ($rc)"; exit 2 }
$batch = Get-Inputs
Say "BATCH_OBJ_COUNT=$($batch.Objs.Count)  BATCH_SRC_COUNT=$($batch.Srcs.Count)"

Say ''
Say '--- capture PRE-BATCH state inputs ---'
Copy-Item $PreBatch $Cml -Force
$rc2 = Invoke-Msvc "cmake -S `"$Rawrxd`" -B `"$Val`" -G Ninja -DCMAKE_BUILD_TYPE=Release", 'cfg_pre'
if ($rc2 -ne 0) { Say "ABORT: pre-batch configure failed ($rc2)"; exit 2 }
$pre = Get-Inputs
Say "PREBATCH_OBJ_COUNT=$($pre.Objs.Count)  PREBATCH_SRC_COUNT=$($pre.Srcs.Count)"

# --- always restore ------------------------------------------------------
Say ''
Say '--- restoring POST-batch state ---'
Copy-Item $PostBatch $Cml -Force
$restored = (Get-FileHash $Cml -Algorithm SHA256).Hash
Say "RESTORE_VERIFIED=$(if ($restored -eq $batchCmlHash) { 1 } else { 0 })  sha=$($restored)"
if ($restored -ne $batchCmlHash) {
    Say '  MANUAL RESTORE REQUIRED from CMakeLists.POST_BATCH.txt'
    exit 9
}

Say ''
Say '--- diff ---'
$oPre  = @(Compare-Object $pre.Objs  $batch.Objs  | Where-Object SideIndicator -eq '<=')
$oPost = @(Compare-Object $pre.Objs  $batch.Objs  | Where-Object SideIndicator -eq '=>')
$sPre  = @(Compare-Object $pre.Srcs  $batch.Srcs  | Where-Object SideIndicator -eq '<=')
$sPost = @(Compare-Object $pre.Srcs  $batch.Srcs  | Where-Object SideIndicator -eq '=>')
foreach ($o in $oPre)  { Say "  PRE_BATCH_ONLY : $($o.InputObject)" }
foreach ($o in $oPost) { Say "  BATCH_ONLY     : $($o.InputObject)" }
Say "OBJ_DIFF_PRE_BATCH_ONLY=$($oPre.Count)"
Say "OBJ_DIFF_BATCH_ONLY=$($oPost.Count)"
Say "SRC_DIFF_PRE_BATCH_ONLY=$($sPre.Count)"
Say "SRC_DIFF_BATCH_ONLY=$($sPost.Count)"

$equal = ($oPre.Count -eq 0 -and $oPost.Count -eq 0 -and $sPre.Count -eq 0 -and $sPost.Count -eq 0)
Say "LINK_INPUT_SET_EQUAL_AFTER_BATCH=$(if ($equal) { 1 } else { 0 })"
Say 'BATCH_INTERPRETATION=NO_BUILD_GRAPH_IMPACT'