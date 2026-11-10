# PACKAGING_DEPLOYMENT_GATE — stage separate RC; never overwrite A4F
$ErrorActionPreference = 'Continue'
$Root = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001'
$Stage = Join-Path $Root 'package\full_feature_rc_001'
$Receipt = Join-Path $Root 'artifacts\PACKAGING_RECEIPT.txt'
$Manifest = Join-Path $Stage 'SHA256_MANIFEST.txt'
New-Item -ItemType Directory -Force -Path $Stage, (Join-Path $Stage 'logs') | Out-Null
$stamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$lines = New-Object System.Collections.Generic.List[string]
function L([string]$s) { $lines.Add($s); Write-Host $s }

L "ASOF_UTC=$stamp"
L 'GATE=PACKAGING_DEPLOYMENT_GATE'
L 'PROMOTE=0'
L 'CERTIFIED=0'
L 'INVENT_PASS=0'
L 'NEVER_REPLACE_A4F=1'

$a4f = 'F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\RawrXD-Win32IDE-Native.exe'
$a4fSha = (Get-FileHash $a4f -Algorithm SHA256).Hash
$a4fSize = (Get-Item $a4f).Length
L "FROZEN_A4F_PATH=$a4f"
L "FROZEN_A4F_SHA256=$a4fSha"
L "FROZEN_A4F_SIZE=$a4fSize"
L "FROZEN_A4F_UNTOUCHED=$([bool]($a4fSha -eq 'A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E'))"

$srcExe = 'F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_ext_host_004\RawrXD-Win32IDE-Native.exe'
if (-not (Test-Path $srcExe)) {
  $srcExe = 'F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_ext_host_003\RawrXD-Win32IDE-Native.exe'
}
$srcSha = (Get-FileHash $srcExe -Algorithm SHA256).Hash
L "RC_SOURCE=$srcExe"
L "RC_SOURCE_SHA256=$srcSha"

$dstExe = Join-Path $Stage 'RawrXD-Win32IDE-Native.exe'
Copy-Item $srcExe $dstExe -Force
$dstSha = (Get-FileHash $dstExe -Algorithm SHA256).Hash
L "RC_STAGED=$dstExe"
L "RC_STAGED_SHA256=$dstSha"
L "RC_STAGED_SIZE=$((Get-Item $dstExe).Length)"

$inv = New-Object System.Collections.Generic.List[string]
$searchRoots = @(
  (Split-Path $srcExe -Parent),
  'F:\rawrxd\build_tip_ext_host_001\bin',
  'F:\rawrxd\build-vulkan\bin\Release',
  'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts'
)
foreach ($r in $searchRoots) {
  if (-not (Test-Path $r)) { continue }
  Get-ChildItem $r -File -ErrorAction SilentlyContinue | ForEach-Object {
    if ($_.Extension -match '\.(dll|vsix|json|gguf)$' -or $_.Name -match 'quickjs|vulkan|Vulkan|ggml') {
      $h = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
      $inv.Add("$($_.FullName)|$($_.Length)|$h")
    }
  }
}

$parent = Split-Path $srcExe -Parent
Get-ChildItem $parent -File -ErrorAction SilentlyContinue | Where-Object {
  $_.Extension -in '.dll', '.json', '.vsix', '.md', '.txt' -or $_.Name -match 'README|SHA|config'
} | ForEach-Object {
  Copy-Item $_.FullName (Join-Path $Stage $_.Name) -Force
  $h = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
  $inv.Add("STAGED:$($_.Name)|$($_.Length)|$h")
}

$model = 'F:\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf'
$modelCfg = Join-Path $Stage 'MODEL_CONFIG.txt'
@(
  "MODEL_PATH=$model",
  "MODEL_SHA256=$((Get-FileHash $model -Algorithm SHA256).Hash)",
  "MODEL_SIZE=$((Get-Item $model).Length)",
  'QUANT=Q4_K_M',
  'CONTEXT=not_forced',
  'COPY_GGUF_INTO_RC=0'
) | Set-Content $modelCfg -Encoding UTF8

$vkNote = Join-Path $Stage 'VULKAN_RUNTIME.txt'
@(
  'VULKAN_INSTANCE=1.4.341',
  'GPU0=AMD Radeon AI PRO R9700',
  'GPU4=AMD Radeon RX 7800 XT',
  'DRIVER=32.0.31041.1004 / 26.8.1 LLPC',
  'ROCM_REPLACEMENT=0'
) | Set-Content $vkNote -Encoding UTF8

$manLines = New-Object System.Collections.Generic.List[string]
$manLines.Add("ASOF_UTC=$stamp")
$manLines.Add("STAGE=$Stage")
$manLines.Add("FROZEN_A4F_SHA256=$a4fSha")
$manLines.Add("RC_EXE_SHA256=$dstSha")
Get-ChildItem $Stage -Recurse -File | ForEach-Object {
  $rel = $_.FullName.Substring($Stage.Length).TrimStart('\')
  $h = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
  $manLines.Add("$h  $rel  $($_.Length)")
}
$manLines -join "`n" | Set-Content $Manifest -Encoding UTF8
L "MANIFEST=$Manifest"
L "MANIFEST_ENTRIES=$($manLines.Count)"
L "INVENTORY_HITS=$($inv.Count)"
$inv -join "`n" | Set-Content (Join-Path $Stage 'INVENTORY.txt') -Encoding UTF8

$ud = Join-Path $Stage 'clean_install_userdata'
if (Test-Path $ud) { Remove-Item $ud -Recurse -Force -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Force -Path $ud | Out-Null
$clog = Join-Path $Stage 'logs\clean_install_launch.log'
$p = Start-Process -FilePath $dstExe -ArgumentList @("--user-data-dir=$ud") -PassThru -WindowStyle Minimized -RedirectStandardOutput $clog -RedirectStandardError "$clog.err"
Start-Sleep -Seconds 4
$alive = ($p -and -not $p.HasExited)
if ($p) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep -Milliseconds 600
Get-Process -Name 'RawrXD-Win32IDE-Native' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
$CLEAN_INSTALL = if ($alive) { 'PASS' } else { 'FAIL' }
L "CLEAN_INSTALL_LAUNCH=$CLEAN_INSTALL"

$a4fAfter = (Get-FileHash $a4f -Algorithm SHA256).Hash
L "A4F_AFTER_SHA256=$a4fAfter"
L "A4F_MATCH_AFTER=$([bool]($a4fAfter -eq $a4fSha))"

$rollback = Join-Path $Stage 'ROLLBACK_NOTES.txt'
@(
  'ROLLBACK=delete package\full_feature_rc_001; A4F overwrite FORBIDDEN',
  "FROZEN_A4F=$a4f",
  "FROZEN_SHA=$a4fSha",
  "RC_SHA=$dstSha",
  'PROMOTE=0'
) | Set-Content $rollback -Encoding UTF8

$FULL_MANIFEST = if (Test-Path $Manifest) { 'PASS' } else { 'FAIL' }
$STAGE_OK = if (($dstSha -eq $srcSha) -and ($a4fAfter -eq 'A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E')) { 'PASS' } else { 'FAIL' }
L "FULL_FEATURE_PACKAGE_MANIFEST=$FULL_MANIFEST"
L "STAGE_SEPARATE_RC=$STAGE_OK"

$OVERALL = if ($STAGE_OK -eq 'PASS' -and $CLEAN_INSTALL -eq 'PASS' -and $FULL_MANIFEST -eq 'PASS') { 'PASS' } else { 'PARTIAL' }
L "PACKAGING=$OVERALL"
L 'INSTALLER=NOT_RUN'
L 'NOT_RUN_NE_PASS=1'
$lines -join "`n" | Set-Content -Path $Receipt -Encoding UTF8
Write-Host "RECEIPT=$Receipt"
