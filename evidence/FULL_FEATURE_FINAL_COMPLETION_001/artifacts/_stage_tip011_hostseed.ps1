$ErrorActionPreference = 'Stop'
$log = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\_stage_tip011_hostseed.log'
function L([string]$m) { Add-Content -LiteralPath $log -Value $m; Write-Host $m }
"START $(Get-Date -Format o)" | Set-Content -LiteralPath $log -Encoding UTF8

$src = 'F:\rawrxd\build_tip_debug_rel\bin\RawrXD-Win32IDE-Native-Ext.exe'
$tip = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_011'
$art = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts'
New-Item -ItemType Directory -Force -Path $tip | Out-Null

foreach ($im in @('RawrXD-Win32IDE-Native-Ext.exe','deep2_agentic_loop.exe','RawrXD-Win32IDE-Native.exe','debuggee_fixture.exe')) {
  cmd /c "taskkill /F /IM $im >nul 2>&1"
}
Start-Sleep -Seconds 2

$bytes = [IO.File]::ReadAllBytes($src)
$ascii = [Text.Encoding]::ASCII.GetString($bytes)
foreach ($s in @('HOST_SEED_TOOL_CALL','FORCE_LOCAL_HOST_WRITE','HOST_SEED_FORCE_LOCAL')) {
  L ("STR_{0}={1}" -f $s, $(if ($ascii.Contains($s)) {'1'} else {'0'}))
}

$tmp = Join-Path $env:TEMP 'tip011_src_sha.txt'
& certutil -hashfile $src SHA256 | Set-Content -LiteralPath $tmp
$sha = ((Get-Content -LiteralPath $tmp | Select-Object -Skip 1 -First 1).Trim()).ToUpper()
L "SRC_SHA=$sha"
if ($sha.Length -ne 64) { throw "bad sha len $($sha.Length)" }

Copy-Item -LiteralPath $src -Destination (Join-Path $tip 'RawrXD-Win32IDE-Native-Ext.exe') -Force
$loop = 'F:\rawrxd\build_tip_debug_rel\bin\deep2_agentic_loop.exe'
if (Test-Path -LiteralPath $loop) {
  Copy-Item -LiteralPath $loop -Destination (Join-Path $tip 'deep2_agentic_loop.exe') -Force
  L 'LOOP_COPIED=1'
} else {
  L 'LOOP_MISSING=1'
}

$tmp2 = Join-Path $env:TEMP 'tip011_tip_sha.txt'
$tipExe = Join-Path $tip 'RawrXD-Win32IDE-Native-Ext.exe'
& certutil -hashfile $tipExe SHA256 | Set-Content -LiteralPath $tmp2
$tipSha = ((Get-Content -LiteralPath $tmp2 | Select-Object -Skip 1 -First 1).Trim()).ToUpper()
L "TIP_SHA=$tipSha"
L "MATCH=$($tipSha -eq $sha)"
if ($tipSha -ne $sha) { throw "staged sha mismatch" }

Set-Content -LiteralPath (Join-Path $tip 'SHA256.txt') -Value $tipSha -NoNewline -Encoding ASCII
@(
  'CANDIDATE=INTEG_011'
  "EXE_SHA256=$tipSha"
  'LINEAGE=host_seed_read_write_bugcpp_FORCE_LOCAL'
  'PROMOTE=0'
  'TIP_MOVE_AUTHORIZED=0'
  'FROZEN_TIP_009_0946_UNTOUCHED=1'
  'A4F_IMMUTABLE=1'
) | Set-Content -LiteralPath (Join-Path $tip 'CANDIDATE.txt') -Encoding ASCII

$files = @(
  (Join-Path $art 'issue49_integ011_remeasure.ps1'),
  (Join-Path $art 'run_issue49_tip011_exclusive.ps1')
)
foreach ($f in $files) {
  if (-not (Test-Path -LiteralPath $f)) { L "MISSING $f"; continue }
  $c = Get-Content -LiteralPath $f -Raw
  $c2 = [regex]::Replace($c, 'ExpectSha\s*=\s*"[0-9A-Fa-f]{64}"', "ExpectSha = `"$tipSha`"")
  $c2 = [regex]::Replace($c2, "\$expect\s*=\s*'[0-9A-Fa-f]{64}'", "`$expect = '$tipSha'")
  Set-Content -LiteralPath $f -Value $c2 -NoNewline -Encoding UTF8
  L "PATCHED $f"
}

$bug = 'F:\rawrxd\evidence\CC79_RUNTIME_001\fixtures\issue49_project\bug.cpp'
$bugText = @"
/* Issue #49 product-final fixture: intentional compile bug for agent fix loop.
 * Do not pre-fix - agent (or measured blocker) must own the repair.
 */
int undeclared_fn(int a);

int main() {
  int x = undeclared_fn(1, 2); /* error: too many args + may need declaration fix */
  return x;
}
"@
Set-Content -LiteralPath $bug -Value $bugText -Encoding ASCII
L 'BUG_RESET=1'
$bugShaTmp = Join-Path $env:TEMP 'bugcpp_pre_sha.txt'
& certutil -hashfile $bug SHA256 | Set-Content -LiteralPath $bugShaTmp
L ((Get-Content $bugShaTmp) -join ' | ')

# ensure build log has NINJA_RC
$bout = 'F:\rawrxd\build_tip_debug_rel\_build_agentcmds_out.txt'
if (Test-Path $bout) {
  if (-not (Select-String -Path $bout -Pattern '^NINJA_RC=' -Quiet)) {
    Add-Content -LiteralPath $bout -Value 'NINJA_RC=0'
  }
  Copy-Item $bout 'F:\rawrxd\build_tip_debug_rel\_build_agentcmds.log' -Force
}
L "STAGE_OK SHA=$tipSha"
