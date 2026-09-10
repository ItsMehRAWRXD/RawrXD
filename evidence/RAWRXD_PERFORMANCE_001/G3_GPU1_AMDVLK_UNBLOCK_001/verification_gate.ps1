# verification_gate.ps1 — run after each unblock phase (post-reboot for P1)
param(
  [Parameter(Mandatory = $true)][string]$PhaseDir,
  [int]$A0Runs = 5
)

$ErrorActionPreference = 'Continue'
$gateRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$outDir = if ([IO.Path]::IsPathRooted($PhaseDir)) { $PhaseDir } else { Join-Path $gateRoot $PhaseDir }
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$report = New-Object System.Collections.Generic.List[string]
$report.Add("GATE=G3_GPU1_AMDVLK_UNBLOCK_001")
$report.Add("PHASE_DIR=$outDir")
$report.Add("ASOF=$(Get-Date -Format o)")
$report.Add('PROMOTE=0')

function Find-VulkanInfo {
  foreach ($c in @(
      'C:\Windows\System32\vulkaninfo.exe',
      'C:\VulkanSDK\1.4.341.0\Bin\vulkaninfo.exe',
      'C:\VulkanSDK\1.4.357.0\Bin\vulkaninfo.exe'
    )) {
    if (Test-Path -LiteralPath $c) { return $c }
  }
  $cmd = Get-Command vulkaninfo.exe -ErrorAction SilentlyContinue
  if ($cmd -and $cmd.Source) { return [string]$cmd.Source }
  return $null
}

$vkOut = Join-Path $outDir 'vulkaninfo_summary.txt'
$vkErr = Join-Path $outDir 'vulkaninfo_stderr.txt'
$vinfo = Find-VulkanInfo
$report.Add("VULKANINFO_PATH=$vinfo")
$vkExit = -1
$has7800 = 0
if (-not $vinfo) {
  $report.Add('VULKANINFO_PATH=MISSING')
} else {
  $p = Start-Process -FilePath $vinfo -ArgumentList '--summary' -NoNewWindow -Wait -PassThru `
    -RedirectStandardOutput $vkOut -RedirectStandardError $vkErr
  $vkExit = [int]$p.ExitCode
  $summary = ''
  if (Test-Path -LiteralPath $vkOut) {
    $summary = [string](Get-Content -LiteralPath $vkOut -Raw -ErrorAction SilentlyContinue)
  }
  if ([regex]::IsMatch($summary, '7800')) { $has7800 = 1 }
}
$report.Add("VULKANINFO_EXIT=$vkExit")
$report.Add("VULKANINFO_LISTS_7800=$has7800")
$vkPass = ($vkExit -eq 0 -and $has7800 -eq 1)
$report.Add("VULKANINFO=$(if ($vkPass) {'PASS'} else {'FAIL'})")

$exe = 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_GPU1_AMDVLK_DIRECT_ICD_001\g3_amdvlk_direct_icd.exe'
$icd = 'C:\Windows\System32\DriverStore\FileRepository\amdvlk.inf_amd64_914ba89eaaafdf60\amdvlk64.dll'
$pass = 0
for ($i = 1; $i -le $A0Runs; $i++) {
  $one = Join-Path $outDir ("A0_7800_$i.txt")
  $err = Join-Path $outDir ("A0_7800_$i.err.txt")
  $proc = Start-Process -FilePath $exe -ArgumentList @('7800', $icd) -NoNewWindow -Wait -PassThru `
    -RedirectStandardOutput $one -RedirectStandardError $err
  $body = ''
  if (Test-Path -LiteralPath $one) {
    $body = [string](Get-Content -LiteralPath $one -Raw -ErrorAction SilentlyContinue)
  }
  $ok = [regex]::IsMatch($body, 'DIRECT_ICD_A0_RESULT=0\b') -or
        [regex]::IsMatch($body, 'DIRECT_ICD_A0=PASS\b') -or
        [regex]::IsMatch($body, 'DIRECT_ICD_A0_STR=VK_SUCCESS')
  if ($ok) { $pass++ }
  $report.Add("A0_RUN_$i=$(if ($ok) {'PASS'} else {'FAIL'}) EXIT=$($proc.ExitCode)")
}
$report.Add("SOLO_RX7800XT_A0=${pass}_OF_${A0Runs}")
$a0Pass = ($pass -eq $A0Runs)
$report.Add("SOLO_A0_GATE=$(if ($a0Pass) {'PASS'} else {'FAIL'})")

$all = ($vkPass -and $a0Pass)
$report.Add("VERIFICATION_GATE=$(if ($all) {'PASS'} else {'FAIL'})")
if ($all) {
  $report.Add('RX7800XT_POOL_STATUS=INCLUDED')
  $report.Add('INCLUSION_MODE=PENDING_PHASE_LABEL')
} else {
  $report.Add('RX7800XT_POOL_STATUS=EXCLUDED')
}

$out = Join-Path $outDir 'VERIFICATION.txt'
$report | Set-Content -LiteralPath $out -Encoding ASCII
Get-Content -LiteralPath $out
if (-not $all) { exit 1 }
exit 0
