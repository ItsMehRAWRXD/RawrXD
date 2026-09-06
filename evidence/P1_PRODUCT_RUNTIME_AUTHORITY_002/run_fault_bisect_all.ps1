# Resolve all P1PRA_FAULT lines in WITNESS.log
$ErrorActionPreference = 'Stop'
$witness = Join-Path $PSScriptRoot 'WITNESS.log'
$out = Join-Path $PSScriptRoot 'reconclusion\C1_C2_FAULT_BISECT.txt'
if (-not (Test-Path $witness)) { throw "Missing $witness" }

function Get-PeSizeOfImage([string]$Path) {
  if (-not (Test-Path $Path)) { return $null }
  $b = [System.IO.File]::ReadAllBytes($Path)
  if ($b.Length -lt 0x100) { return $null }
  $e = [BitConverter]::ToInt32($b, 0x3C)
  if ($e -le 0 -or ($e + 0x54) -gt $b.Length) { return $null }
  return [BitConverter]::ToUInt32($b, $e + 0x50)
}

$mods = @(
  @{ Name = 'RawrXD-Win32IDE.exe'; Path = 'F:\~dev\rawrxd\build_p1pra_win32ide\bin\RawrXD-Win32IDE.exe' },
  @{ Name = 'ntdll.dll'; Path = "$env:SystemRoot\System32\ntdll.dll" },
  @{ Name = 'kernel32.dll'; Path = "$env:SystemRoot\System32\kernel32.dll" },
  @{ Name = 'kernelbase.dll'; Path = "$env:SystemRoot\System32\KernelBase.dll" }
)
foreach ($m in $mods) { $m.Size = Get-PeSizeOfImage $m.Path }

$stageNames = @{
  '3' = 'P1PRA_DHI_ENTERPRISE_LICENSE'
  '33' = 'P1PRA_DHI_TELEMETRY'
  '7' = 'telemetry_stage_7'
  '67' = 'utc_stage_67'
}

$lines = Select-String -Path $witness -Pattern 'P1PRA_FAULT=' | ForEach-Object { $_.Line }
$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine("P1PRA_FAULT BISECT - total=$($lines.Count) witness=$witness")
[void]$sb.AppendLine("generated=$(Get-Date -Format o)")
[void]$sb.AppendLine('')

$byStage = @{}
foreach ($line in $lines) {
  $stage = 'unknown'
  if ($line -match 'stage=(\d+)') { $stage = $Matches[1] }
  if (-not $byStage.ContainsKey($stage)) { $byStage[$stage] = 0 }
  $byStage[$stage]++
}
[void]$sb.AppendLine('## Fault count by stage id')
foreach ($k in ($byStage.Keys | Sort-Object)) {
  $label = if ($stageNames.ContainsKey($k)) { $stageNames[$k] } else { 'unknown' }
  [void]$sb.AppendLine("  stage=$k ($label): $($byStage[$k])")
}
[void]$sb.AppendLine('')
[void]$sb.AppendLine('## Sample resolutions (unique RIP, last 20 faults)')

$seenRip = @{}
foreach ($line in ($lines | Select-Object -Last 20)) {
  [void]$sb.AppendLine($line)
  if ($line -notmatch 'rip=([0-9A-Fa-fx]+)') {
    if ($line -notmatch 'addr=([0-9A-Fa-fx]+)') { continue }
    $ripRaw = $Matches[1]
  } else { $ripRaw = $Matches[1] }
  if ($ripRaw -notmatch '^0[xX]') { $ripRaw = '0x' + $ripRaw }
  $rip = [uint64]$ripRaw
  if ($seenRip.ContainsKey($rip)) { [void]$sb.AppendLine("  (dup rip)"); continue }
  $seenRip[$rip] = $true
  if ($rip -lt 0x10000) {
    [void]$sb.AppendLine('  class=unmapped_or_corrupt_low')
    continue
  }
  if ($rip -lt 0x7FF000000000) {
    [void]$sb.AppendLine("  class=non-static-image rip=0x{0:X}" -f $rip)
    continue
  }
  $page = [uint64]($rip -band 0xFFFFFFFFFFFFF000)
  $matched = $false
  foreach ($m in $mods) {
    if (-not $m.Size) { continue }
    for ($base = $page; $base -gt ($page - 0x2000000); $base -= 0x1000) {
      if ($rip -ge $base -and $rip -lt ($base + $m.Size)) {
        $rva = $rip - $base
        [void]$sb.AppendLine(('  match={0} base=0x{1:X} rva=0x{2:X}' -f $m.Name, $base, $rva))
        $matched = $true
        break
      }
    }
    if ($matched) { break }
  }
  if (-not $matched) { [void]$sb.AppendLine("  class=unmapped_module rip=0x{0:X}" -f $rip) }
}
[void]$sb.AppendLine('')
[void]$sb.AppendLine('ISOLATION: stage=3 -> deferredHeavyInit enterprise_license (Win32IDE_Core.cpp P1PRA_DHI_ENTERPRISE_LICENSE)')
[void]$sb.AppendLine('ISOLATION: stage=33/utc_stage=67 -> initTelemetry / UTC_InitTelemetry (Win32IDE_Telemetry.cpp + RawrXD_Telemetry_Kernel.asm)')
[void]$sb.AppendLine('STATUS: faults logged non-fatally via VEH; parallel to inference send path unless bridge state corrupted')

$sb.ToString() | Set-Content $out -Encoding UTF8
Write-Host "Wrote $out"
