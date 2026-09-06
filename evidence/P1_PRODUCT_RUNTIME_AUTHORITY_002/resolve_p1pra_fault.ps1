# Resolve P1PRA_FAULT rip values against local PE image sizes (post-run, no live process).
$ErrorActionPreference = 'Stop'
$witness = Join-Path $PSScriptRoot 'WITNESS.log'
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

Write-Host '===== P1PRA_FAULT RIP RESOLVE ====='
Select-String -Path $witness -Pattern 'P1PRA_FAULT=' | Select-Object -Last 8 | ForEach-Object {
  $line = $_.Line
  Write-Host $line
  if ($line -notmatch 'rip=([0-9A-Fa-fx]+)') {
    if ($line -notmatch 'addr=([0-9A-Fa-fx]+)') { return }
    $ripRaw = $Matches[1]
  } else {
    $ripRaw = $Matches[1]
  }
  if ($ripRaw -notmatch '^0[xX]') { $ripRaw = '0x' + $ripRaw }
  $rip = [uint64]$ripRaw
  if ($rip -lt 0x10000) {
    Write-Host ("  class=unmapped_or_corrupt_low rip=0x{0:X}" -f $rip)
    return
  }
  if ($rip -lt 0x7FF000000000) {
    Write-Host ("  class=non-static-image-looking/unresolved rip=0x{0:X}" -f $rip)
    return
  }
  $page = $rip -band [uint64]0xFFFFFFFFFFFFF000
  foreach ($m in $mods) {
    if (-not $m.Size) { continue }
    for ($base = $page; $base -gt ($page - 0x2000000); $base -= 0x1000) {
      if ($rip -ge $base -and $rip -lt ($base + $m.Size)) {
        $rva = $rip - $base
        Write-Host ("  match={0} inferred_base=0x{1:X} rva=0x{2:X} size=0x{3:X}" -f $m.Name, $base, $rva, $m.Size)
        return
      }
    }
  }
  Write-Host "  class=unmapped_module_range rip=0x{0:X}" -f $rip
}
