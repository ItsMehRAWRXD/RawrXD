#Requires -Version 5.1
$ErrorActionPreference = 'Continue'
$Out = 'F:\rawrxd\evidence\PROGRESSION_FINISH25_001\CANCEL\logs'
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$Log = Join-Path $Out 'prove_rebuild_20261108.txt'
function W($m){ $l='[{0}] {1}' -f (Get-Date -Format o),$m; Add-Content $Log $l; Write-Output $l }

$exe = 'F:\rawrxd\build_progression_finish25\bin\RawrXD-Win32IDE-Native.exe'
$h = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
$sz = (Get-Item -LiteralPath $exe).Length
W "PRE_SHA=$h SIZE=$sz"

# Dump exception + module containing fault RIP
$d = Join-Path $env:LOCALAPPDATA 'CrashDumps\RawrXD-Win32IDE-Native.exe.28836.dmp'
$d2 = Join-Path $env:LOCALAPPDATA 'CrashDumps\RawrXD-Win32IDE-Native.exe(1).28836.dmp'
function Parse-Dump($path) {
  if (-not (Test-Path -LiteralPath $path)) { W "MISSING $path"; return }
  $fs = [IO.File]::Open($path,'Open','Read')
  $br = New-Object IO.BinaryReader($fs)
  [void]$br.ReadUInt32(); [void]$br.ReadUInt32()
  $n = $br.ReadUInt32(); $dir = $br.ReadUInt32()
  $excRva = 0; $modRva = 0
  $fs.Position = $dir
  for ($i=0; $i -lt $n; $i++) {
    $t = $br.ReadUInt32(); $ds = $br.ReadUInt32(); $dr = $br.ReadUInt32()
    if ($t -eq 6) { $excRva = $dr }
    if ($t -eq 4) { $modRva = $dr }
  }
  $fs.Position = $excRva
  $tid = $br.ReadUInt32(); [void]$br.ReadUInt32()
  $code = $br.ReadUInt32(); $flags = $br.ReadUInt32()
  [void]$br.ReadUInt64(); $addr = $br.ReadUInt64()
  $np = $br.ReadUInt32(); [void]$br.ReadUInt32()
  W ("DUMP={0} CODE=0x{1:X8} ADDR=0x{2:X16} TID={3} NP={4}" -f ([IO.Path]::GetFileName($path)), $code, $addr, $tid, $np)
  for ($i=0; $i -lt [Math]::Min($np,4); $i++) {
    $p = $br.ReadUInt64(); W ("  INFO[{0}]=0x{1:X}" -f $i, $p)
  }
  # ModuleListStream: count then MINIDUMP_MODULE[count]
  # struct MINIDUMP_MODULE { ULONG64 BaseOfImage; ULONG32 SizeOfImage; ULONG32 CheckSum; ULONG32 TimeDateStamp; RVA ModuleNameRva; ... }
  if ($modRva -gt 0) {
    $fs.Position = $modRva
    $count = $br.ReadUInt32()
    $found = $false
    for ($i=0; $i -lt $count; $i++) {
      $base = $br.ReadUInt64()
      $size = $br.ReadUInt32()
      [void]$br.ReadUInt32(); [void]$br.ReadUInt32() # checksum, time
      $nameRva = $br.ReadUInt32()
      # skip VS_FIXEDFILEINFO + CvRecord + MiscRecord + Reserved0/1 = 4+8+8+8+8 = 36? 
      # Actually after ModuleNameRva: MINIDUMP_LOCATION_DESCRIPTOR VersionInfo is embedded VS_FIXEDFILEINFO (52 bytes) then CvRecord (8) MiscRecord (8) Reserved0 (8) Reserved1 (8)
      # MINIDUMP_MODULE size is typically 108 bytes on x64
      $posAfterName = $fs.Position
      # VS_FIXEDFILEINFO is 52 bytes, then 2x LOCATION_DESCRIPTOR (8 each)=16, then 2x ULONG64=16 → 84 after nameRva? 
      # Official: after ModuleNameRva comes VS_FIXEDFILEINFO VersionInfo (13 DWORDs = 52), CvRecord (RVA+Size=8), MiscRecord(8), Reserved0(8), Reserved1(8) = 84
      [void]$br.ReadBytes(84)
      if ($addr -ge $base -and $addr -lt ($base + $size)) {
        $save = $fs.Position
        $fs.Position = $nameRva
        $len = $br.ReadUInt32()
        $nb = $br.ReadBytes([int]$len)
        $name = [Text.Encoding]::Unicode.GetString($nb).TrimEnd([char]0)
        $fs.Position = $save
        W ("FAULT_MODULE={0} BASE=0x{1:X} SIZE=0x{2:X} RVA=0x{3:X}" -f $name, $base, $size, ($addr - $base))
        $found = $true
      }
    }
    if (-not $found) { W "FAULT_MODULE=UNRESOLVED count=$count" }
  }
  $br.Close(); $fs.Close()
}
Parse-Dump $d
Parse-Dump $d2

# Tip strings present in current EXE?
$bytes = [IO.File]::ReadAllBytes($exe)
$ascii = [Text.Encoding]::ASCII.GetString($bytes)
$tipHits = @()
foreach ($s in @('BATCH1_CANCEL','m_blockModelDiscoveryUi','kRawrxdCopilotUiUpdate','request_started request_id','CHAT_RUNTIME')) {
  if ($ascii.Contains($s)) { $tipHits += $s }
}
W ("EXE_TIP_STRINGS={0}" -f ($(if($tipHits.Count){$tipHits -join ','}else{'NONE'})))

# Rebuild
W 'REBUILD_START'
& powershell -NoProfile -ExecutionPolicy Bypass -File 'F:\rawrxd\evidence\PROGRESSION_FINISH25_001\rebuild_link_progression.ps1' 2>&1 | Tee-Object -FilePath (Join-Path $Out 'rebuild_stdout.txt')
W "REBUILD_EXIT=$LASTEXITCODE"
$h2 = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
$sz2 = (Get-Item -LiteralPath $exe).Length
W "POST_SHA=$h2 SIZE=$sz2"
W "SHA_CHANGED=$([int]($h -ne $h2))"
