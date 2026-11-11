# Improved x64 minidump stack residual parse — exception ctx + RSP-relative return-address walk.
param(
  [Parameter(Mandatory)][string]$DumpPath,
  [Parameter(Mandatory)][string]$OutPath
)
$ErrorActionPreference = 'Stop'
$fs = [IO.File]::OpenRead($DumpPath)
$br = New-Object IO.BinaryReader($fs)

$null = $br.ReadUInt32(); $null = $br.ReadUInt32()
$numStreams = [int]$br.ReadUInt32(); $streamDirRva = [int64]$br.ReadUInt32()
$null = $br.ReadUInt32(); $null = $br.ReadUInt32(); $null = $br.ReadUInt64()

$streams = @{}
$fs.Position = $streamDirRva
for ($i = 0; $i -lt $numStreams; $i++) {
  $stype = [int]$br.ReadUInt32(); $dsize = [int]$br.ReadUInt32(); $drva = [int64]$br.ReadUInt32()
  if (-not $streams.ContainsKey($stype) -and $dsize -gt 0) {
    $streams[$stype] = @{ Rva = $drva; Size = $dsize }
  }
}

function Read-At([int64]$Rva, [int]$Size) {
  $script:fs.Position = $Rva
  return $script:br.ReadBytes($Size)
}

$mods = New-Object System.Collections.Generic.List[object]
if ($streams.ContainsKey(4)) {
  $fs.Position = $streams[4].Rva
  $n = [int]$br.ReadUInt32()
  for ($i = 0; $i -lt $n; $i++) {
    # MINIDUMP_MODULE = 108 bytes
    $base = $br.ReadUInt64(); $size = $br.ReadUInt32()
    $null = $br.ReadUInt32(); $null = $br.ReadUInt32(); $nameRva = [int64]$br.ReadUInt32()
    $restPos = $fs.Position
    $path = ''
    if ($nameRva -gt 0 -and $nameRva -lt $fs.Length) {
      # MINIDUMP_STRING: ULONG32 Length (bytes) + WCHAR Buffer[Length/2]
      $fs.Position = $nameRva
      $byteLen = [int]$br.ReadUInt32()
      if ($byteLen -gt 0 -and $byteLen -lt 2048 -and ($fs.Position + $byteLen) -le $fs.Length) {
        $raw = $br.ReadBytes($byteLen)
        $path = [Text.Encoding]::Unicode.GetString($raw).TrimEnd([char]0)
      }
    }
    $fs.Position = $restPos
    $null = $br.ReadBytes(84) # VersionInfo(52)+Cv(8)+Misc(8)+Reserved0/1(16)
    $leaf = $path
    $idxSlash = [Math]::Max($path.LastIndexOf([char]'\'), $path.LastIndexOf([char]'/'))
    if ($idxSlash -ge 0 -and $idxSlash -lt ($path.Length - 1)) { $leaf = $path.Substring($idxSlash + 1) }
    if ([string]::IsNullOrWhiteSpace($leaf)) { $leaf = ("mod_{0:X}" -f $base) }
    $mods.Add([pscustomobject]@{
        Base = $base; Size = [uint64]$size; Name = $leaf; Path = $path
      })
  }
}

function Resolve-Addr([uint64]$Addr) {
  foreach ($m in $script:mods) {
    if ($Addr -ge $m.Base -and $Addr -lt ($m.Base + $m.Size)) {
      return ("{0}+0x{1:X}" -f $m.Name, ($Addr - $m.Base))
    }
  }
  return ("0x{0:X}" -f $Addr)
}

$exThread = 0; $exCode = 0; $exFlags = 0; $exAddr = [uint64]0; $exInfo = @()
$ctxRip = [uint64]0; $ctxRsp = [uint64]0; $ctxRbp = [uint64]0
$ctxRcx = [uint64]0; $ctxRdx = [uint64]0; $ctxR8 = [uint64]0; $ctxR9 = [uint64]0

if ($streams.ContainsKey(6)) {
  $fs.Position = $streams[6].Rva
  $exThread = $br.ReadUInt32(); $null = $br.ReadUInt32()
  $exCode = $br.ReadUInt32(); $exFlags = $br.ReadUInt32(); $null = $br.ReadUInt64(); $exAddr = $br.ReadUInt64()
  $null = $br.ReadUInt32(); $null = $br.ReadUInt32()
  for ($j = 0; $j -lt 15; $j++) { $exInfo += $br.ReadUInt64() }
  $ctxSize = [int]$br.ReadUInt32(); $ctxRva = [int64]$br.ReadUInt32()
  if ($ctxSize -ge 0x100) {
    $ctx = Read-At $ctxRva $ctxSize
    $ctxRcx = [BitConverter]::ToUInt64($ctx, 0x80)
    $ctxRdx = [BitConverter]::ToUInt64($ctx, 0x88)
    $ctxRsp = [BitConverter]::ToUInt64($ctx, 0x98)
    $ctxRbp = [BitConverter]::ToUInt64($ctx, 0xA0)
    $ctxR8 = [BitConverter]::ToUInt64($ctx, 0xB8)
    $ctxR9 = [BitConverter]::ToUInt64($ctx, 0xC0)
    $ctxRip = [BitConverter]::ToUInt64($ctx, 0xF8)
  }
}

$threadStack = $null; $threadCount = 0
if ($streams.ContainsKey(3)) {
  $fs.Position = $streams[3].Rva
  $threadCount = [int]$br.ReadUInt32()
  for ($i = 0; $i -lt $threadCount; $i++) {
    $tid = $br.ReadUInt32()
    $null = $br.ReadUInt32(); $null = $br.ReadUInt32(); $null = $br.ReadUInt32(); $null = $br.ReadUInt64()
    $stkStart = $br.ReadUInt64(); $stkSize = $br.ReadUInt32(); $stkRva = [int64]$br.ReadUInt32()
    $null = $br.ReadUInt32(); $null = $br.ReadUInt32()
    if ($tid -eq $exThread) {
      $threadStack = [pscustomobject]@{
        Tid = $tid; StackStart = $stkStart; StackSize = $stkSize; StackRva = $stkRva
      }
    }
  }
}

$memRanges = New-Object System.Collections.Generic.List[object]
if ($streams.ContainsKey(5)) {
  $fs.Position = $streams[5].Rva
  $nr = [int]$br.ReadUInt32()
  for ($i = 0; $i -lt $nr; $i++) {
    $start = $br.ReadUInt64(); $dsz = $br.ReadUInt32(); $drva = [int64]$br.ReadUInt32()
    $memRanges.Add([pscustomobject]@{ Start = $start; Size = [uint64]$dsz; FileOff = $drva })
  }
}

function Read-VA([uint64]$Va, [int]$Len) {
  if ($null -ne $script:threadStack) {
    $end = $script:threadStack.StackStart + [uint64]$script:threadStack.StackSize
    if ($Va -ge $script:threadStack.StackStart -and ($Va + [uint64]$Len) -le $end) {
      $off = [int]($Va - $script:threadStack.StackStart)
      $blob = Read-At $script:threadStack.StackRva ([int]$script:threadStack.StackSize)
      $out = New-Object byte[] $Len
      [Array]::Copy($blob, $off, $out, 0, [Math]::Min($Len, $blob.Length - $off))
      return $out
    }
  }
  foreach ($r in $script:memRanges) {
    if ($Va -ge $r.Start -and ($Va + [uint64]$Len) -le ($r.Start + $r.Size)) {
      $off = [int64]($Va - $r.Start)
      $script:fs.Position = $r.FileOff + $off
      return $script:br.ReadBytes($Len)
    }
  }
  return $null
}

$stackFrames = New-Object System.Collections.Generic.List[object]
if ($ctxRip -ne 0) {
  $stackFrames.Add([pscustomobject]@{ Kind = 'RIP'; Addr = $ctxRip; Sym = (Resolve-Addr $ctxRip); RspOff = '' })
}

$scanNote = 'NO_STACK_BYTES'
if ($ctxRsp -ne 0) {
  $blob = Read-VA $ctxRsp 0x2000
  if ($null -eq $blob -and $null -ne $threadStack) {
    $full = Read-At $threadStack.StackRva ([int][Math]::Min($threadStack.StackSize, 0x8000))
    if ($ctxRsp -ge $threadStack.StackStart -and $ctxRsp -lt ($threadStack.StackStart + [uint64]$full.Length)) {
      $startOff = [int]($ctxRsp - $threadStack.StackStart)
      $blob = New-Object byte[] ($full.Length - $startOff)
      [Array]::Copy($full, $startOff, $blob, 0, $blob.Length)
      $scanNote = 'THREAD_STACK_SLICE'
    }
    else {
      $blob = $full
      $scanNote = 'THREAD_STACK_FULL_UNALIGNED'
    }
  }
  elseif ($null -ne $blob) {
    $scanNote = 'RSP_DIRECT'
  }
  if ($null -ne $blob) {
    for ($off = 0; $off + 8 -le $blob.Length -and $stackFrames.Count -lt 80; $off += 8) {
      $v = [BitConverter]::ToUInt64($blob, $off)
      if ($v -lt 0x10000) { continue }
      $sym = Resolve-Addr $v
      if ($sym -match '^0x') { continue }
      if ($stackFrames.Count -eq 1 -and $v -eq $ctxRip) { continue }
      $stackFrames.Add([pscustomobject]@{
          Kind = 'RET'; Addr = $v; Sym = $sym; RspOff = ('+0x{0:X}' -f $off)
        })
    }
  }
}

$want = 'RawrXD|comctl32|user32|ntdll|KERNEL32|KERNELBASE|msctf|ole32|riched|gdi32|imm32'
$lines = New-Object System.Collections.Generic.List[string]
[void]$lines.Add('CANCEL_NATIVE_STACK_RESIDUAL_PARSE')
[void]$lines.Add("Dump=$DumpPath")
[void]$lines.Add("DumpSize=$((Get-Item -LiteralPath $DumpPath).Length)")
[void]$lines.Add(("Streams={0}" -f (($streams.Keys | Sort-Object) -join ',')))
[void]$lines.Add("ThreadCount=$threadCount")
[void]$lines.Add("ExceptionThreadId=$exThread")
[void]$lines.Add(("ExceptionCode=0x{0:X8}" -f $exCode))
[void]$lines.Add(("ExceptionFlags=0x{0:X8}" -f $exFlags))
[void]$lines.Add(("ExceptionAddress=0x{0:X} ({1})" -f $exAddr, (Resolve-Addr $exAddr)))
if ($exInfo.Count -ge 2) {
  [void]$lines.Add(("ExceptionInformation[0]=0x{0:X} (0=read,1=write)" -f $exInfo[0]))
  [void]$lines.Add(("ExceptionInformation[1]=0x{0:X} (target VA)" -f $exInfo[1]))
}
[void]$lines.Add(("Context.Rip=0x{0:X} ({1})" -f $ctxRip, (Resolve-Addr $ctxRip)))
[void]$lines.Add(("Context.Rsp=0x{0:X}" -f $ctxRsp))
[void]$lines.Add(("Context.Rbp=0x{0:X}" -f $ctxRbp))
[void]$lines.Add(("Context.Rcx=0x{0:X}" -f $ctxRcx))
[void]$lines.Add(("Context.Rdx=0x{0:X}" -f $ctxRdx))
[void]$lines.Add(("Context.R8=0x{0:X}" -f $ctxR8))
[void]$lines.Add(("Context.R9=0x{0:X}" -f $ctxR9))
if ($null -ne $threadStack) {
  [void]$lines.Add(("FaultingThread.StackStart=0x{0:X} Size=0x{1:X} FileRva=0x{2:X}" -f $threadStack.StackStart, $threadStack.StackSize, $threadStack.StackRva))
  $inStack = ($ctxRsp -ge $threadStack.StackStart -and $ctxRsp -lt ($threadStack.StackStart + [uint64]$threadStack.StackSize))
  [void]$lines.Add("RspInThreadStackMemory=$inStack")
}
else {
  [void]$lines.Add('FaultingThread.Stack=NOT_FOUND_IN_THREADLIST')
}
[void]$lines.Add("MemoryListRanges=$($memRanges.Count)")
[void]$lines.Add("StackScanMode=$scanNote")
[void]$lines.Add('')
[void]$lines.Add('=== Key modules ===')
foreach ($m in ($mods | Where-Object { $_.Name -match $want } | Sort-Object Name, Base)) {
  [void]$lines.Add(("{0} base=0x{1:X} size=0x{2:X}" -f $m.Name, $m.Base, $m.Size))
}
[void]$lines.Add('')
[void]$lines.Add('=== Stack (RIP + module-mapped RET candidates from RSP) ===')
$idx = 0
foreach ($f in $stackFrames) {
  if ($f.Kind -eq 'RIP') { [void]$lines.Add(("  [{0,2}] RIP  {1}" -f $idx, $f.Sym)) }
  else { [void]$lines.Add(("  [{0,2}] RET  {1}  (rsp{2})" -f $idx, $f.Sym, $f.RspOff)) }
  $idx++
}
$prod = @($stackFrames | Where-Object { $_.Sym -match 'RawrXD' })
$com = @($stackFrames | Where-Object { $_.Sym -match 'comctl32' })
$user = @($stackFrames | Where-Object { $_.Sym -match 'user32' })
[void]$lines.Add('')
[void]$lines.Add("PRODUCT_FRAMES_IN_STACK_SCAN=$($prod.Count)")
foreach ($p in $prod) { [void]$lines.Add("  PRODUCT $($p.Sym)") }
[void]$lines.Add("COMCTL32_FRAMES=$($com.Count)")
[void]$lines.Add("USER32_FRAMES=$($user.Count)")

$text = ($lines -join "`r`n")
Set-Content -LiteralPath $OutPath -Value $text -Encoding UTF8
Write-Output $text
$br.Close(); $fs.Close()
