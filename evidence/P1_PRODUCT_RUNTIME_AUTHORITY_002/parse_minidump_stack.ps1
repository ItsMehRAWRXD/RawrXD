# Minimal x64 minidump parser — exception RIP/RSP + stack walk vs module list.
param(
    [Parameter(Mandatory)][string]$DumpPath,
    [string]$OutPath
)

$ErrorActionPreference = 'Stop'
$fs = [IO.File]::OpenRead($DumpPath)
$br = New-Object IO.BinaryReader($fs)

function Read-U32 { param([IO.BinaryReader]$B) [uint32]$B.ReadUInt32() }
function Read-U64 { param([IO.BinaryReader]$B) [uint64]$B.ReadUInt64() }

$fs.Position = 0
$sig = Read-U32 $br
if ($sig -ne 0x504D444D) { throw "Not MINIDUMP: sig=$sig" }
[void](Read-U32 $br) # Version
$numStreams = Read-U32 $br
$streamDirRva = Read-U32 $br
[void](Read-U32 $br) # CheckSum
[void](Read-U32 $br) # TimeDateStamp
[void](Read-U64 $br) # Flags

$streams = @{}
$fs.Position = $streamDirRva
for ($i = 0; $i -lt $numStreams; $i++) {
    $stype = Read-U32 $br
    $dsize = Read-U32 $br
    $drva = Read-U32 $br
    $streams[$stype] = @{ Rva = $drva; Size = $dsize }
}

function Read-At([uint32]$Rva, [uint32]$Size) {
    $fs.Position = $Rva
    return $br.ReadBytes([int]$Size)
}

# ModuleList stream = 4
$mods = @()
if ($streams.ContainsKey(4)) {
    $fs.Position = $streams[4].Rva
    $n = Read-U32 $br
    for ($i = 0; $i -lt $n; $i++) {
        $base = Read-U64 $br
        $size = Read-U32 $br
        [void](Read-U32 $br) # checksum
        $ts = Read-U32 $br
        $nameRva = Read-U32 $br
        $vs0 = Read-U32 $br; $vs1 = Read-U32 $br
        [void](Read-U64 $br) # CvRecord
        [void](Read-U64 $br) # MiscRecord
        $rs0 = Read-U64 $br; $rs1 = Read-U64 $br
        $pos = $fs.Position
        $fs.Position = $nameRva
        $nameChars = New-Object System.Collections.Generic.List[byte]
        while ($true) {
            $ch = $br.ReadUInt16()
            if ($ch -eq 0) { break }
            $nameChars.Add([byte]($ch -band 0xFF))
            $nameChars.Add([byte](($ch -shr 8) -band 0xFF))
        }
        $name = [Text.Encoding]::Unicode.GetString($nameChars.ToArray())
        $fs.Position = $pos
        $leaf = Split-Path $name -Leaf
        $mods += [pscustomobject]@{ Base = $base; Size = $size; Name = $leaf; Path = $name }
    }
}

function Resolve-Addr([uint64]$Addr) {
    foreach ($m in $mods) {
        if ($Addr -ge $m.Base -and $Addr -lt ($m.Base + $m.Size)) {
            $rva = $Addr - $m.Base
            return "{0}+0x{1:X}" -f $m.Name, $rva
        }
    }
    return ("0x{0:X}" -f $Addr)
}

$exThread = $null
$exCode = $null
$exAddr = $null
$ctxRip = $null
$ctxRsp = $null
$ctxRcx = $null
$ctxRdx = $null

if ($streams.ContainsKey(6)) {
    $fs.Position = $streams[6].Rva
    $exThread = Read-U32 $br
    [void](Read-U32 $br)
    $exCode = Read-U32 $br
    [void](Read-U32 $br) # flags
    [void](Read-U64 $br) # record
    $exAddr = Read-U64 $br
    [void](Read-U32 $br) # nparams
    for ($j = 0; $j -lt 15; $j++) { [void](Read-U64 $br) }
    $ctxSize = Read-U32 $br
    $ctxRva = Read-U32 $br
    if ($ctxSize -ge 0xF8 + 8) {
        $ctx = Read-At $ctxRva $ctxSize
        $ctxRip = [BitConverter]::ToUInt64($ctx, 0xF8)
        $ctxRsp = [BitConverter]::ToUInt64($ctx, 0x98)
        $ctxRcx = [BitConverter]::ToUInt64($ctx, 0x80)
        $ctxRdx = [BitConverter]::ToUInt64($ctx, 0x88)
    }
}

$stackFrames = @()
if ($streams.ContainsKey(3) -and $ctxRsp) {
    $fs.Position = $streams[3].Rva
    $nt = Read-U32 $br
    $threadStack = $null
    for ($i = 0; $i -lt $nt; $i++) {
        $tid = Read-U32 $br
        [void](Read-U32 $br) # suspend
        [void](Read-U32 $br) # pri class
        [void](Read-U32 $br) # pri
        [void](Read-U64 $br) # teb
        $stkSize = Read-U32 $br
        $stkRva = Read-U32 $br
        $ctxSz = Read-U32 $br
        $ctxRv = Read-U32 $br
        if ($tid -eq $exThread) {
            $threadStack = @{ Rva = $stkRva; Size = $stkSize }
            if (-not $ctxRip -and $ctxSz -ge 0x100) {
                $ctx = Read-At $ctxRv $ctxSz
                $ctxRip = [BitConverter]::ToUInt64($ctx, 0xF8)
                $ctxRsp = [BitConverter]::ToUInt64($ctx, 0x98)
            }
        }
    }
    if ($threadStack) {
        $mem = Read-At $threadStack.Rva ([Math]::Min($threadStack.Size, 0x2000))
        $off = 0
        while ($off + 8 -le $mem.Length -and $stackFrames.Count -lt 48) {
            $v = [BitConverter]::ToUInt64($mem, $off)
            if ($v -gt 0x10000) {
                $sym = Resolve-Addr $v
                if ($sym -notmatch '^0x') { $stackFrames += $sym }
            }
            $off += 8
        }
    }
}

$lines = @(
    "MINIDUMP_STACK_PARSE",
    "Dump=$DumpPath",
    "ExceptionThreadId=$exThread",
    ("ExceptionCode=0x{0:X8}" -f $exCode),
    ("ExceptionAddress={0} ({1})" -f $exAddr, (Resolve-Addr $exAddr)),
    ("Context Rip=0x{0:X} ({1})" -f $ctxRip, (Resolve-Addr $ctxRip)),
    ("Context Rsp=0x{0:X}" -f $ctxRsp),
    ("Context Rcx=0x{0:X}" -f $ctxRcx),
    ("Context Rdx=0x{0:X}" -f $ctxRdx),
    "",
    "=== Modules (image) ==="
)
foreach ($m in ($mods | Where-Object { $_.Name -match 'RawrXD|ntdll|KERNEL' } | Sort-Object Name)) {
    $lines += ("{0} base=0x{1:X} size=0x{2:X}" -f $m.Name, $m.Base, $m.Size)
}
$lines += ""
$lines += "=== Stack scan (return-address candidates) ==="
$idx = 0
foreach ($f in $stackFrames) {
    $lines += ("  [{0,2}] {1}" -f $idx, $f)
    $idx++
}

$text = $lines -join "`r`n"
if ($OutPath) { Set-Content -Path $OutPath -Value $text -Encoding UTF8 }
$text
$br.Close(); $fs.Close()
