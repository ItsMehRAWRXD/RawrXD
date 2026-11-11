param([string]$Dump = "$env:LOCALAPPDATA\RawrXD\crashes\rawrxd-20261103-012239.dmp")
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class DumpMod {
  [StructLayout(LayoutKind.Sequential, Pack=4)]
  public struct MINIDUMP_MODULE {
    public ulong BaseOfImage;
    public uint SizeOfImage;
    public uint CheckSum;
    public uint TimeDateStamp;
    public uint ModuleNameRva;
    public uint dwSignature, dwStrucVersion, dwFileVersionMS, dwFileVersionLS;
    public uint dwProductVersionMS, dwProductVersionLS, dwFileFlagsMask, dwFileFlags;
    public uint dwFileOS, dwFileType, dwFileSubtype, dwFileDateMS, dwFileDateLS;
    public uint CvDataSize, CvRva, MiscDataSize, MiscRva;
    public ulong Reserved0, Reserved1;
  }
  [DllImport("dbghelp.dll", SetLastError=true)]
  public static extern bool MiniDumpReadDumpStream(
    IntPtr BaseOfDump, uint StreamNumber, out IntPtr Dir, out IntPtr StreamPointer, out uint StreamSize);
}
'@
$bytes = [IO.File]::ReadAllBytes($Dump)
$pinned = [Runtime.InteropServices.GCHandle]::Alloc($bytes, 'Pinned')
try {
  $base = $pinned.AddrOfPinnedObject()
  $dir = [IntPtr]::Zero; $stream = [IntPtr]::Zero; $ssize = [uint32]0
  # ModuleListStream = 4
  $ok = [DumpMod]::MiniDumpReadDumpStream($base, 4, [ref]$dir, [ref]$stream, [ref]$ssize)
  "ModuleListRead=$ok size=$ssize err=$([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
  if (-not $ok) { return }
  $num = [Runtime.InteropServices.Marshal]::ReadInt32($stream)
  "count=$num"
  $faultRip = [uint64]0x7FFC7BE7BD02
  # Exception stream = 6
  $dir2=[IntPtr]::Zero; $estream=[IntPtr]::Zero; $esize=[uint32]0
  [void][DumpMod]::MiniDumpReadDumpStream($base, 6, [ref]$dir2, [ref]$estream, [ref]$esize)
  $code = [Runtime.InteropServices.Marshal]::ReadInt32($estream, 8)
  $rip = [uint64][Runtime.InteropServices.Marshal]::ReadInt64($estream, 24)
  $access = [uint64][Runtime.InteropServices.Marshal]::ReadInt64($estream, 40)
  $target = [uint64][Runtime.InteropServices.Marshal]::ReadInt64($estream, 48)
  "EXC code=0x$($code.ToString('X8')) rip=0x$($rip.ToString('X')) write=$access target=0x$($target.ToString('X'))"
  $faultRip = $rip
  $modSize = [Runtime.InteropServices.Marshal]::SizeOf([type][DumpMod+MINIDUMP_MODULE])
  "MINIDUMP_MODULE sizeof=$modSize"
  $ptr = [Int64]$stream + 4
  if (($ptr % 8) -ne 0) { $ptr += 4 }
  for ($i=0; $i -lt $num; $i++) {
    $m = [Runtime.InteropServices.Marshal]::PtrToStructure([IntPtr]$ptr, [type][DumpMod+MINIDUMP_MODULE])
    $nameRva = $m.ModuleNameRva
    $slen = [BitConverter]::ToUInt32($bytes, [int]$nameRva)
    $name = [Text.Encoding]::Unicode.GetString($bytes, [int]$nameRva + 4, [Math]::Min([int]$slen, 520))
    $leaf = $name
    $idx = $leaf.LastIndexOf('\'); if ($idx -ge 0) { $leaf = $leaf.Substring($idx+1) }
    $end = $m.BaseOfImage + $m.SizeOfImage
    if ($faultRip -ge $m.BaseOfImage -and $faultRip -lt $end) {
      "HIT $leaf base=0x$($m.BaseOfImage.ToString('X')) rva=0x$(($faultRip-$m.BaseOfImage).ToString('X')) size=0x$($m.SizeOfImage.ToString('X'))"
    }
    if ($leaf -match 'RawrXD|RichEd|msftedit|user32|ntdll|ucrtbase|comctl32|winhttp|vcruntime|msvcp') {
      "MOD $leaf 0x$($m.BaseOfImage.ToString('X'))-0x$($end.ToString('X'))"
    }
    $ptr += $modSize
  }
} finally { $pinned.Free() }
