param([string]$Path)
# Loads a DLL and reports the exact loader error.
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class RawrLoad {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern IntPtr LoadLibraryW(string p);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Ansi)]
  public static extern IntPtr GetProcAddress(IntPtr h, string n);
  [DllImport("kernel32.dll")]
  public static extern uint GetLastError();
}
'@
$h = [RawrLoad]::LoadLibraryW($Path)
$err = [RawrLoad]::GetLastError()
Write-Host ("LoadLibrary('{0}')" -f $Path)
Write-Host ("  handle = {0}" -f $h)
Write-Host ("  error  = {0}" -f $err)
if ($h -ne [IntPtr]::Zero) {
    $p = [RawrLoad]::GetProcAddress($h, "RawrxdAdd")
    Write-Host ("  GetProcAddress(RawrxdAdd) = {0}" -f $p)
}
