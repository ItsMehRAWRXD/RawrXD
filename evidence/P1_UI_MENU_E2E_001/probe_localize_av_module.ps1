# Localization only: debuggee IDE, resolve MODULE for first 0xC0000005.
# Same SHA. NOT repair. NOT full E2E ladder.
$ErrorActionPreference = 'Stop'
$expect = '00768A39154489D6EED3CCC1A755C16F0F2978B010F759DEFB8CB224142EDC35'
$bin = 'F:\~dev\rawrxd\build-ninja\bin'
$ide = Join-Path $bin 'RawrXD-Win32IDE.exe'
$repo = 'F:\~dev\rawrxd\evidence\P1_UI_MENU_E2E_001'
$out = Join-Path $repo 'LOCALIZE_AV_MODULE.txt'
$sha = (Get-FileHash $ide -Algorithm SHA256).Hash
if ($sha -ne $expect) { throw "SHA_MISMATCH live=$sha" }

Get-Process RawrXD-Win32IDE,p1_ui_menu_e2e_cert -ErrorAction SilentlyContinue |
  Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class AvLoc3 {
  public const uint DBG_CONTINUE = 0x00010002;
  public const uint DBG_EXCEPTION_NOT_HANDLED = 0x80010001;
  public const uint EXCEPTION_ACCESS_VIOLATION = 0xC0000005;
  public const uint EXCEPTION_BREAKPOINT = 0x80000003;
  public const uint DEBUG_ONLY_THIS_PROCESS = 0x00000002;

  [StructLayout(LayoutKind.Explicit, Size = 176)]
  public struct DEBUG_EVENT {
    [FieldOffset(0)] public uint dwDebugEventCode;
    [FieldOffset(4)] public uint dwProcessId;
    [FieldOffset(8)] public uint dwThreadId;
    [FieldOffset(16)] public uint ExceptionCode;
    [FieldOffset(20)] public uint ExceptionFlags;
    [FieldOffset(24)] public IntPtr ExceptionRecordPtr;
    [FieldOffset(32)] public IntPtr ExceptionAddress;
  }
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
  public struct STARTUPINFOW {
    public int cb; public IntPtr reserved, desktop, title;
    public int x,y,xSize,ySize,xCountChars,yCountChars,fill,flags;
    public short show, reserved2; public IntPtr reserved3, stdIn, stdOut, stdErr;
  }
  [StructLayout(LayoutKind.Sequential)]
  public struct PROCESS_INFORMATION {
    public IntPtr hProcess, hThread; public uint dwProcessId, dwThreadId;
  }
  [StructLayout(LayoutKind.Sequential)]
  public struct MODULEINFO {
    public IntPtr lpBaseOfDll; public uint SizeOfImage; public IntPtr EntryPoint;
  }

  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern bool CreateProcessW(string app, string cmd, IntPtr pa, IntPtr ta,
    bool inherit, uint flags, IntPtr env, string dir, ref STARTUPINFOW si, out PROCESS_INFORMATION pi);
  [DllImport("kernel32.dll")] public static extern bool WaitForDebugEvent(ref DEBUG_EVENT ev, uint ms);
  [DllImport("kernel32.dll")] public static extern bool ContinueDebugEvent(uint pid, uint tid, uint status);
  [DllImport("kernel32.dll")] public static extern bool DebugActiveProcessStop(uint pid);
  [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
  [DllImport("psapi.dll", SetLastError=true)]
  public static extern bool EnumProcessModulesEx(IntPtr h, [Out] IntPtr[] mods, uint cb, out uint needed, uint filter);
  [DllImport("psapi.dll", CharSet=CharSet.Unicode)]
  public static extern uint GetModuleFileNameExW(IntPtr h, IntPtr mod, StringBuilder sb, uint n);
  [DllImport("psapi.dll", SetLastError=true)]
  public static extern bool GetModuleInformation(IntPtr h, IntPtr mod, out MODULEINFO info, uint cb);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Ansi)] public static extern int GetClassNameA(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern IntPtr GetMenu(IntPtr h);
  [DllImport("user32.dll")] public static extern int GetMenuItemCount(IntPtr m);
  [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint msg, IntPtr w, IntPtr l);
  public delegate bool EnumProc(IntPtr h, IntPtr l);

  public static string ResolveModule(IntPtr hProc, IntPtr addr) {
    IntPtr[] mods = new IntPtr[1024];
    uint needed;
    if (!EnumProcessModulesEx(hProc, mods, (uint)(IntPtr.Size * mods.Length), out needed, 3))
      return "(EnumProcessModulesEx failed err=" + Marshal.GetLastWin32Error() + ")";
    int count = (int)(needed / (uint)IntPtr.Size);
    ulong a = unchecked((ulong)addr.ToInt64());
    for (int i = 0; i < count; i++) {
      MODULEINFO mi;
      if (!GetModuleInformation(hProc, mods[i], out mi, (uint)Marshal.SizeOf(typeof(MODULEINFO))))
        continue;
      ulong b = unchecked((ulong)mi.lpBaseOfDll.ToInt64());
      ulong e = b + mi.SizeOfImage;
      if (a >= b && a < e) {
        var sb = new StringBuilder(520);
        GetModuleFileNameExW(hProc, mods[i], sb, 520);
        return string.Format("MODULE={0}\nBASE=0x{1:X}\nSIZE=0x{2:X}\nRVA=0x{3:X}",
          sb, b, mi.SizeOfImage, a - b);
      }
    }
    return string.Format("MODULE=(none mapped)\nADDR=0x{0:X}\nMODULE_COUNT={1}", a, count);
  }

  public static IntPtr FindMain(uint pid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, l) => {
      uint p; GetWindowThreadProcessId(h, out p);
      if (p != pid) return true;
      var sb = new StringBuilder(128);
      GetClassNameA(h, sb, 128);
      if (sb.ToString() != "RawrXD_IDE_MainWindow") return true;
      IntPtr m = GetMenu(h);
      if (m != IntPtr.Zero && GetMenuItemCount(m) == 23) { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
}
'@

$env:RAWRXD_P1_CMD_DIAG = '1'
$env:RAWRXD_P1_UI_MENU_E2E = '1'
$env:RAWRXD_P1_UI_MENU_LIFETIME = '1'

$si = New-Object AvLoc3+STARTUPINFOW
$si.cb = [Runtime.InteropServices.Marshal]::SizeOf($si)
$pi = New-Object AvLoc3+PROCESS_INFORMATION
if (-not [AvLoc3]::CreateProcessW($ide, "`"$ide`"", [IntPtr]::Zero, [IntPtr]::Zero, $false,
    [AvLoc3]::DEBUG_ONLY_THIS_PROCESS, [IntPtr]::Zero, $bin, [ref]$si, [ref]$pi)) {
  throw "CreateProcess failed $($LASTEXITCODE)"
}

$lines = [System.Collections.Generic.List[string]]::new()
$lines.Add('LOCALIZE_AV_MODULE — same-SHA debug capture (NOT repair)')
$lines.Add("BINARY_SHA=$sha")
$lines.Add("PID=$($pi.dwProcessId)")
$lines.Add('COMPONENT_BLAME=NONE')
$lines.Add('REPAIR=NOT STARTED')

$invoked = $false
$gotAv = $false
$readySince = $null
$ev = New-Object AvLoc3+DEBUG_EVENT
$deadline = [datetime]::UtcNow.AddSeconds(100)

while ([datetime]::UtcNow -lt $deadline) {
  $has = [AvLoc3]::WaitForDebugEvent([ref]$ev, 100)
  if ($has) {
    $cont = [AvLoc3]::DBG_CONTINUE
    if ($ev.dwDebugEventCode -eq 1) {
      $code = $ev.ExceptionCode
      if ($code -eq [AvLoc3]::EXCEPTION_BREAKPOINT) {
        $cont = [AvLoc3]::DBG_CONTINUE
      } elseif ($code -eq [AvLoc3]::EXCEPTION_ACCESS_VIOLATION -and -not $gotAv) {
        $gotAv = $true
        $addr = $ev.ExceptionAddress.ToInt64()
        $mod = [AvLoc3]::ResolveModule($pi.hProcess, $ev.ExceptionAddress)
        $lines.Add(('EXCEPTION_CODE=0x{0:X8}' -f $code))
        $lines.Add(('EXCEPTION_ADDR=0x{0:X}' -f $addr))
        $lines.Add($mod)
        Write-Host ("AV addr=0x{0:X}" -f $addr)
        Write-Host $mod
        $cont = [AvLoc3]::DBG_EXCEPTION_NOT_HANDLED
      } else {
        $cont = [AvLoc3]::DBG_EXCEPTION_NOT_HANDLED
      }
    } elseif ($ev.dwDebugEventCode -eq 5) {
      $lines.Add('EXIT_PROCESS')
      [AvLoc3]::ContinueDebugEvent($ev.dwProcessId, $ev.dwThreadId, $cont) | Out-Null
      break
    }
    [AvLoc3]::ContinueDebugEvent($ev.dwProcessId, $ev.dwThreadId, $cont) | Out-Null
    if ($ev.dwDebugEventCode -eq 5) { break }
  }

  if (-not $invoked) {
    $hwnd = [AvLoc3]::FindMain($pi.dwProcessId)
    if ($hwnd -ne [IntPtr]::Zero) {
      if ($null -eq $readySince) { $readySince = [datetime]::UtcNow }
      elseif (([datetime]::UtcNow - $readySince).TotalSeconds -ge 3.5) {
        [void][AvLoc3]::PostMessage($hwnd, 0x0111, [IntPtr]1001, [IntPtr]::Zero)
        $lines.Add("POST_1001 hwnd=$hwnd")
        $invoked = $true
        Write-Host 'POSTED_1001'
      }
    }
  }
}

if (-not $gotAv) { $lines.Add('NO_AV_CAPTURED') }
try { [AvLoc3]::DebugActiveProcessStop($pi.dwProcessId) } catch {}
try { Stop-Process -Id $pi.dwProcessId -Force -ErrorAction SilentlyContinue } catch {}
$lines | Set-Content $out -Encoding UTF8
$lines | ForEach-Object { Write-Host $_ }
Write-Host "WROTE $out"
