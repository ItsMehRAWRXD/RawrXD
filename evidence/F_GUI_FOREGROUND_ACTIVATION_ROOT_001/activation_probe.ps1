$ErrorActionPreference='Stop'
$exe='F:\rawrxd\build_ide\bin\RawrXD-Win32IDE-Native.exe'
$expected='70E6B1700F8EDF7A3770F63A5B89565AB05798CAB4B8DFC784200153B786F9DA'
Add-Type @'
using System;using System.Runtime.InteropServices;
public static class ActivationNative{
[StructLayout(LayoutKind.Sequential)]public struct POINT{public int x,y;}
[StructLayout(LayoutKind.Sequential)]public struct RECT{public int left,top,right,bottom;}
[StructLayout(LayoutKind.Sequential)]public struct WINDOWPLACEMENT{public uint length,flags,showCmd;public POINT min,max;public RECT normal;}
[StructLayout(LayoutKind.Sequential)]public struct GUITHREADINFO{public uint cbSize,flags;public IntPtr active,focus,capture,menu,move,caret;public RECT caretRect;}
[DllImport("user32.dll",SetLastError=true)]public static extern bool SetForegroundWindow(IntPtr h);
[DllImport("user32.dll",SetLastError=true)]public static extern bool ShowWindowAsync(IntPtr h,int cmd);
[DllImport("user32.dll")]public static extern bool IsWindowVisible(IntPtr h);
[DllImport("user32.dll")]public static extern bool IsWindowEnabled(IntPtr h);
[DllImport("user32.dll")]public static extern bool IsIconic(IntPtr h);
[DllImport("user32.dll",SetLastError=true)]public static extern bool GetWindowPlacement(IntPtr h,ref WINDOWPLACEMENT p);
[DllImport("user32.dll")]public static extern IntPtr GetForegroundWindow();
[DllImport("user32.dll")]public static extern uint GetWindowThreadProcessId(IntPtr h,out uint pid);
[DllImport("user32.dll",SetLastError=true)]public static extern bool GetGUIThreadInfo(uint id,ref GUITHREADINFO i);
[DllImport("kernel32.dll")]public static extern uint GetCurrentThreadId();
[DllImport("kernel32.dll",SetLastError=true)]public static extern bool ProcessIdToSessionId(uint pid,out uint sid);}
'@
if((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash-ne$expected){throw'SHA mismatch'}
$native=@(Get-CimInstance Win32_Process -Filter "Name='rawrxd-win32ide-native.exe'")
if($native.Count){throw 'active IDE exists; physical probe refused'}
'STATIC_AND_READINESS_PASS=1';'PHYSICAL_LAUNCH=NOT_PERFORMED'
