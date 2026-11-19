$src = @"
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public class TabVerify {
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc p, IntPtr l);
    [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr parent, EnumWindowsProc p, IntPtr l);
    [DllImport("user32.dll", CharSet=CharSet.Ansi)] public static extern IntPtr SendMessageA(IntPtr h, uint m, IntPtr w, IntPtr l);
    [DllImport("user32.dll", CharSet=CharSet.Ansi)] public static extern int GetClassNameA(IntPtr h, StringBuilder s, int m);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
    public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);

    public const uint TCM_GETITEMCOUNT = 0x1304;
    public const uint TCM_GETITEMA = 0x1305;
    public const uint TCIF_TEXT = 0x0001;

    public static IntPtr Main = IntPtr.Zero;
    public static List<IntPtr> Tabs = new List<IntPtr>();

    public static string ReadTabA(IntPtr hTab, int idx) {
        const int TCITEM_SIZE = 48;
        IntPtr mem = Marshal.AllocHGlobal(TCITEM_SIZE + 512);
        try {
            // TCITEMA layout (x64): mask@0, dwState@4, dwStateMask@8, pszText@16, cchTextMax@24, iImage@28, lParam@32
            Marshal.WriteInt32(mem, 0, (int)TCIF_TEXT);      // mask
            Marshal.WriteInt32(mem, 4, 0);                    // dwState
            Marshal.WriteInt32(mem, 8, 0);                    // dwStateMask
            Marshal.WriteIntPtr(mem, 16, (IntPtr)(mem.ToInt64() + TCITEM_SIZE)); // pszText -> buffer
            Marshal.WriteInt32(mem, 24, 255);                 // cchTextMax
            Marshal.WriteInt32(mem, 28, -1);                  // iImage
            Marshal.WriteIntPtr(mem, 32, IntPtr.Zero);        // lParam
            SendMessageA(hTab, TCM_GETITEMA, (IntPtr)idx, mem);
            return Marshal.PtrToStringAnsi((IntPtr)(mem.ToInt64() + TCITEM_SIZE)) ?? "";
        } finally { Marshal.FreeHGlobal(mem); }
    }
}
"@
Add-Type -TypeDefinition $src

$targetPid = 31540
$findMain = [TabVerify+EnumWindowsProc]{
    param($h, $l)
    $wp = 0
    [TabVerify]::GetWindowThreadProcessId($h, [ref]$wp) | Out-Null
    if ($wp -eq $targetPid -and [TabVerify]::IsWindowVisible($h)) { [TabVerify]::Main = $h; return $false }
    return $true
}
[TabVerify]::EnumWindows($findMain, [IntPtr]::Zero) | Out-Null

$findTabs = [TabVerify+EnumWindowsProc]{
    param($h, $l)
    $sb = New-Object System.Text.StringBuilder 128
    [TabVerify]::GetClassNameA($h, $sb, 128) | Out-Null
    if ($sb.ToString() -eq 'SysTabControl32') { [TabVerify]::Tabs.Add($h) }
    return $true
}
[TabVerify]::EnumChildWindows([TabVerify]::Main, $findTabs, [IntPtr]::Zero) | Out-Null

Write-Output "MainHWND=$([TabVerify]::Main)  TabControls=$([TabVerify]::Tabs.Count)"
$ti = 0
foreach ($tab in [TabVerify]::Tabs) {
    $count = [TabVerify]::SendMessageA($tab, [TabVerify]::TCM_GETITEMCOUNT, [IntPtr]::Zero, [IntPtr]::Zero).ToInt32()
    Write-Output "--- TabControl #$ti HWND=$tab itemCount=$count ---"
    for ($n = 0; $n -lt [Math]::Min($count, 16); $n++) {
        $txt = [TabVerify]::ReadTabA($tab, $n)
        $cjk = $txt -match '[\u4e00-\u9fff]'
        Write-Output ("  [{0}] '{1}'  CJK={2}" -f $n, $txt, $cjk)
    }
    $ti++
}
