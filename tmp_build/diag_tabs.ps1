$src = @"
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public class TabDiag {
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc p, IntPtr l);
    [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr parent, EnumWindowsProc p, IntPtr l);
    [DllImport("user32.dll", CharSet=CharSet.Ansi)] public static extern IntPtr SendMessageA(IntPtr h, uint m, IntPtr w, IntPtr l);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
    [DllImport("user32.dll", CharSet=CharSet.Ansi)] public static extern int GetClassNameA(IntPtr h, StringBuilder s, int m);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] public static extern int GetWindowLong(IntPtr h, int i);
    public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);

    public const uint TCM_GETITEMCOUNT = 0x1304;
    public const uint TCM_GETITEMA = 0x1305;
    public const uint TCM_GETITEMW = 0x133D;
    public const uint TCIF_TEXT = 0x0001;

    public static IntPtr Main = IntPtr.Zero;
    public static List<IntPtr> Tabs = new List<IntPtr>();
    public static List<int> TabIds = new List<int>();

    // raw dump: returns bytes at pszText target after A read
    public static string DumpA(IntPtr hTab, int idx) {
        IntPtr mem = Marshal.AllocHGlobal(40 + 1024);
        try {
            Marshal.WriteInt32(mem, 0, (int)TCIF_TEXT);
            Marshal.WriteInt32(mem, 4, 0);
            Marshal.WriteInt32(mem, 8, 0);
            Marshal.WriteIntPtr(mem, 16, (IntPtr)(mem.ToInt64() + 40));
            Marshal.WriteInt32(mem, 24, 511);
            Marshal.WriteInt32(mem, 28, -1);
            Marshal.WriteIntPtr(mem, 32, IntPtr.Zero);
            for (int i = 40; i < 40 + 64; i++) Marshal.WriteByte(mem, i, 0);
            SendMessageA(hTab, TCM_GETITEMA, (IntPtr)idx, mem);
            IntPtr txtPtr = Marshal.ReadIntPtr(mem, 16);
            StringBuilder sb = new StringBuilder();
            if (txtPtr != IntPtr.Zero) {
                for (int i = 0; i < 48; i++) {
                    byte b = Marshal.ReadByte(txtPtr, i);
                    if (b == 0) break;
                    sb.Append(b.ToString("X2") + " ");
                }
            }
            string ansi = "";
            if (txtPtr != IntPtr.Zero) ansi = Marshal.PtrToStringAnsi(txtPtr);
            return "ptr=" + txtPtr.ToString("X") + " bytes=[" + sb.ToString() + "] ansi='" + (ansi ?? "") + "'";
        } finally { Marshal.FreeHGlobal(mem); }
    }
}
"@
Add-Type -TypeDefinition $src

$targetPid = 52692
$findMain = [TabDiag+EnumWindowsProc]{
    param($h, $l)
    $wp = 0
    [TabDiag]::GetWindowThreadProcessId($h, [ref]$wp) | Out-Null
    if ($wp -eq $targetPid -and [TabDiag]::IsWindowVisible($h)) { [TabDiag]::Main = $h; return $false }
    return $true
}
[TabDiag]::EnumWindows($findMain, [IntPtr]::Zero) | Out-Null

$findTabs = [TabDiag+EnumWindowsProc]{
    param($h, $l)
    $sb = New-Object System.Text.StringBuilder 128
    [TabDiag]::GetClassNameA($h, $sb, 128) | Out-Null
    if ($sb.ToString() -eq 'SysTabControl32') {
        [TabDiag]::Tabs.Add($h)
        [TabDiag]::TabIds.Add([TabDiag]::GetWindowLong($h, -12))
    }
    return $true
}
[TabDiag]::EnumChildWindows([TabDiag]::Main, $findTabs, [IntPtr]::Zero) | Out-Null

Write-Output "MainHWND=$([TabDiag]::Main) TabControls=$([TabDiag]::Tabs.Count)"
for ($i = 0; $i -lt [TabDiag]::Tabs.Count; $i++) {
    $tab = [TabDiag]::Tabs[$i]
    $id = [TabDiag]::TabIds[$i]
    $count = [TabDiag]::SendMessageA($tab, [TabDiag]::TCM_GETITEMCOUNT, [IntPtr]::Zero, [IntPtr]::Zero).ToInt32()
    Write-Output "=== TabControl #$i HWND=$tab ID=$id itemCount=$count ==="
    for ($n = 0; $n -lt [Math]::Min($count, 6); $n++) {
        Write-Output ("  [{0}] {1}" -f $n, [TabDiag]::DumpA($tab, $n))
    }
}
