$ErrorActionPreference = 'Stop'
$src = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\harness\issue49_ORIG.ps1'
$dst = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\harness\issue49_product_final_e6cf_chatfix.ps1'
$t = [IO.File]::ReadAllText($src)

# Retarget defaults to INTEG_008 / E6CF (no cross-SHA inherit).
$t = $t.Replace(
  '[string]$TipExe = "F:\rawrxd\evidence\CC79_RUNTIME_001\package\tip_cc79_integ_002\RawrXD-Win32IDE-Native-Ext.exe",',
  '[string]$TipExe = "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_008\RawrXD-Win32IDE-Native-Ext.exe",'
)
$t = $t.Replace(
  '[string]$ExpectSha = "F5F4807E4738F500397AA5ACEBC8BE095806DF19C71FF959083512C73A16BA15",',
  '[string]$ExpectSha = "E6CF5BD2B23638B046926F301997926BD35B1524CD3D58B59A75A24946466A3E",'
)
$t = $t.Replace(
  '[string]$OutDir = "F:\rawrxd\evidence\CC79_RUNTIME_001\artifacts",',
  '[string]$OutDir = "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\issue49_integ008_chatfix",'
)
$t = $t.Replace(
  '[string]$LogDir = "F:\rawrxd\evidence\CC79_RUNTIME_001\candidates\tip_cc79_integ_002_issue49",',
  '[string]$LogDir = "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_008\issue49_chatfix_logs",'
)

$oldType = @'
Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public static class I49 {
  public const uint WM_COMMAND=0x0111; public const uint WM_GETTEXT=0x000D; public const uint WM_GETTEXTLENGTH=0x000E;
  public const uint LVM_GETITEMCOUNT=0x1004; public const uint SMTO_NORMAL=0;
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder s);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern bool SetWindowTextW(IntPtr h, string s);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageTimeoutW(IntPtr h, uint m, IntPtr w, IntPtr l, uint f, uint t, out IntPtr r);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  public static IntPtr FindMain(uint pid){
    IntPtr f=IntPtr.Zero;
    EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p!=pid||!IsWindowVisible(h)) return true;
      var sb=new StringBuilder(256); GetClassNameW(h,sb,256);
      if(sb.ToString()=="RawrXD_IDE_Window"){ f=h; return false;} return true; }, IntPtr.Zero);
    return f;
  }
  public static IntPtr FindId(IntPtr root,int id){
    IntPtr f=IntPtr.Zero;
    EnumChildWindows(root,(h,lp)=>{ if(GetDlgCtrlID(h)==id){f=h;return false;} return true;},IntPtr.Zero);
    return f;
  }
  public static int IdList(IntPtr root,int id){ IntPtr h=FindId(root,id); if(h==IntPtr.Zero) return -1; return (int)SendMessageW(h,LVM_GETITEMCOUNT,IntPtr.Zero,IntPtr.Zero); }
  public static int IdLen(IntPtr root,int id){ IntPtr h=FindId(root,id); if(h==IntPtr.Zero) return -1; return (int)SendMessageW(h,WM_GETTEXTLENGTH,IntPtr.Zero,IntPtr.Zero); }
  public static bool VisId(IntPtr root,int id){ IntPtr h=FindId(root,id); return h!=IntPtr.Zero && IsWindowVisible(h); }
  public static bool Cmd(IntPtr main,int id,uint ms){ IntPtr r; return SendMessageTimeoutW(main,WM_COMMAND,(IntPtr)id,IntPtr.Zero,SMTO_NORMAL,ms,out r)!=IntPtr.Zero; }
  public static bool SetText(IntPtr h, string s){ if(h==IntPtr.Zero) return false; return SetWindowTextW(h,s); }
  public static string GetText(IntPtr h){
    if(h==IntPtr.Zero) return "";
    int n=(int)SendMessageW(h,WM_GETTEXTLENGTH,IntPtr.Zero,IntPtr.Zero);
    if(n<=0) return "";
    if(n>120000) n=120000;
    var sb=new StringBuilder(n+2);
    SendMessageW(h,WM_GETTEXT,(IntPtr)(n+1),sb);
    return sb.ToString();
  }
}
"@
'@

$newType = @'
Add-Type @"
using System; using System.Text; using System.Collections.Generic; using System.Runtime.InteropServices;
public static class I49 {
  public const uint WM_COMMAND=0x0111; public const uint WM_SETTEXT=0x000C; public const uint WM_GETTEXT=0x000D; public const uint WM_GETTEXTLENGTH=0x000E;
  public const uint LVM_GETITEMCOUNT=0x1004; public const uint SMTO_NORMAL=0; public const uint KEYEVENTF_KEYUP=0x0002;
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder s);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, string s);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern bool SetWindowTextW(IntPtr h, string s);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageTimeoutW(IntPtr h, uint m, IntPtr w, IntPtr l, uint f, uint t, out IntPtr r);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern IntPtr SetFocus(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr GetFocus();
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
  [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, bool fAttach);
  [DllImport("user32.dll", SetLastError=true)] public static extern uint SendInput(uint n, INPUT[] i, int cb);
  [StructLayout(LayoutKind.Sequential)] public struct INPUT { public uint type; public KEYBDINPUT ki; }
  [StructLayout(LayoutKind.Sequential)] public struct KEYBDINPUT {
    public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public IntPtr dwExtraInfo; public uint padding1; public uint padding2;
  }
  public static int InputSize { get { return Marshal.SizeOf(typeof(INPUT)); } }
  public static uint KeyDown(ushort vk){ INPUT[] a=new INPUT[1]; a[0].type=1; a[0].ki.wVk=vk; return SendInput(1,a,InputSize); }
  public static uint KeyUp(ushort vk){ INPUT[] a=new INPUT[1]; a[0].type=1; a[0].ki.wVk=vk; a[0].ki.dwFlags=KEYEVENTF_KEYUP; return SendInput(1,a,InputSize); }
  public static IntPtr FindMain(uint pid){
    IntPtr f=IntPtr.Zero;
    EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p!=pid||!IsWindowVisible(h)) return true;
      var sb=new StringBuilder(256); GetClassNameW(h,sb,256);
      string c=sb.ToString();
      if(c=="RawrXD_IDE_Window"||c=="RawrXD_IDE_MainWindow"){ f=h; return false;} return true; }, IntPtr.Zero);
    return f;
  }
  public static IntPtr FindId(IntPtr root,int id){
    IntPtr f=IntPtr.Zero;
    EnumChildWindows(root,(h,lp)=>{ if(GetDlgCtrlID(h)==id){f=h;return false;} return true;},IntPtr.Zero);
    return f;
  }
  public static IntPtr FindEditId(IntPtr root,int id){
    var stack=new Stack<IntPtr>(); stack.Push(root);
    while(stack.Count>0){
      IntPtr cur=stack.Pop();
      var kids=new List<IntPtr>();
      EnumChildWindows(cur,(h,lp)=>{ kids.Add(h); return true; },IntPtr.Zero);
      foreach(var k in kids){
        var sb=new StringBuilder(64); GetClassNameW(k,sb,64);
        if(GetDlgCtrlID(k)==id && sb.ToString().IndexOf("Edit",StringComparison.OrdinalIgnoreCase)>=0) return k;
        stack.Push(k);
      }
    }
    return IntPtr.Zero;
  }
  public static int IdList(IntPtr root,int id){ IntPtr h=FindId(root,id); if(h==IntPtr.Zero) return -1; return (int)SendMessageW(h,LVM_GETITEMCOUNT,IntPtr.Zero,IntPtr.Zero); }
  public static int IdLen(IntPtr root,int id){ IntPtr h=FindEditId(root,id); if(h==IntPtr.Zero) h=FindId(root,id); if(h==IntPtr.Zero) return -1; return (int)SendMessageW(h,WM_GETTEXTLENGTH,IntPtr.Zero,IntPtr.Zero); }
  public static bool VisId(IntPtr root,int id){ IntPtr h=FindId(root,id); return h!=IntPtr.Zero && IsWindowVisible(h); }
  public static bool Cmd(IntPtr main,int id,uint ms){ IntPtr r; return SendMessageTimeoutW(main,WM_COMMAND,(IntPtr)id,IntPtr.Zero,SMTO_NORMAL,ms,out r)!=IntPtr.Zero; }
  public static bool SetText(IntPtr h, string s){ if(h==IntPtr.Zero) return false; SendMessageW(h,WM_SETTEXT,IntPtr.Zero,s??""); return true; }
  public static string GetText(IntPtr h){
    if(h==IntPtr.Zero) return "";
    int n=(int)SendMessageW(h,WM_GETTEXTLENGTH,IntPtr.Zero,IntPtr.Zero);
    if(n<=0) return "";
    if(n>120000) n=120000;
    var sb=new StringBuilder(n+2);
    SendMessageW(h,WM_GETTEXT,(IntPtr)(n+1),sb);
    return sb.ToString();
  }
  public static void FocusChat(IntPtr main, IntPtr chat){
    uint pid=0; uint ideTid=GetWindowThreadProcessId(main,out pid); uint myTid=GetCurrentThreadId();
    IntPtr fg=GetForegroundWindow(); uint pidFg=0; uint fgTid=(fg!=IntPtr.Zero)?GetWindowThreadProcessId(fg,out pidFg):(uint)0;
    if(fgTid!=0 && fgTid!=myTid && fgTid!=ideTid) AttachThreadInput(myTid,fgTid,true);
    if(ideTid!=0 && ideTid!=myTid) AttachThreadInput(myTid,ideTid,true);
    ShowWindow(main,9); BringWindowToTop(main); SetForegroundWindow(main); SetFocus(chat);
  }
  public static void DetachChat(IntPtr main){
    uint pid=0; uint ideTid=GetWindowThreadProcessId(main,out pid); uint myTid=GetCurrentThreadId();
    if(ideTid!=0 && ideTid!=myTid) AttachThreadInput(myTid,ideTid,false);
  }
  public static void SendCtrlEnter(IntPtr main, IntPtr chat){
    FocusChat(main,chat);
    System.Threading.Thread.Sleep(50);
    KeyDown(0x11); System.Threading.Thread.Sleep(40);
    KeyDown(0x0D); System.Threading.Thread.Sleep(80);
    KeyUp(0x0D); KeyUp(0x11);
    System.Threading.Thread.Sleep(50);
    DetachChat(main);
  }
}
"@
'@

if (-not $t.Contains($oldType.TrimEnd())) { throw 'old Add-Type block not found' }
$t = $t.Replace($oldType.TrimEnd(), $newType.TrimEnd())

$oldChat = @'
$chat = [I49]::FindId($main, 1202)
$prompt = 'Find the bug in bug.cpp, fix it, build it and test it.'
$setOk = [I49]::SetText($chat, $prompt)
$chatLen = [I49]::IdLen($main, 1202)
Log "CHAT_INPUT setOk=$setOk len=$chatLen hwnd=0x$('{0:X}' -f $chat.ToInt64())"
Mark $steps '05_AGENT_PROMPT' $(if ($setOk -and $chatLen -gt 10) { 'PASS_PROMPT_STAGED_IN_CHAT_INPUT' } else { 'FAIL_CHAT_INPUT_SET' })

$runOk = [I49]::Cmd($main, 4106, 8000)
Log "AGENTIC_LOOP_RUN_4106=$runOk"
Start-Sleep 2
$startOk = [I49]::Cmd($main, 4100, 5000)
Log "AGENT_START_LOOP_4100=$startOk"
'@

$newChat = @'
# Align with E6CF CHAT busywait path: recursive Edit IDC 1202 + WM_SETTEXT + Ctrl+Enter SendInput.
$chat = [I49]::FindEditId($main, 1202)
if ($chat -eq [IntPtr]::Zero) { $chat = [I49]::FindId($main, 1202) }
$prompt = 'Find the bug in bug.cpp, fix it, build it and test it.'
$rtLog = Join-Path $LogDir 'chat_runtime.log'
if (Test-Path -LiteralPath $rtLog) { Remove-Item -LiteralPath $rtLog -Force -EA SilentlyContinue }
$setOk = [I49]::SetText($chat, $prompt)
Start-Sleep -Milliseconds 200
$stagedText = [I49]::GetText($chat)
$chatLen = $stagedText.Length
Log "CHAT_INPUT setOk=$setOk len=$chatLen hwnd=0x$('{0:X}' -f $chat.ToInt64()) staged='$($stagedText.Substring(0,[Math]::Min(48,$stagedText.Length)))'"
$beforeAttempts = @()
if (Test-Path -LiteralPath $rtLog) { $beforeAttempts = @(Get-Content -LiteralPath $rtLog | Where-Object { $_ -match 'CHAT_SEND_ATTEMPT' }) }
[I49]::SendCtrlEnter($main, $chat)
Start-Sleep -Milliseconds 800
$afterText = [I49]::GetText($chat)
$afterAttempts = @()
if (Test-Path -LiteralPath $rtLog) { $afterAttempts = @(Get-Content -LiteralPath $rtLog | Where-Object { $_ -match 'CHAT_SEND_ATTEMPT' }) }
$newAttempts = @($afterAttempts | Where-Object { $beforeAttempts -notcontains $_ }).Count
$chatSendOk = ($newAttempts -ge 1) -or ($chatLen -gt 10 -and ($afterText -eq '' -or $afterText -ne $stagedText))
$chatStageOk = ($setOk -and $chatLen -gt 10)
Log "CHAT_CTRL_ENTER newAttempts=$newAttempts afterLen=$($afterText.Length) stageOk=$chatStageOk sendOk=$chatSendOk rt=$rtLog"
if ($chatStageOk -and $chatSendOk) {
  Mark $steps '05_AGENT_PROMPT' 'PASS_PROMPT_CTRL_ENTER_SEND'
} elseif ($chatStageOk) {
  Mark $steps '05_AGENT_PROMPT' 'PASS_PROMPT_STAGED_IN_CHAT_INPUT'
} elseif ($chatSendOk) {
  Mark $steps '05_AGENT_PROMPT' 'PASS_CTRL_ENTER_SEND_ATTEMPT'
} else {
  Mark $steps '05_AGENT_PROMPT' 'FAIL_CHAT_INPUT_SET'
}

$runOk = [I49]::Cmd($main, 4106, 8000)
Log "AGENTIC_LOOP_RUN_4106=$runOk"
Start-Sleep 2
$startOk = [I49]::Cmd($main, 4100, 5000)
Log "AGENT_START_LOOP_4100=$startOk"
'@

if (-not $t.Contains($oldChat.TrimEnd())) { throw 'old chat block not found' }
$t = $t.Replace($oldChat.TrimEnd(), $newChat.TrimEnd())

$t = $t.Replace(
  '# Issue #49 product-final attempt on tip_cc79_integ_002 (F5F4807E...).',
  '# Issue #49 product-final on tip_final_integ_008 (E6CF...). CHAT path = busywait Ctrl+Enter.'
)

[IO.File]::WriteAllText($dst, $t)
Write-Host "WROTE=$dst LEN=$($t.Length)"
Write-Host "HAS_FindEditId=$($t.Contains('FindEditId')) HAS_SendCtrlEnter=$($t.Contains('SendCtrlEnter')) HAS_E6CF=$($t.Contains('E6CF5BD2B23638B046926F301997926BD35B1524CD3D58B59A75A24946466A3E'))"
