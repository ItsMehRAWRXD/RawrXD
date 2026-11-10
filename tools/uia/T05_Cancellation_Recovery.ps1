param(
  [Parameter(Mandatory)][string]$Exe,
  [Parameter(Mandatory)][string]$Sha256,
  [Parameter(Mandatory)][string]$EvidenceDir
)
$ErrorActionPreference='Stop'
Import-Module "$PSScriptRoot\RawrXD.UIA.psm1" -Force
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null
$marker = 'RAWRXD_CANCEL_RECOVERY_OK'
if(-not ('RawrXD_T05Native' -as [type])){
  Add-Type -TypeDefinition @'
using System; using System.Text; using System.Collections.Generic; using System.Runtime.InteropServices;
public static class RawrXD_T05Native {
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc lp, IntPtr l);
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern int GetWindowLongW(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern bool IsWindowEnabled(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder l);
  public const uint WM_SETTEXT=0x000C; public const uint BM_CLICK=0x00F5; public const uint WM_COMMAND=0x0111;
  public static IntPtr FindId(IntPtr parent, int id){
    IntPtr found=IntPtr.Zero;
    EnumChildWindows(parent,(h,l)=>{ if(GetWindowLongW(h,-12)==id){found=h;return false;} return true;},IntPtr.Zero);
    return found;
  }
  public static List<string> ComboItems(IntPtr combo){
    var rows=new List<string>(); if(combo==IntPtr.Zero) return rows;
    int cnt=SendMessageW(combo,0x0146,IntPtr.Zero,IntPtr.Zero).ToInt32();
    for(int i=0;i<cnt && i<300;i++){
      int len=SendMessageW(combo,0x0149,(IntPtr)i,IntPtr.Zero).ToInt32(); if(len<0) continue;
      var b=new StringBuilder(len+2); SendMessageW(combo,0x0148,(IntPtr)i,b); rows.Add(b.ToString());
    }
    return rows;
  }
  public static void SelectComboIndex(IntPtr parent, IntPtr combo, int index, int comboId){
    SendMessageW(combo,0x014E,(IntPtr)index,IntPtr.Zero);
    IntPtr wp=(IntPtr)((1<<16)|(comboId&0xFFFF)); // CBN_SELCHANGE
    SendMessageW(parent,WM_COMMAND,wp,combo);
    wp=(IntPtr)((9<<16)|(comboId&0xFFFF)); // CBN_SELENDOK
    SendMessageW(parent,WM_COMMAND,wp,combo);
  }
  public static int SetEditWmOnly(IntPtr edit, string text){
    IntPtr p=Marshal.StringToHGlobalUni(text);
    try { SendMessageW(edit,WM_SETTEXT,IntPtr.Zero,p); }
    finally { Marshal.FreeHGlobal(p); }
    return SendMessageW(edit,0x000E,IntPtr.Zero,IntPtr.Zero).ToInt32();
  }
  public static void ClickChild(IntPtr btn){ if(btn!=IntPtr.Zero) SendMessageW(btn,BM_CLICK,IntPtr.Zero,IntPtr.Zero); }
  public static string Text(IntPtr h){
    int len=SendMessageW(h,0x000E,IntPtr.Zero,IntPtr.Zero).ToInt32();
    if(len<=0) return "";
    var buf=new StringBuilder(len+2);
    SendMessageW(h,0x000D,(IntPtr)(len+1),buf); return buf.ToString();
  }
}
'@
}
$s=Start-RawrSession -Exe $Exe -Sha256 $Sha256 -EvidenceDir $EvidenceDir
$result=[ordered]@{
  Gate='T05'; CandidateSHA256=$Sha256; PID=$s.Pid; Model=$null
  CancelObserved=$false; SecondRequestSent=$false; SecondRequestRecovered=$false
  ProcessAlive=$false; StopFeedbackObserved=$false; MarkerExact=$false
  TranscriptDelta=$null; Error=$null
}
try {
  $p=Get-Process -Id $s.Pid -ErrorAction Stop
  $until=[DateTime]::UtcNow.AddSeconds(90)
  do {
    $p.Refresh()
    if($p.MainWindowHandle -ne [IntPtr]::Zero){
      $probe=[RawrXD_T05Native]::FindId($p.MainWindowHandle,1204)
      if($probe -ne [IntPtr]::Zero){ break }
    }
    Start-Sleep -Milliseconds 300
  } while([DateTime]::UtcNow -lt $until)
  if($p.MainWindowHandle -eq [IntPtr]::Zero){ throw 'NO_MAIN_WINDOW' }
  $main=$p.MainWindowHandle
  $combo=[RawrXD_T05Native]::FindId($main,1206)
  $inputHwnd=[RawrXD_T05Native]::FindId($main,1202)
  $outputHwnd=[RawrXD_T05Native]::FindId($main,1203)
  $sendHwnd=[RawrXD_T05Native]::FindId($main,1204)
  if($combo -eq [IntPtr]::Zero -or $inputHwnd -eq [IntPtr]::Zero -or $sendHwnd -eq [IntPtr]::Zero){ throw 'CONTROLS_MISSING' }

  $rows=@()
  $modelUntil=[DateTime]::UtcNow.AddSeconds(120)
  while([DateTime]::UtcNow -lt $modelUntil){
    $null=Get-Process -Id $s.Pid -ErrorAction Stop
    $rows=@([RawrXD_T05Native]::ComboItems($combo))
    $hasGemma=$false
    foreach($r in $rows){ if($r -like "*gemma3:4b*"){ $hasGemma=$true; break } }
    if($hasGemma){ break }
    if($rows.Count -gt 0){
      # Models present but gemma3:4b not yet; keep waiting
    }
    Start-Sleep -Milliseconds 500
  }
  if(-not $hasGemma){ throw ('gemma3:4b not discovered in combobox after 120s') }
  $pick=-1; $model=''
  foreach($pref in @('gemma3:4b','qwen2.5-coder:1.5b-base','nemotron-3-nano:4b','llama3.2','bigdaddyg-productivity-local')){
    for($i=0;$i -lt $rows.Count;$i++){
      if($rows[$i] -like "*$pref*"){ $pick=$i; $model=$rows[$i]; break }
    }
    if($pick -ge 0){ break }
  }
  if($pick -lt 0){
    for($i=0;$i -lt $rows.Count;$i++){
      if($rows[$i] -match '(?i)ollama' -and $rows[$i] -notmatch 'connecting'){ $pick=$i; $model=$rows[$i]; break }
    }
  }
  if($pick -lt 0){ throw ('NO_USABLE_MODEL count={0}' -f $rows.Count) }
  [RawrXD_T05Native]::SelectComboIndex($main,$combo,$pick,1206)
  $result.Model=$model
  Start-Sleep -Milliseconds 800

  $promptA='Generate a very long detailed response about C++ build systems. Continue for many paragraphs and do not stop early.'
  $len=[RawrXD_T05Native]::SetEditWmOnly($inputHwnd,$promptA)
  if($len -le 0){ throw 'PROMPT_A_SET_FAILED' }
  [RawrXD_T05Native]::ClickChild($sendHwnd)

  $stopEnabled=$false
  for($i=0;$i -lt 90;$i++){
    Start-Sleep -Milliseconds 500
    $null=Get-Process -Id $s.Pid -ErrorAction Stop
    $stopHwnd=[RawrXD_T05Native]::FindId($main,1210)
    if($stopHwnd -ne [IntPtr]::Zero -and [RawrXD_T05Native]::IsWindowEnabled($stopHwnd)){ $stopEnabled=$true; break }
  }
  if(-not $stopEnabled){ throw 'STOP_NEVER_ENABLED' }
  [RawrXD_T05Native]::ClickChild($stopHwnd)
  $result.CancelObserved=$true
  Start-Sleep -Seconds 3

  $beforeB=''
  try { $beforeB=[RawrXD_T05Native]::Text($outputHwnd) } catch { $beforeB='' }
  if($beforeB -match '\[stopped\]|generation cancelled'){ $result.StopFeedbackObserved=$true }

  $bPrompt = "Reply exactly: $marker"
  $inputHwnd=[RawrXD_T05Native]::FindId($main,1202)
  $sendHwnd=[RawrXD_T05Native]::FindId($main,1204)
  $outputHwnd=[RawrXD_T05Native]::FindId($main,1203)
  $blen=[RawrXD_T05Native]::SetEditWmOnly($inputHwnd,$bPrompt)
  if($blen -le 0){ throw "SET_TEXT_VERIFICATION_FAILED expected=[$bPrompt]" }
  $rb=[RawrXD_T05Native]::Text($inputHwnd)
  if($rb -ne $bPrompt){ throw "SET_TEXT_VERIFICATION_FAILED expected=[$bPrompt] actual=[$rb]" }
  [RawrXD_T05Native]::ClickChild($sendHwnd)
  $result.SecondRequestSent=$true

  $seen=$false; $delta=''
  for($i=0;$i -lt 90;$i++){
    Start-Sleep -Milliseconds 500
    try {
      $null=Get-Process -Id $s.Pid -ErrorAction Stop
      $result.ProcessAlive=$true
      $outputHwnd=[RawrXD_T05Native]::FindId($main,1203)
      $text=[RawrXD_T05Native]::Text($outputHwnd)
      if($beforeB.Length -gt 0 -and $text.Length -ge $beforeB.Length){
        $delta=$text.Substring($beforeB.Length)
      } else { $delta=$text }
      if($delta -match ("(?ms)^AI:.*{0}" -f [regex]::Escape($marker))){
        $seen=$true; $result.MarkerExact=$true; break
      }
      if($text -match '\[stopped\]|generation cancelled'){ $result.StopFeedbackObserved=$true }
    } catch {
      $result.ProcessAlive=$false
      $result.Error=$_.Exception.Message
      break
    }
  }
  $result.TranscriptDelta=$delta
  $result.SecondRequestRecovered=$seen
  if(-not $result.Error){
    try { $null=Get-Process -Id $s.Pid -ErrorAction Stop; $result.ProcessAlive=$true } catch {
      $result.ProcessAlive=$false
      if(-not $result.Error){ $result.Error=$_.Exception.Message }
    }
  }
} catch {
  $result.Error=$_.Exception.Message
  try { $null=Get-Process -Id $s.Pid -ErrorAction Stop; $result.ProcessAlive=$true } catch { $result.ProcessAlive=$false }
} finally {
  $result | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $EvidenceDir 'T05.receipt.json') -Encoding UTF8
  try { Stop-RawrTestProcess $s } catch {}
}
$result | ConvertTo-Json -Depth 8
$pass = $result.CancelObserved -and $result.SecondRequestSent -and $result.SecondRequestRecovered -and $result.ProcessAlive
if(-not $pass){ exit 1 }
exit 0
