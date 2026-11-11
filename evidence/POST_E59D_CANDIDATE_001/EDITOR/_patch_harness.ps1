#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
$h = 'F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\EDITOR\editor_requal.ps1'
$c = Get-Content -LiteralPath $h -Raw

$newSaveAs = @'
function Invoke-SaveAs([IntPtr]$main,[Diagnostics.Process]$proc,[string]$path){
  [void](Dismiss-SavePromptOnly ([uint32]$proc.Id) 7)
  [void][PostE59dEdit]::PostMessageW($main,[PostE59dEdit]::WM_COMMAND,[IntPtr][PostE59dEdit]::IDM_FILE_SAVEAS,[IntPtr]::Zero)
  $dlg=[IntPtr]::Zero; $deadline=(Get-Date).AddSeconds(15)
  while((Get-Date) -lt $deadline){
    if($proc.HasExited){ return $false }
    $dlg=[PostE59dEdit]::FindDialogByTitle([uint32]$proc.Id,'Save')
    if($dlg -eq [IntPtr]::Zero){ $dlg=[PostE59dEdit]::FindAnyDialog([uint32]$proc.Id) }
    if($dlg -ne [IntPtr]::Zero){ $t=[PostE59dEdit]::TitleOf($dlg); if($t -notmatch 'Unsaved'){break} }
    Start-Sleep -Milliseconds 150
  }
  if($dlg -eq [IntPtr]::Zero){ WLog 'SAVEAS_NO_DIALOG'; return $false }
  WLog ("SAVEAS_DLG title='{0}'" -f [PostE59dEdit]::TitleOf($dlg))
  [void][PostE59dEdit]::DriveFileDialog($dlg,$path); Start-Sleep -Milliseconds 1000
  $ow=[PostE59dEdit]::FindAnyDialog([uint32]$proc.Id)
  if($ow -ne [IntPtr]::Zero){
    $ot=[PostE59dEdit]::TitleOf($ow)
    if($ot -ne 'Save As' -and $ot -ne 'Open' -and $ot -notmatch 'Save As'){ WLog ("SAVEAS_CONFIRM title='{0}'" -f $ot); [PostE59dEdit]::ClickDialog($ow,6); Start-Sleep -Milliseconds 500 }
    else { WLog ("SAVEAS_RETRY_ENTER title='{0}'" -f $ot); [PostE59dEdit]::SetForegroundWindow($ow); [PostE59dEdit]::PressEnter(); Start-Sleep -Milliseconds 800 }
  }
  [void](Wait-NoDialog ([uint32]$proc.Id) 8000)
  $ok = Test-Path -LiteralPath $path
  WLog "SAVEAS_RESULT ok=$ok path=$path"
  return ,$ok
}
'@

$newOpen = @'
function Invoke-Open([IntPtr]$main,[Diagnostics.Process]$proc,[string]$path){
  if([PostE59dEdit]::SaveMenuEnabled($main)){
    [void][PostE59dEdit]::PostMessageW($main,[PostE59dEdit]::WM_COMMAND,[IntPtr][PostE59dEdit]::IDM_FILE_NEW,[IntPtr]::Zero)
    Start-Sleep -Milliseconds 400; [void](Dismiss-SavePromptOnly ([uint32]$proc.Id) 7); Start-Sleep -Milliseconds 300
  }
  [void][PostE59dEdit]::PostMessageW($main,[PostE59dEdit]::WM_COMMAND,[IntPtr][PostE59dEdit]::IDM_FILE_OPEN,[IntPtr]::Zero)
  Start-Sleep -Milliseconds 400; [void](Dismiss-SavePromptOnly ([uint32]$proc.Id) 7)
  $dlg=[IntPtr]::Zero; $deadline=(Get-Date).AddSeconds(15)
  while((Get-Date) -lt $deadline){
    if($proc.HasExited){ return $false }
    $dlg=[PostE59dEdit]::FindDialogByTitle([uint32]$proc.Id,'Open')
    if($dlg -eq [IntPtr]::Zero){
      $any=[PostE59dEdit]::FindAnyDialog([uint32]$proc.Id)
      if($any -ne [IntPtr]::Zero){
        $t=[PostE59dEdit]::TitleOf($any)
        if($t -match 'Unsaved|Save Changes|modified'){ [PostE59dEdit]::ClickDialog($any,7); Start-Sleep -Milliseconds 300; continue }
        if($t -eq '' -or $t -match 'Open'){ $dlg=$any; break }
      }
    } else { break }
    Start-Sleep -Milliseconds 150
  }
  if($dlg -eq [IntPtr]::Zero){ WLog 'OPEN_NO_DIALOG'; return $false }
  WLog ("OPEN_DLG title='{0}' path=$path" -f [PostE59dEdit]::TitleOf($dlg))
  [void][PostE59dEdit]::DriveFileDialog($dlg,$path); [void](Wait-NoDialog ([uint32]$proc.Id) 8000); Start-Sleep -Milliseconds 400
  $title=[PostE59dEdit]::TitleOf($main); $leaf=[IO.Path]::GetFileName($path)
  $ok = ($title.IndexOf($leaf,[StringComparison]::OrdinalIgnoreCase) -ge 0)
  WLog "OPEN_RESULT ok=$ok title='$title'"
  return ,$ok
}
'@

$c = [regex]::Replace($c, '(?s)function Invoke-SaveAs\([^\)]*\)\{.*?\r?\n\}(?=\r?\nfunction Invoke-Open)', ($newSaveAs.TrimEnd() + "`r`n"))
$c = [regex]::Replace($c, '(?s)function Invoke-Open\([^\)]*\)\{.*?\r?\n\}(?=\r?\nfunction Invoke-Save)', ($newOpen.TrimEnd() + "`r`n"))

# Unicode input: prefer SetEditorText
$oldPaste = @'
  [void][PostE59dEdit]::SetClipboardText($payload)
  [PostE59dEdit]::SetEditorText($editor,'')
  Start-Sleep -Milliseconds 100
  [PostE59dEdit]::PasteIntoEditor($editor)
'@
$newPaste = @'
  [PostE59dEdit]::SetEditorText($editor,$payload)
  Start-Sleep -Milliseconds 200
  $probe=[PostE59dEdit]::GetEditorText($editor)
  if(-not ($probe -match 'caf' -and $probe.Contains([char]0x6771))){
    WLog 'unicode_settext_weak_fallback_clipboard'
    [void][PostE59dEdit]::SetClipboardText($payload)
    [PostE59dEdit]::SetEditorText($editor,'')
    Start-Sleep -Milliseconds 100
    [PostE59dEdit]::PasteIntoEditor($editor)
  }
'@
if ($c.Contains('[void][PostE59dEdit]::SetClipboardText($payload)')) {
  $c = $c.Replace($oldPaste, $newPaste)
}

# Harden unicode save branch
$oldBranch = @'
  if(-not (Invoke-SaveAs $main $proc $uPath)){
    $results.UNICODE_SAVE_REOPEN='FAIL_SAVEAS'
  } else {
    $disk=[IO.File]::ReadAllBytes($uPath)
'@
$newBranch = @'
  $saveOk = [bool](Invoke-SaveAs $main $proc $uPath)
  if(-not $saveOk -or -not (Test-Path -LiteralPath $uPath)){
    $results.UNICODE_SAVE_REOPEN='FAIL_SAVEAS'
    WLog "unicode_saveas_failed saveOk=$saveOk exists=$((Test-Path -LiteralPath $uPath))"
  } else {
    $disk=[IO.File]::ReadAllBytes($uPath)
'@
if ($c.Contains($oldBranch)) {
  $c = $c.Replace($oldBranch, $newBranch)
} else {
  Write-Host 'WARN: unicode branch pattern not exact; applying loose replace'
  $c = [regex]::Replace($c,
    'if\(-not \(Invoke-SaveAs \$main \$proc \$uPath\)\)\{\s*\$results\.UNICODE_SAVE_REOPEN=''FAIL_SAVEAS''\s*\} else \{\s*\$disk=\[IO\.File\]::ReadAllBytes\(\$uPath\)',
    ($newBranch -replace '\$','$$$$'))
}

Set-Content -LiteralPath $h -Value $c -Encoding UTF8
Write-Host "PATCHED bytes=$((Get-Item $h).Length)"
Select-String -Path $h -Pattern 'SAVEAS_RESULT|unicode_settext_weak|unicode_saveas_failed|return ,\$ok' |
  ForEach-Object { $_.Line.Trim() }
