$ErrorActionPreference = 'Continue'
$gate = 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_STREAMER_AGENTIC_IDE_PARITY_001'
$local = 'C:\Users\Garrett\AppData\Local\Temp\RawrXD-Win32IDE.exe'
$port = 11440
$wd = 'G:\~dev\rawrxd'
$motdAbs = 'G:\~dev\rawrxd\.cursor\rules\PassiveRoleNotRoleplay.md'
$out = Join-Path $gate 'server4.out.txt'
$err = Join-Path $gate 'server4.err.txt'

Get-Process RawrXD-Win32IDE -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep 1

$p = Start-Process -FilePath $local `
  -ArgumentList @('--headless','--local','--port',"$port",'--bind','127.0.0.1','--working-dir',$wd) `
  -PassThru -RedirectStandardOutput $out -RedirectStandardError $err -WindowStyle Hidden

$ready = $false
for ($i = 0; $i -lt 40; $i++) {
  Start-Sleep 1
  if ($p.HasExited) {
    Write-Host "EARLY_EXIT=$($p.ExitCode)"
    Get-Content $err -Tail 40
    exit 1
  }
  try {
    $h = Invoke-WebRequest "http://127.0.0.1:$port/health" -UseBasicParsing -TimeoutSec 2
    if ($h.StatusCode -eq 200) { $ready = $true; Write-Host "HEALTH_OK_SEC=$i"; break }
  } catch {}
}
if (-not $ready) { Write-Host 'NO_HEALTH'; exit 1 }

function Post-Tool([string]$tool, [hashtable]$argsMap) {
  $payload = @{ tool = $tool; args = $argsMap }
  $json = $payload | ConvertTo-Json -Compress -Depth 8
  try {
    $r = Invoke-WebRequest -Uri "http://127.0.0.1:$port/api/tool" -Method POST `
      -Body ([System.Text.Encoding]::UTF8.GetBytes($json)) `
      -ContentType 'application/json; charset=utf-8' -UseBasicParsing -TimeoutSec 45
    return "STATUS=$($r.StatusCode)`n$($r.Content)"
  } catch {
    $resp = $_.Exception.Response
    if ($resp) {
      $sr = New-Object System.IO.StreamReader($resp.GetResponseStream())
      $c = $sr.ReadToEnd()
      $sr.Close()
      return "STATUS=$([int]$resp.StatusCode)`n$c"
    }
    return "STATUS=-1`n$($_.Exception.Message)"
  }
}

$pre = Post-Tool 'list_directory' @{ path = '.cursor/rules' }
[System.IO.File]::WriteAllText((Join-Path $gate 'pre_motd.txt'), $pre)

$motd1 = Post-Tool 'read_motd' @{}
[System.IO.File]::WriteAllText((Join-Path $gate 'motd_read_motd.txt'), $motd1)

$motd2 = Post-Tool 'read_file' @{ path = $motdAbs }
[System.IO.File]::WriteAllText((Join-Path $gate 'motd_read_abs.txt'), $motd2)

$post = Post-Tool 'list_directory' @{ path = '.cursor/rules' }
[System.IO.File]::WriteAllText((Join-Path $gate 'post_motd_list.txt'), $post)

$cli = Post-Tool 'execute_command' @{ command = 'echo TOOL_LOOP_OK' }
[System.IO.File]::WriteAllText((Join-Path $gate 'post_motd_cli.txt'), $cli)

$ver = (Invoke-WebRequest "http://127.0.0.1:$port/api/version" -UseBasicParsing).Content
$bh = (Invoke-WebRequest "http://127.0.0.1:$port/api/nvme/bunnyhop/status" -UseBasicParsing).Content
[System.IO.File]::WriteAllText((Join-Path $gate 'version.txt'), $ver)
[System.IO.File]::WriteAllText((Join-Path $gate 'bunnyhop_status.txt'), $bh)

$preOk = ($pre -match 'STATUS=403') -and ($pre -match 'motd_required')
$motdOk = (($motd1 -match 'STATUS=200') -or ($motd2 -match 'STATUS=200')) -and (($motd1 + $motd2) -match 'PassiveRoleNotRoleplay')
$listOk = ($post -match 'STATUS=200') -and ($post -match 'StreamerAgenticContinueEnsure')
$cliOk = ($cli -match 'STATUS=200') -and ($cli -match 'TOOL_LOOP_OK')
$pass = $preOk -and $motdOk -and $listOk -and $cliOk

Write-Host "TOOL_PARITY_PASS=$pass preOk=$preOk motdOk=$motdOk listOk=$listOk cliOk=$cliOk"
Write-Host ("PRE=" + $pre.Substring(0, [Math]::Min(140, $pre.Length)))
Write-Host ("MOTD1=" + $motd1.Substring(0, [Math]::Min(140, $motd1.Length)))
Write-Host ("MOTD2=" + $motd2.Substring(0, [Math]::Min(140, $motd2.Length)))
Write-Host ("LIST=" + $post.Substring(0, [Math]::Min(140, $post.Length)))
Write-Host ("CLI=" + $cli.Substring(0, [Math]::Min(140, $cli.Length)))

Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
if ($pass) { exit 0 } else { exit 2 }
