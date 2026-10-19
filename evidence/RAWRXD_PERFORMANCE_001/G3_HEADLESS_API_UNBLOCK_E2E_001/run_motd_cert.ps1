# MOTD + /api/tool gate cert — bodies via files only (no --data-raw).
$ErrorActionPreference = 'Continue'
$base = 'http://127.0.0.1:11435'
$ev = Split-Path -Parent $MyInvocation.MyCommand.Path
$repo = 'G:\~dev\rawrxd'
$exe = Join-Path $repo 'build-fd\bin\RawrXD-Win32IDE.exe'

function Ensure-Headless {
  $listen = Get-NetTCPConnection -LocalPort 11435 -State Listen -ErrorAction SilentlyContinue |
    Select-Object -First 1
  if ($listen) {
    return [int]$listen.OwningProcess
  }
  Get-Process RawrXD-Win32IDE -ErrorAction SilentlyContinue | ForEach-Object {
    try { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue } catch {}
  }
  Start-Sleep -Seconds 1
  $p = Start-Process -FilePath $exe -ArgumentList @(
    '--headless', '--port', '11435', '--dir', $repo
  ) -WorkingDirectory $repo -PassThru -WindowStyle Hidden
  $deadline = (Get-Date).AddSeconds(20)
  while ((Get-Date) -lt $deadline) {
    $l = Get-NetTCPConnection -LocalPort 11435 -State Listen -ErrorAction SilentlyContinue |
      Select-Object -First 1
    if ($l) { return [int]$l.OwningProcess }
    if ($p.HasExited) { throw "Headless exited early code=$($p.ExitCode)" }
    Start-Sleep -Milliseconds 500
  }
  throw 'Headless did not bind :11435'
}

function Http-Get([string]$path) {
  $out = Join-Path $ev ('_g_' + [guid]::NewGuid().ToString('N') + '.bin')
  $code = & curl.exe -sS --max-time 15 -o $out -w '%{http_code}' -H 'Origin: null' "$base$path"
  $body = if (Test-Path -LiteralPath $out) { [IO.File]::ReadAllText($out) } else { '' }
  Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
  [pscustomobject]@{ Code = "$code"; Body = $body }
}

function Http-PostFile([string]$path, [string]$file) {
  $out = Join-Path $ev ('_p_' + [guid]::NewGuid().ToString('N') + '.bin')
  $code = & curl.exe -sS --max-time 60 -o $out -w '%{http_code}' `
    -H 'Origin: null' -H 'Content-Type: application/json' `
    --data-binary "@$file" "$base$path"
  $body = if (Test-Path -LiteralPath $out) { [IO.File]::ReadAllText($out) } else { '' }
  Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue
  [pscustomobject]@{ Code = "$code"; Body = $body }
}

[IO.File]::WriteAllText((Join-Path $ev 'body_list.json'), '{"tool":"list_directory","args":{"path":"."}}')
[IO.File]::WriteAllText((Join-Path $ev 'body_motd_rel.json'), '{"tool":"read_file","args":{"path":".cursor/rules/PassiveRoleNotRoleplay.md"}}')
[IO.File]::WriteAllText((Join-Path $ev 'body_motd_abs.json'), '{"tool":"read_file","args":{"path":"G:/~dev/rawrxd/.cursor/rules/PassiveRoleNotRoleplay.md"}}')
[IO.File]::WriteAllText((Join-Path $ev 'body_gen.json'), '{"prompt":"ping","stream":false}')
[IO.File]::WriteAllText((Join-Path $ev 'body_echo.json'), '{"tool":"execute_command","args":{"command":"echo headless_tool_ok"}}')

$pidOwner = Ensure-Headless
$proc = Get-Process -Id $pidOwner -ErrorAction SilentlyContinue
$health = Http-Get '/health'
$status = Http-Get '/status'
$caps = Http-Get '/api/engine/capabilities'
$tags = Http-Get '/api/tags'
$bunny = Http-Get '/api/nvme/bunnyhop/status'

$cert = New-Object System.Collections.Generic.List[string]
$cert.Add("HEADLESS_PROCESS_ALIVE=$(if ($proc -and -not $proc.HasExited) { '1' } else { '0' })")
$cert.Add("PORT_11435_OWNER=$pidOwner")
$cert.Add("HEALTH_HTTP=$($health.Code)")
$cert.Add("STATUS_HTTP=$($status.Code)")
$cert.Add("CAPS_HTTP=$($caps.Code)")
$cert.Add("TAGS_HTTP=$($tags.Code)")
$cert.Add("BUNNYHOP_STATUS_HTTP=$($bunny.Code)")
$health.Body | Set-Content (Join-Path $ev 'health.body.txt')

$pre = Http-PostFile '/api/tool' (Join-Path $ev 'body_list.json')
$pre.Body | Set-Content (Join-Path $ev 'pre_motd.txt')
$preInvalid = $pre.Body -match 'invalid_json'
$preMotd = $pre.Body -match 'motd_required'
$preExec = $pre.Body -match '"entries"'
$cert.Add("PRE_MOTD_VALID_JSON=$(if (-not $preInvalid) { '1' } else { '0' })")
$cert.Add("PRE_MOTD_TOOL_EXECUTED=$(if ($preExec) { '1' } else { '0' })")
$cert.Add("PRE_MOTD_DISPOSITION=$(if ($preMotd) { 'MOTD_REQUIRED' } elseif ($preInvalid) { 'INVALID_JSON' } else { 'OTHER' })")
$cert.Add("PRE_MOTD_HTTP=$($pre.Code)")

$motd = Http-PostFile '/api/tool' (Join-Path $ev 'body_motd_rel.json')
$motdPath = '.cursor/rules/PassiveRoleNotRoleplay.md'
$motd.Body | Set-Content (Join-Path $ev 'motd_rel.txt')
if ($motd.Code -ne '200' -or $motd.Body -match 'file_not_found') {
  $motd = Http-PostFile '/api/tool' (Join-Path $ev 'body_motd_abs.json')
  $motdPath = 'G:/~dev/rawrxd/.cursor/rules/PassiveRoleNotRoleplay.md'
  $motd.Body | Set-Content (Join-Path $ev 'motd_abs.txt')
}
$motdPass = ($motd.Code -eq '200') -and ($motd.Body -match 'Message of the Day|MOTD gate|PassiveRoleNotRoleplay')
$cert.Add("MOTD_PATH_USED=$motdPath")
$cert.Add("MOTD_READ=$(if ($motdPass) { 'PASS' } else { 'FAIL' })")
$cert.Add("MOTD_ACK=$(if ($motdPass) { '1' } else { '0' })")
$cert.Add("MOTD_HTTP=$($motd.Code)")

$post = Http-PostFile '/api/tool' (Join-Path $ev 'body_list.json')
$post.Body | Set-Content (Join-Path $ev 'post_motd_list.txt')
$postPass = ($post.Code -eq '200') -and ($post.Body -match '"entries"')
$cert.Add("POST_MOTD_LIST_DIRECTORY=$(if ($postPass) { 'PASS' } else { 'FAIL' })")
$cert.Add("POST_MOTD_TOOL_UNLOCKED=$(if ($postPass) { '1' } else { '0' })")
$cert.Add("POST_MOTD_HTTP=$($post.Code)")

$echo = Http-PostFile '/api/tool' (Join-Path $ev 'body_echo.json')
$echo.Body | Set-Content (Join-Path $ev 'post_motd_echo.txt')
$echoPass = ($echo.Code -eq '200') -and ($echo.Body -match 'headless_tool_ok|exitCode')
$cert.Add("POST_MOTD_EXECUTE_COMMAND=$(if ($echoPass) { 'PASS' } else { 'FAIL' })")
$cert.Add("POST_MOTD_EXECUTE_HTTP=$($echo.Code)")

$gen = Http-PostFile '/api/generate' (Join-Path $ev 'body_gen.json')
$gen.Body | Set-Content (Join-Path $ev 'generate_reset.txt')
$cert.Add("GENERATE_RESET_HTTP=$($gen.Code)")

$after = Http-PostFile '/api/tool' (Join-Path $ev 'body_list.json')
$after.Body | Set-Content (Join-Path $ev 'after_generate_tool.txt')
$resetOk = $after.Body -match 'motd_required'
$cert.Add("AFTER_GENERATE_MOTD_ACK=$(if ($resetOk) { '0' } else { '1' })")
$cert.Add("AFTER_GENERATE_DISPOSITION=$(if ($resetOk) { 'MOTD_REQUIRED' } elseif ($after.Body -match 'invalid_json') { 'INVALID_JSON' } elseif ($after.Body -match '"entries"') { 'STILL_UNLOCKED' } else { 'OTHER' })")
$cert.Add("PER_MESSAGE_FAILCLOSED=$(if ($resetOk) { 'PASS' } else { 'FAIL' })")
$cert.Add("AFTER_GENERATE_HTTP=$($after.Code)")

$gate = ($health.Code -eq '200') -and
  ($cert -contains 'PRE_MOTD_DISPOSITION=MOTD_REQUIRED') -and
  ($cert -contains 'PRE_MOTD_VALID_JSON=1') -and
  ($cert -contains 'MOTD_READ=PASS') -and
  ($cert -contains 'POST_MOTD_TOOL_UNLOCKED=1') -and
  ($cert -contains 'PER_MESSAGE_FAILCLOSED=PASS')
$cert.Add("GATE_SEQUENCE=$(if ($gate) { 'PASS' } else { 'FAIL' })")
$cert.Add('NOTE=bodies via --data-binary @file; headless --dir repo root')
$certPath = Join-Path $ev 'CERT.txt'
$cert | Set-Content -LiteralPath $certPath
$cert
if (-not $gate) { exit 1 }
exit 0
