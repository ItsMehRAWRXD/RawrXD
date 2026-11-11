$ErrorActionPreference = 'Stop'

# Kill prior hung findstr if still around
foreach ($p in @(14240, 30868, 3284)) {
  try { Stop-Process -Id $p -Force -ErrorAction SilentlyContinue } catch {}
}

# Reconstruct tip formatted prompt with LF (tokenizer path), UTF-8 em-dash (U+2014).
# Tip stdout used CP1252 0x97 for the dash under Windows console redirect; in-memory
# ask string is typically Unicode em-dash. Also write ASCII-hyphen variant for parity check.
$askSys = "You are a helpful assistant. Follow the user's instructions exactly. Reply with the requested text only — no JSON, no tools, no markdown fences."
$user = "Say exactly: AGENT_RESULT=5"
# Tip stdout shows two blank lines between system block and user ask inside the user turn.
$body = $askSys + "`n`n`n" + $user
# Gemma formatGemma does not include literal <bos>; tip print prefixes <bos> for display.
# Pass special-token strings; llama.cpp tokenize parses known specials when present.
$fmtNoBos = "<start_of_turn>user`n" + $body + "<end_of_turn>`n<start_of_turn>model`n"
$fmtWithBosLabel = "<bos>" + $fmtNoBos

$utf8 = New-Object Text.UTF8Encoding $false
[IO.File]::WriteAllText('F:\rawrxd\tmp_trusted_ref\prompt_nobos.txt', $fmtNoBos, $utf8)
[IO.File]::WriteAllText('F:\rawrxd\tmp_trusted_ref\prompt_with_bos_label.txt', $fmtWithBosLabel, $utf8)

# ASCII hyphen variant of tip-bytes dash
$askSysHyphen = $askSys.Replace([char]0x2014, '-')
$fmtHyphen = "<start_of_turn>user`n" + $askSysHyphen + "`n`n`n" + $user + "<end_of_turn>`n<start_of_turn>model`n"
[IO.File]::WriteAllText('F:\rawrxd\tmp_trusted_ref\prompt_nobos_hyphen.txt', $fmtHyphen, $utf8)

$cli = 'F:\rawrxd\tmp_trusted_ref\llama_b12283\llama-cli.exe'
$model = 'F:\rawrxd\gemma3-1b-Q2_K.gguf'
$workdir = 'F:\rawrxd\tmp_trusted_ref\llama_b12283'

function Run-Ref([string]$tag, [string[]]$args) {
  $out = "F:\rawrxd\tmp_trusted_ref\ref_run_$tag.txt"
  Write-Output "=== RUN $tag ==="
  Write-Output ($args -join ' ')
  $p = Start-Process -FilePath $cli -ArgumentList $args -WorkingDirectory $workdir `
    -RedirectStandardOutput $out -RedirectStandardError "F:\rawrxd\tmp_trusted_ref\ref_err_$tag.txt" `
    -PassThru -NoNewWindow
  $ok = $p.WaitForExit(600000)
  if (-not $ok) {
    try { $p.Kill() } catch {}
    Write-Output "TIMEOUT_$tag"
    return
  }
  Write-Output ("EXIT_$tag=" + $p.ExitCode)
  # Copy primary alias
  if ($tag -eq 'primary') {
    Copy-Item $out 'F:\rawrxd\tmp_trusted_ref\ref_run.txt' -Force
    Copy-Item "F:\rawrxd\tmp_trusted_ref\ref_err_$tag.txt" 'F:\rawrxd\tmp_trusted_ref\ref_err.txt' -Force
  }
}

# Primary: no-jinja, file prompt without literal <bos>, greedy, verbose-prompt, single-turnish
# -ngl 0 force CPU; --no-warmup faster start; --simple-io
$common = @(
  '-m', $model,
  '-n', '8',
  '--temp', '0',
  '--top-k', '1',
  '--seed', '1',
  '--no-jinja',
  '--verbose-prompt',
  '-ngl', '0',
  '--no-warmup',
  '--simple-io',
  '-st'
)

Run-Ref 'primary' ($common + @('-f', 'F:\rawrxd\tmp_trusted_ref\prompt_nobos.txt'))
Run-Ref 'boslabel' ($common + @('-f', 'F:\rawrxd\tmp_trusted_ref\prompt_with_bos_label.txt'))
Run-Ref 'hyphen' ($common + @('-f', 'F:\rawrxd\tmp_trusted_ref\prompt_nobos_hyphen.txt'))

# Also try chat-template path matching tip ask (system + user) with jinja/gemma
$chatArgs = @(
  '-m', $model,
  '-n', '8',
  '--temp', '0',
  '--top-k', '1',
  '--seed', '1',
  '--jinja',
  '--chat-template', 'gemma',
  '-sys', $askSys,
  '-p', $user,
  '--verbose-prompt',
  '-ngl', '0',
  '--no-warmup',
  '--simple-io',
  '-st'
)
Run-Ref 'chat' $chatArgs

Write-Output 'ALL_DONE'
