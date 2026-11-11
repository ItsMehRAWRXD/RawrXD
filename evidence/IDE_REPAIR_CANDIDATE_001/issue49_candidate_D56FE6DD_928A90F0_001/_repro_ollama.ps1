$ErrorActionPreference = 'Stop'
$out = 'F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_candidate_D56FE6DD_928A90F0_001\_ollama_repro_raw.json'
$payload = @{
  model = 'qwen3:8b'
  stream = $false
  think = $false
  options = @{ temperature = 0.2; num_predict = 512; num_ctx = 4096 }
  messages = @(
    @{
      role = 'system'
      content = "You are the RawrXD autonomous coding agent. Use exactly one tool command per reply, with no prose.`nYour FIRST tokens MUST be the literal prefix TOOL (T-O-O-L then space).`nAllowed commands:`nTOOL read <relative-path>`nTOOL write <relative-path> @@<complete-file-content>@@`nTOOL build`nTOOL test`nTOOL finish`nFew-shot legal replies (one per turn):`nTOOL read bug.cpp"
    }
    @{
      role = 'user'
      content = 'Inspect bug.cpp and reply with exactly one TOOL command. Start with TOOL read bug.cpp'
    }
  )
} | ConvertTo-Json -Depth 8 -Compress

try {
  $resp = Invoke-WebRequest -Uri 'http://127.0.0.1:11434/api/chat' -Method POST -ContentType 'application/json; charset=utf-8' -Body ([System.Text.Encoding]::UTF8.GetBytes($payload)) -TimeoutSec 600
  $raw = $resp.Content
  [System.IO.File]::WriteAllText($out, $raw, [System.Text.UTF8Encoding]::new($false))
  "HTTP=$($resp.StatusCode)" | Out-File 'F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_candidate_D56FE6DD_928A90F0_001\_ollama_repro_meta.txt' -Encoding utf8
  "BODY_BYTES=$($raw.Length)" | Out-File 'F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_candidate_D56FE6DD_928A90F0_001\_ollama_repro_meta.txt' -Append -Encoding utf8
  $j = $raw | ConvertFrom-Json
  $content = [string]$j.message.content
  $thinking = [string]$j.message.thinking
  $tools = $j.message.tool_calls
  "content_len=$($content.Length)" | Out-File 'F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_candidate_D56FE6DD_928A90F0_001\_ollama_repro_meta.txt' -Append -Encoding utf8
  "thinking_len=$($thinking.Length)" | Out-File 'F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_candidate_D56FE6DD_928A90F0_001\_ollama_repro_meta.txt' -Append -Encoding utf8
  "tool_calls=$($null -ne $tools)" | Out-File 'F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_candidate_D56FE6DD_928A90F0_001\_ollama_repro_meta.txt' -Append -Encoding utf8
  "CONTENT<<<$content>>>" | Out-File 'F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_candidate_D56FE6DD_928A90F0_001\_ollama_repro_meta.txt' -Append -Encoding utf8
  Write-Output 'REPRO_OK'
} catch {
  $_ | Out-File 'F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_candidate_D56FE6DD_928A90F0_001\_ollama_repro_meta.txt' -Encoding utf8
  Write-Output 'REPRO_FAIL'
  throw
}