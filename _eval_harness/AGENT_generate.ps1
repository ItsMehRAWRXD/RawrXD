param(
  [string]$Model = "bigdaddygnative:latest",
  [string]$Prompt = "",
  [int]$NumPredict = 160,
  [int]$NumCtx = 8192,
  [double]$Temperature = 0.4
)
if ([string]::IsNullOrWhiteSpace($Prompt)) {
  $Prompt = "Question: A bat and a ball cost 110 dollars in total. The bat costs 100 dollars more than the ball. How much does the ball cost? Think step by step, then give the final number."
}
$opts = @{
  temperature    = $Temperature
  num_predict    = $NumPredict
  num_ctx        = $NumCtx
  top_p          = 0.95
  top_k          = 50
  repeat_penalty = 1.05
}
$body = @{ model = $Model; prompt = $Prompt; stream = $false; options = $opts } | ConvertTo-Json -Depth 5
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$r = Invoke-RestMethod -Uri "http://localhost:11434/api/generate" -Method POST -Body $body -ContentType "application/json" -TimeoutSec 1200
$sw.Stop()
$modelLoad = if ($r.load_duration) { [math]::Round(($r.load_duration)/1e9,2) } else { 0 }
$evalSec = if ($r.eval_duration) { [math]::Round(($r.eval_duration)/1e9,2) } else { 0 }
$totalSec = if ($r.total_duration) { [math]::Round(($r.total_duration)/1e9,2) } else { 0 }
$tps = if ($r.eval_duration -and $r.eval_duration -gt 0) { [math]::Round(1e9/$r.eval_duration,2) } else { 0 }
Write-Output "MODEL=$Model"
Write-Output "WALL_SEC=$([math]::Round($sw.Elapsed.TotalSeconds,1)) LOAD_S=$modelLoad EVAL_S=$evalSec TOTAL_S=$totalSec EVAL_COUNT=$($r.eval_count) TOK_PER_SEC=$tps"
Write-Output "----RESPONSE_BEGIN----"
Write-Output $r.response
Write-Output "----RESPONSE_END----"
