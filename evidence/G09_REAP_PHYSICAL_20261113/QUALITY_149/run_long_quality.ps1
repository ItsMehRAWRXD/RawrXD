$ErrorActionPreference = "Continue"
$ev = "F:\rawrxd\evidence\G09_REAP_PHYSICAL_20261113"
$qd = Join-Path $ev "QUALITY_149"
$exe = "G:\~dev\rawrxd\build_ninja\bin\rawr_149_rebound.exe"
$model = "F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M\Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf"
$coding = "Write a complete Python function is_prime(n) that returns True iff n is prime. Include a short docstring, handle n less than 2, and add three assert self-checks for 2, 17, and 1. Output only the function and asserts — no markdown."
$reasoning = "A bat and a ball cost `$1.10 in total. The bat costs `$1.00 more than the ball. How much does the ball cost? Show each algebraic step, then give the final answer on its own line as ANSWER: <dollars>."

function Invoke-QualityArm {
  param($Tag, $Retained, $Prompt, $N)
  $stamp = Get-Date -Format o
  $out = Join-Path $qd ("long_{0}.out.txt" -f $Tag)
  $err = Join-Path $qd ("long_{0}.err.txt" -f $Tag)
  $json = Join-Path $qd ("long_{0}.json" -f $Tag)
  $trace = Join-Path $qd ("long_{0}.tokens.txt" -f $Tag)
  $meta = Join-Path $qd ("long_{0}.meta.txt" -f $Tag)
  "START=$stamp TAG=$Tag RETAINED=$Retained N=$N" | Set-Content $meta
  $env:WEIGHT_BUDGET = "E8B0M"
  $env:RAWRXD_GREEDY = "1"
  $env:RAWRXD_NO_TP = "1"
  $env:DEEP2_GEN_QUALITY_TRACE = $trace
  if ($Retained -gt 0) { $env:RAWRXD_REAP_RETAINED = "$Retained" } else { Remove-Item Env:RAWRXD_REAP_RETAINED -ErrorAction SilentlyContinue }
  if (Test-Path $trace) { Remove-Item $trace -Force }
  $args = @("run", $model, "--reap", "30GB/8", "-p", $Prompt, "--max-tokens", "$N", "--receipt", $json)
  $p = Start-Process -FilePath $exe -ArgumentList $args -NoNewWindow -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
  $p.WaitForExit()
  $end = Get-Date -Format o
  "END=$end EXIT=$($p.ExitCode)" | Add-Content $meta
  "DONE TAG=$Tag EXIT=$($p.ExitCode) END=$end" | Add-Content (Join-Path $qd "LONG_RUN_PROGRESS.txt")
}

"LONG_RUN_START=$(Get-Date -Format o)" | Set-Content (Join-Path $qd "LONG_RUN_PROGRESS.txt")
Invoke-QualityArm -Tag "coding_149" -Retained 149 -Prompt $coding -N 48
Invoke-QualityArm -Tag "reasoning_149" -Retained 149 -Prompt $reasoning -N 32
Invoke-QualityArm -Tag "coding_r8" -Retained 0 -Prompt $coding -N 48
Invoke-QualityArm -Tag "reasoning_r8" -Retained 0 -Prompt $reasoning -N 32
"LONG_RUN_END=$(Get-Date -Format o)" | Add-Content (Join-Path $qd "LONG_RUN_PROGRESS.txt")
