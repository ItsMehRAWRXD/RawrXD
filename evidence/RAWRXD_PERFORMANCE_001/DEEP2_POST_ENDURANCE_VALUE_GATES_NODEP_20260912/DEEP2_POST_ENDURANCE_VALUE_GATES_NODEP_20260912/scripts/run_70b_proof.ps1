param(
  [Parameter(Mandatory=$true)][string]$ModelPath,
  [string]$Rawr = "G:\~dev\rawrxd\build-fd\bin\rawr.exe",
  [string]$ModelName = "",
  [string]$Evidence = "G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\DEEP2_70B_CONSTRAINED_EXTERNAL_001",
  [int]$Tokens = 64,
  [int]$Trials = 3,
  [string]$CompetitorExe = "",
  [string]$CompetitorArgsTemplate = "-m {MODEL} -p {PROMPT} -n {TOKENS}"
)
$ErrorActionPreference = "Stop"
if ($Trials -lt 3) { throw "Trials must be >=3 for authority." }
New-Item -ItemType Directory -Force -Path $Evidence | Out-Null
if (-not (Test-Path $ModelPath)) { throw "ModelPath not found: $ModelPath" }
if ([string]::IsNullOrWhiteSpace($ModelName)) { $ModelName = $ModelPath }
$modelHash = (Get-FileHash -Algorithm SHA256 $ModelPath).Hash.ToLowerInvariant()
$prompts = @(
  "Explain why locality matters for autoregressive decoding in under 120 words.",
  "Write a short C++ function that clamps an integer without using templates.",
  "Summarize the tradeoff between quantization error and memory bandwidth in under 120 words."
)
$promptFile = Join-Path $Evidence "prompts.txt"; $prompts | Set-Content -Encoding UTF8 $promptFile
$promptHash = (Get-FileHash -Algorithm SHA256 $promptFile).Hash.ToLowerInvariant()
function Median([double[]]$v){$s=@($v|Sort-Object);if(!$s.Count){return 0.0};if($s.Count%2){return [double]$s[[int]($s.Count/2)]};return([double]$s[$s.Count/2-1]+[double]$s[$s.Count/2])/2.0}
function Parse-DevicePeak([string]$stderr){
  $vals=@(); foreach($pat in @('GPU_RESIDENT_BYTES=(\d+)','VRAM_USED_BYTES=(\d+)','GPU0_RESIDENT_BYTES=(\d+)','GPU1_RESIDENT_BYTES=(\d+)')){[regex]::Matches($stderr,$pat)|ForEach-Object{$vals += [int64]$_.Groups[1].Value}}
  if($vals.Count){return [int64](($vals|Measure-Object -Maximum).Maximum)}; return [int64]-1
}
function Run-RawrTrial([int]$i,[string]$prompt){
  $out=Join-Path $Evidence ("rawr_{0:00}.stdout.txt" -f $i);$err=Join-Path $Evidence ("rawr_{0:00}.stderr.txt" -f $i)
  $args=@('run',$ModelName,$prompt,'-n',[string]$Tokens)
  $sw=[Diagnostics.Stopwatch]::StartNew();$p=Start-Process -FilePath $Rawr -ArgumentList $args -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
  $peakWs=0L;$peakPm=0L
  while(-not $p.HasExited){$p.Refresh();if($p.WorkingSet64 -gt $peakWs){$peakWs=$p.WorkingSet64};if($p.PrivateMemorySize64 -gt $peakPm){$peakPm=$p.PrivateMemorySize64};Start-Sleep -Milliseconds 100}
  $p.WaitForExit();$sw.Stop();$stderr=if(Test-Path $err){Get-Content $err -Raw}else{""}
  $gen=if($stderr -match 'GENERATED_TOKENS=(\d+)'){[int]$Matches[1]}elseif($stderr -match 'TOKENS_COMMITTED=(\d+)'){[int]$Matches[1]}else{$Tokens}
  $retries=if($stderr -match 'GENERATION_RETRIES=(\d+)'){[int]$Matches[1]}else{0};$mock=if($stderr -match 'MOCK_BACKEND=1'){1}else{0};$dev=Parse-DevicePeak $stderr
  [pscustomobject]@{ENGINE='rawr';TRIAL=$i;EXIT=$p.ExitCode;WALL_NS=[int64]($sw.Elapsed.TotalMilliseconds*1000000);GENERATED_TOKENS=$gen;TPS=$(if($sw.Elapsed.TotalSeconds -gt 0){$gen/$sw.Elapsed.TotalSeconds}else{0});RETRIES=$retries;MOCK=$mock;PEAK_WORKING_SET_BYTES=$peakWs;PEAK_PRIVATE_BYTES=$peakPm;PEAK_DEVICE_BYTES=$dev}
}
$warmup=Run-RawrTrial 0 $prompts[0]
$rows=@();for($i=1;$i -le $Trials;$i++){$rows += Run-RawrTrial $i $prompts[($i-1)%$prompts.Count]}
$rows|Export-Csv -NoTypeInformation (Join-Path $Evidence 'rawr_trials.csv')
$median=Median @($rows.TPS);$bad=@($rows|Where-Object{$_.EXIT-ne 0-or$_.GENERATED_TOKENS-le 0-or$_.RETRIES-ne 0-or$_.MOCK-ne 0}).Count
$peakHost=[int64](($rows.PEAK_WORKING_SET_BYTES|Measure-Object -Maximum).Maximum);$deviceKnown=@($rows|Where-Object{$_.PEAK_DEVICE_BYTES-ge 0});$peakDev=if($deviceKnown.Count){[int64](($deviceKnown.PEAK_DEVICE_BYTES|Measure-Object -Maximum).Maximum)}else{[int64]-1}
$compStatus='NOT_RUN';$compMedian=0.0
if($CompetitorExe -and (Test-Path $CompetitorExe)){$comp=@();for($i=1;$i-le$Trials;$i++){$pp=$prompts[($i-1)%$prompts.Count];$aa=$CompetitorArgsTemplate.Replace('{MODEL}',('"'+$ModelPath+'"')).Replace('{PROMPT}',('"'+$pp+'"')).Replace('{TOKENS}',[string]$Tokens);$o=Join-Path $Evidence ("competitor_{0:00}.stdout.txt"-f$i);$e=Join-Path $Evidence ("competitor_{0:00}.stderr.txt"-f$i);$sw=[Diagnostics.Stopwatch]::StartNew();$cp=Start-Process -FilePath $CompetitorExe -ArgumentList $aa -Wait -PassThru -RedirectStandardOutput $o -RedirectStandardError $e;$sw.Stop();$comp += [pscustomobject]@{TRIAL=$i;EXIT=$cp.ExitCode;WALL_NS=[int64]($sw.Elapsed.TotalMilliseconds*1000000);TPS_WALL_LOWER_BOUND=$(if($sw.Elapsed.TotalSeconds-gt 0){$Tokens/$sw.Elapsed.TotalSeconds}else{0})}};$comp|Export-Csv -NoTypeInformation (Join-Path $Evidence 'competitor_trials.csv');$compStatus=if(@($comp|Where-Object{$_.EXIT-ne 0}).Count-eq 0){'PASS'}else{'FAIL'};$compMedian=Median @($comp.TPS_WALL_LOWER_BOUND)}
$receipt=@('GATE=DEEP2_70B_CONSTRAINED_EXTERNAL_001',"MODEL_PATH=$ModelPath","MODEL_SHA256=$modelHash","PROMPT_CORPUS_SHA256=$promptHash","TRIALS=$Trials",'WARMUP_EXCLUDED=1',"TOKENS_PER_TRIAL=$Tokens",('TPS_MEDIAN={0:N6}'-f$median),"PEAK_HOST_BYTES=$peakHost",$(if($peakDev-ge 0){"PEAK_DEVICE_BYTES=$peakDev"}else{'PEAK_DEVICE_BYTES=UNAVAILABLE'}),"RAW_TRIAL_FAILURES=$bad","COMPETITOR=$compStatus",('COMPETITOR_TPS_WALL_LOWER_BOUND_MEDIAN={0:N6}'-f$compMedian),$(if($CompetitorExe){'SAME_GGUF_COMPETITOR_WHERE_SUPPORTED=1'}else{'SAME_GGUF_COMPETITOR_WHERE_SUPPORTED=0'}),'PROMOTE=0')
$receipt|Set-Content (Join-Path $Evidence 'RECEIPT.txt');$receipt;if($bad-ne 0){exit 20};exit 0
