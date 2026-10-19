param([string]$RepoRoot='.')
$patterns=@(
 'PrefetchWorkerThread','PrefetchZoneAsync','PredictNextZones','StartBackgroundLoading',
 'BackgroundLoadThread','prefetchExpert','prefetchPredicted','OnRouterPrediction',
 'FILE_FLAG_SEQUENTIAL_SCAN','MAP_POPULATE','ERROR_IO_PENDING','CreateIoRing','SubmitIoRing'
)
$roots=@('src\deep2','src\streaming','src\streaming_gguf_loader_enhanced.cpp','runtime')
$hits=@()
foreach($r in $roots){$p=Join-Path $RepoRoot $r;if(!(Test-Path $p)){continue};$it=Get-Item $p;$files=if($it.PSIsContainer){Get-ChildItem $p -Recurse -File -Include *.c,*.cpp,*.h,*.hpp}else{@($it)};foreach($f in $files){foreach($pat in $patterns){foreach($m in (Select-String -Path $f.FullName -Pattern $pat -SimpleMatch)){$hits += [pscustomobject]@{File=$f.FullName;Line=$m.LineNumber;Pattern=$pat;Text=$m.Line.Trim()}}}}}
$hits | Sort-Object File,Line,Pattern | Format-Table -AutoSize
"DEEP2_BACKGROUND_IO_SEARCH_HITS=$($hits.Count)"
"NOTE=Search hits are removal/bypass candidates; only control-flow reachability proves a live violation."
