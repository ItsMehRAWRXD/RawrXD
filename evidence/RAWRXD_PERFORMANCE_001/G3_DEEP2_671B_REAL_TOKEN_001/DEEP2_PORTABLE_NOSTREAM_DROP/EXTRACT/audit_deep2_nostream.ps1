param([string]$Root='.')
$patterns=@(
 'PrefetchZoneAsync\s*\(', 'PrefetchWorkerThread\s*\(', 'StartBackgroundLoading\s*\(',
 'BackgroundLoadThread\s*\(', 'PrefetchExpert\s*\(', 'prefetchExpert\s*\(',
 'prefetchPredicted\s*\(', 'OnRouterPrediction\s*\(', 'FILE_FLAG_SEQUENTIAL_SCAN',
 'MAP_POPULATE', 'ERROR_IO_PENDING', 'std::thread\s*\(', 'std::async\s*\('
)
$targets=@('src/deep2','src/streaming','src/streaming_gguf_loader.cpp','src/streaming_gguf_loader_enhanced.cpp','runtime')
$hits=@()
foreach($t in $targets){$p=Join-Path $Root $t;if(Test-Path $p){
 $items=if((Get-Item $p).PSIsContainer){Get-ChildItem $p -Recurse -File -Include *.c,*.cpp,*.h,*.hpp}else{Get-Item $p}
 foreach($f in $items){foreach($pat in $patterns){$m=Select-String -Path $f.FullName -Pattern $pat;foreach($x in $m){$hits += [pscustomobject]@{File=$f.FullName;Line=$x.LineNumber;Pattern=$pat;Text=$x.Line.Trim()}}}}
}}
$hits | Sort-Object File,Line | Format-Table -AutoSize
"DEEP2_BACKGROUND_STREAMING_RESIDUAL_COUNT=$($hits.Count)"
if($hits.Count){exit 1}else{exit 0}
