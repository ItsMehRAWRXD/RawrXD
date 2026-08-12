$bytes = [IO.File]::ReadAllBytes('d:\rawrxd\build-ninja\bin\rawrxd.exe')
$text = [Text.Encoding]::ASCII.GetString($bytes)
$symbols = @('Profiler_Initialize','Profiler_SetBatchContext','Profiler_ReadTsc','Profiler_TrackCall','Profiler_AnalyzeBottlenecks')
foreach ($sym in $symbols) {
    $found = $text.Contains($sym)
    Write-Host "$sym : $found"
}
