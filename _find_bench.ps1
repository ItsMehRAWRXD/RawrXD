$exe = Get-ChildItem `
    "F:\~dev\rawrxd","G:\~dev\rawrxd","F:\~dev","G:\~dev" `
    -Filter deep2_benchmark.exe -File -Recurse -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

$model = Get-ChildItem `
    "G:\OllamaModels","D:\rawrxd","F:\models" `
    -Filter *.gguf -File -Recurse -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Name -match 'nemotron' -and
        ($_.Name -match '30b|3\.5|lightning')
    } |
    Sort-Object Length -Descending |
    Select-Object -First 1

"`n=== DEEP2 ==="
$exe | Select-Object FullName,Length,LastWriteTime

"`n=== MODEL ==="
$model | Select-Object FullName,Length,LastWriteTime
