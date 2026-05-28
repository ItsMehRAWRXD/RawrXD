$bench = 'D:\llama-vulkan\build\bin\llama-bench.exe'
$out   = 'd:\rawrxd\bench\out'
New-Item -ItemType Directory -Force -Path $out | Out-Null

$models = @(
    'D:\tinyllama_fresh.gguf',
    'D:\phi3mini.gguf',
    'D:\codestral22b.gguf'
)

foreach ($p in $models) {
    $name = [IO.Path]::GetFileNameWithoutExtension($p)
    Write-Host ""
    Write-Host "==== $name ===="
    $log = Join-Path $out ("{0}_full.log" -f $name)
    & $bench -m $p -ngl 99 -r 5 -p 512 -n 128 2>&1 | Tee-Object $log | Select-Object -Last 10
}
