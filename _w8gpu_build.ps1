Set-Location F:\~dev\rawrxd
cmake --build "F:\~dev\rawrxd\build_w1" --config Release --target RawrXD-Win32IDE -j 2 2>&1 | Out-File F:\~dev\_w8gpu_build_log.txt -Encoding UTF8
"BUILD_EXIT=$LASTEXITCODE" | Out-File F:\~dev\_w8gpu_build_done.txt -Encoding ASCII
