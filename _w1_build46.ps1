Set-Location F:\~dev\rawrxd
cmake --build "F:\~dev\rawrxd\build_w1" --config Release --target RawrXD-Win32IDE -j 4 2>&1 | Out-File F:\~dev\_w1_build46.txt -Encoding UTF8
"BUILD_EXIT=$LASTEXITCODE" | Out-File F:\~dev\_w1_build46_done.txt -Encoding ASCII
