Set-Location F:\~dev\rawrxd
cmake --build "F:\~dev\rawrxd\build_w1" --config Release --target RawrXD-Win32IDE 2>&1 | Out-File F:\~dev\_w8_build2.txt -Encoding UTF8
"BUILD_EXIT=$LASTEXITCODE" | Out-File F:\~dev\_w8_build2_done.txt -Encoding ASCII
