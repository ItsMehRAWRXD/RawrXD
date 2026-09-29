Set-Location F:\~dev\rawrxd
Remove-Item build_w1\bin\Release\RawrXD-Win32IDE.pdb -Force -ErrorAction SilentlyContinue
cmake --build build_w1 --config Release --target RawrXD-Win32IDE 2>&1 | Out-File F:\~dev\_w1_build41.txt -Encoding UTF8
"BUILD_EXIT=$LASTEXITCODE" | Out-File F:\~dev\_w1_build41_done.txt -Encoding ASCII
