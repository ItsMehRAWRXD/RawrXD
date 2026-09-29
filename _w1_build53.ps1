Set-Location F:\~dev\rawrxd
Remove-Item "F:\~dev\rawrxd\build_w1\bin\Release\RawrXD-Win32IDE.pdb" -Force -ErrorAction SilentlyContinue
Remove-Item "F:\~dev\rawrxd\build_w1\bin\Release\RawrXD-Win32IDE.exe" -Force -ErrorAction SilentlyContinue
cmake --build "F:\~dev\rawrxd\build_w1" --config Release --target RawrXD-Win32IDE -j 2 2>&1 | Out-File F:\~dev\_w1_build53.txt -Encoding UTF8
"BUILD_EXIT=$LASTEXITCODE" | Out-File F:\~dev\_w1_build53_done.txt -Encoding ASCII
