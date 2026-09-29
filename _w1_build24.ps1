Set-Location F:\~dev\rawrxd
cmake -S . -B build_w1 -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Release 2>&1 | Out-File F:\~dev\_w1_reconfigure24.txt -Encoding UTF8
"RECONFIGURE_EXIT=$LASTEXITCODE" | Out-File F:\~dev\_w1_reconfigure24_done.txt -Encoding ASCII
cmake --build "F:\~dev\rawrxd\build_w1" --config Release --target RawrXD-Win32IDE -j 6 2>&1 | Out-File F:\~dev\_w1_build24.txt -Encoding UTF8
"BUILD_EXIT=$LASTEXITCODE" | Out-File F:\~dev\_w1_build24_done.txt -Encoding ASCII
