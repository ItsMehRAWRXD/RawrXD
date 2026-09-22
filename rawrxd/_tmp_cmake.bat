cd /d f:\~dev\rawrxd
cmake -G "Visual Studio 17 2022" -A x64 -S . -B build_p1pra_win32ide -DCMAKE_BUILD_TYPE=Release > f:\~dev\rawrxd\_cmake_out.txt 2>&1
if errorlevel 1 (
    echo CMAKE_FAILED
) else (
    echo CMAKE_SUCCESS
)
echo Done > f:\~dev\rawrxd\_cmake_done.txt
