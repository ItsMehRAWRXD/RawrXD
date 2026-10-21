@echo off
REM ============================================================================
REM build_voxel.bat - builds the voxel engine and its certification gates
REM without CMake, so the gates can run on a tree whose CMake configuration
REM is not yet clean.
REM ============================================================================
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
set SRC=G:\wt_voxel
set OUT=G:\wt_voxel\build\voxel_direct
if not exist "%OUT%" mkdir "%OUT%"

cl /nologo /EHsc /std:c++20 /O2 /W3 /DNOMINMAX /D_CRT_SECURE_NO_WARNINGS ^
   /I "%SRC%\src" ^
   /c "%SRC%\src\voxel\VoxelWorld.cpp" /Fo:"%OUT%\VoxelWorld.obj" || exit /b 1
cl /nologo /EHsc /std:c++20 /O2 /W3 /DNOMINMAX /D_CRT_SECURE_NO_WARNINGS ^
   /I "%SRC%\src" ^
   /c "%SRC%\src\voxel\VoxelMesher.cpp" /Fo:"%OUT%\VoxelMesher.obj" || exit /b 1
cl /nologo /EHsc /std:c++20 /O2 /W3 /DNOMINMAX /D_CRT_SECURE_NO_WARNINGS ^
   /I "%SRC%\src" ^
   /c "%SRC%\src\voxel\VoxelRenderer.cpp" /Fo:"%OUT%\VoxelRenderer.obj" || exit /b 1
cl /nologo /EHsc /std:c++20 /O2 /W3 /DNOMINMAX /D_CRT_SECURE_NO_WARNINGS ^
   /I "%SRC%\src" ^
   /c "%SRC%\src\voxel\VoxelRasterizer.cpp" /Fo:"%OUT%\VoxelRasterizer.obj" || exit /b 1
cl /nologo /EHsc /std:c++20 /O2 /W3 /DNOMINMAX /D_CRT_SECURE_NO_WARNINGS ^
   /I "%SRC%\src" ^
   /c "%SRC%\src\voxel\sunshine\WorldGen.cpp" /Fo:"%OUT%\WorldGen.obj" || exit /b 1
cl /nologo /EHsc /std:c++20 /O2 /W3 /DNOMINMAX /D_CRT_SECURE_NO_WARNINGS ^
   /I "%SRC%\src" ^
   /c "%SRC%\tools\voxel_render_certify.cpp" /Fo:"%OUT%\certify.obj" || exit /b 1
cl /nologo /EHsc /std:c++20 /O2 /W3 /DNOMINMAX /D_CRT_SECURE_NO_WARNINGS ^
   /I "%SRC%\src" ^
   /c "%SRC%\tools\sunshine_world_test.cpp" /Fo:"%OUT%\sunshine_test.obj" || exit /b 1
link /nologo /OUT:"%OUT%\voxel_render_certify.exe" ^
   "%OUT%\VoxelWorld.obj" "%OUT%\VoxelMesher.obj" "%OUT%\VoxelRenderer.obj" "%OUT%\VoxelRasterizer.obj" "%OUT%\WorldGen.obj" "%OUT%\certify.obj" ^
   d3d12.lib dxgi.lib d3dcompiler.lib user32.lib || exit /b 1
link /nologo /OUT:"%OUT%\sunshine_world_test.exe" ^
   "%OUT%\VoxelWorld.obj" "%OUT%\VoxelMesher.obj" "%OUT%\VoxelRasterizer.obj" "%OUT%\WorldGen.obj" "%OUT%\sunshine_test.obj" ^
   d3d12.lib dxgi.lib d3dcompiler.lib user32.lib || exit /b 1
echo BUILD_OK
exit /b 0
