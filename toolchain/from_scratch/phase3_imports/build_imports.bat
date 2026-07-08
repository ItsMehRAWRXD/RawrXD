@echo off
REM Build Phase 3 Import Builder
REM No CMake dependency - direct compilation

gcc -c import_builder.c -o import_builder.obj
gcc -c import_test.c -o import_test.obj
gcc import_test.obj import_builder.obj -o rawrxd_import_test.exe

echo Build complete: rawrxd_import_test.exe