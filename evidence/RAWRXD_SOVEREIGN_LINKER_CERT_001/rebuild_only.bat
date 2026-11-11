@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" || exit /b 2
set "BD=F:\rawrxd\build_5os_win"
set "OD=%BD%\CMakeFiles\rawrxd_link.dir\src\toolchain\linker"
set "BIN=F:\rawrxd\evidence\RAWRXD_SOVEREIGN_LINKER_CERT_001\bin"
if not exist "%BIN%" mkdir "%BIN%"
set "OUT=%BIN%\rawrxd_link_corpus_%RANDOM%.exe"
set "STABLE=%BIN%\rawrxd_link_corpus.exe"

if "%RAWRXD_SKIP_LINKER_REBUILD%"=="1" if exist "%STABLE%" (
  echo [rebuild] SKIP pinned %STABLE%
  certutil -hashfile "%STABLE%" SHA256
  exit /b 0
)

cd /d "%BD%" || exit /b 2
ninja.exe CMakeFiles/rawrxd_link.dir/src/toolchain/linker/main.c.obj ^
  CMakeFiles/rawrxd_link.dir/src/toolchain/linker/coff_reader.c.obj ^
  CMakeFiles/rawrxd_link.dir/src/toolchain/linker/section_merge.c.obj ^
  CMakeFiles/rawrxd_link.dir/src/toolchain/linker/reloc_resolver.c.obj ^
  CMakeFiles/rawrxd_link.dir/src/toolchain/linker/pe_writer.c.obj ^
  CMakeFiles/rawrxd_link.dir/src/toolchain/linker/entry_stub.c.obj
if errorlevel 1 exit /b 3

link /nologo /LTCG /OPT:REF /OPT:ICF /subsystem:console /DYNAMICBASE /NXCOMPAT /MACHINE:X64 ^
  /out:"%OUT%" ^
  "%OD%\main.c.obj" "%OD%\coff_reader.c.obj" "%OD%\section_merge.c.obj" ^
  "%OD%\reloc_resolver.c.obj" "%OD%\pe_writer.c.obj" "%OD%\entry_stub.c.obj" ^
  kernel32.lib
if errorlevel 1 exit /b 4
if not exist "%OUT%" exit /b 5
copy /y "%OUT%" "%STABLE%" >nul
echo [rebuild] OK %STABLE% (from %OUT%)
certutil -hashfile "%STABLE%" SHA256
exit /b 0
