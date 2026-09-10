# smoke_k3c_no_deps.ps1 — compile drop sources only (no Win32IDE rebuild).
$ErrorActionPreference = "Stop"
$vcvars = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
$cl = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\cl.exe"
$gate = "G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_K3C_NO_DEPS_SOURCE_DROP_001"
$out = Join-Path $gate "tools\smoke_k3c_no_deps.exe"
$files = @(
  "$gate\drop\k3c.cpp",
  "$gate\tools\smoke_k3c_no_deps.cpp"
)
$inc = "/I$gate\drop"
$flist = ($files | ForEach-Object { '"' + $_ + '"' }) -join ' '
cmd /c "`"$vcvars`" >nul && `"$cl`" /nologo /EHsc /std:c++17 /O2 /DWIN32 /D_WINDOWS $inc $flist /Fe:`"$out`" /link /SUBSYSTEM:CONSOLE"
if ($LASTEXITCODE -ne 0) {
  "SMOKE_COMPILE=FAIL" | Set-Content -Path (Join-Path $gate "SMOKE_OUT.txt") -Encoding UTF8
  exit $LASTEXITCODE
}
& $out | Tee-Object -FilePath (Join-Path $gate "SMOKE_OUT.txt")
exit $LASTEXITCODE
