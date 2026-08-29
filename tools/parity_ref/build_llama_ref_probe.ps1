# build_llama_ref_probe.ps1 — EXTERNAL llama.cpp measuring stick (NOT a Deep2 dep)
$ErrorActionPreference = 'Stop'
$vcvars = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if (!(Test-Path $vcvars)) { throw "BuildTools vcvars64.bat not found" }

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$outDir = Join-Path $root "bin"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$llamaInc = "F:\~dev\llama.cpp\include"
$ggmlInc  = "F:\~dev\llama.cpp\ggml\include"
$llamaDll = "F:\~dev\llama-direct\vulkan\llama.dll"
$src = Join-Path $root "llama_ref_parity_probe.cpp"
$exe = Join-Path $outDir "llama_ref_parity_probe.exe"

# Build import lib from DLL exports (external probe only)
$exports = Join-Path $root "llama_exports.txt"
$def = Join-Path $root "llama.def"
$lib = Join-Path $outDir "llama.lib"
$dumpbin = $null

cmd /c "`"$vcvars`" >nul && dumpbin /EXPORTS `"$llamaDll`" > `"$exports.raw`""
Get-Content "$exports.raw" |
  Select-String -Pattern '^\s+\d+\s+[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+(\S+)$' |
  ForEach-Object { $_.Matches.Groups[1].Value } |
  Where-Object { $_ -like 'llama_*' } |
  Set-Content $exports

@(
  'LIBRARY llama'
  'EXPORTS'
) + (Get-Content $exports) | Set-Content $def

cmd /c "`"$vcvars`" >nul && lib /nologo /def:`"$def`" /out:`"$lib`" /machine:x64"

cmd /c "`"$vcvars`" >nul && cl /nologo /O2 /EHsc /std:c++17 /I`"$llamaInc`" /I`"$ggmlInc`" /Fe:`"$exe`" `"$src`" /link /LIBPATH:`"$outDir`" llama.lib"

if (!(Test-Path $exe)) { throw "Build failed: $exe missing" }
Write-Host "BUILT $exe"
Write-Host "NOTE: This binary is an EXTERNAL measuring stick only. Deep2 has zero llama/Ollama deps."
