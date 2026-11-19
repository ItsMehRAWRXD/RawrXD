$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$out = Join-Path $root 'build\pe_writer_e2e'
New-Item -ItemType Directory -Force $out | Out-Null
$cl = Get-Command cl.exe -ErrorAction SilentlyContinue
if (-not $cl) {
  $candidate = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\cl.exe'
  if (Test-Path $candidate) { $cl = Get-Item $candidate } else { throw 'cl.exe unavailable' }
}
Push-Location $out
try {
  & $cl.FullName /nologo /O2 /TC /I (Join-Path $root 'src\toolchain\linker') `
    (Join-Path $root 'tests\pe_writer_e2e.c') (Join-Path $root 'src\toolchain\linker\pe_writer.c') `
    /Fe:pe_writer_e2e.exe
  if ($LASTEXITCODE -ne 0) { throw "compile exit $LASTEXITCODE" }
  & .\pe_writer_e2e.exe
  if ($LASTEXITCODE -ne 0) { throw "harness exit $LASTEXITCODE" }
  foreach ($name in 'pe_writer_minimal.exe','pe_writer_large_import.exe') {
    $p = Join-Path $out $name
    if (-not (Test-Path $p)) { throw "missing $name" }
    $bytes = [IO.File]::ReadAllBytes($p)
    if ($bytes[0] -ne 0x4d -or $bytes[1] -ne 0x5a) { throw "$name missing MZ" }
    $pe = [BitConverter]::ToInt32($bytes, 0x3c)
    if ([Text.Encoding]::ASCII.GetString($bytes, $pe, 4) -ne 'PE`0`0') { throw "$name missing PE" }
    $sections = [BitConverter]::ToUInt16($bytes, $pe + 6)
    $opt = $pe + 24
    if ([BitConverter]::ToUInt16($bytes, $opt) -ne 0x20b) { throw "$name is not PE32+" }
    $headerSize = [BitConverter]::ToUInt32($bytes, $opt + 60)
    if (($headerSize % 0x200) -ne 0) { throw "$name header alignment" }
    for ($i = 0; $i -lt $sections; $i++) {
      $sh = $pe + 4 + 20 + 240 + ($i * 40)
      $rva = [BitConverter]::ToUInt32($bytes, $sh + 12)
      $raw = [BitConverter]::ToUInt32($bytes, $sh + 20)
      $rawSize = [BitConverter]::ToUInt32($bytes, $sh + 16)
      if (($rva % 0x1000) -ne 0 -or ($raw % 0x200) -ne 0 -or ($rawSize % 0x200) -ne 0) { throw "$name section alignment" }
      if ($raw + $rawSize -gt $bytes.Length) { throw "$name section exceeds file" }
    }
  }
  & .\pe_writer_minimal.exe
  $minimalExit = $LASTEXITCODE
  if ($minimalExit -ne 42) { throw "minimal execution exit $minimalExit" }
  & .\pe_writer_large_import.exe
  $importExit = $LASTEXITCODE
  if ($importExit -ne 42) { throw "import execution exit $importExit" }
  [pscustomobject]@{ generated = $true; minimal_exit = $minimalExit; import_exit = $importExit; minimal_sha256 = (Get-FileHash .\pe_writer_minimal.exe -Algorithm SHA256).Hash; import_sha256 = (Get-FileHash .\pe_writer_large_import.exe -Algorithm SHA256).Hash } | ConvertTo-Json
} finally { Pop-Location }
