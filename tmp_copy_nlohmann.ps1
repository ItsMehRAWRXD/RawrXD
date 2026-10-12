$ErrorActionPreference = 'Stop'
$src = 'F:\rawrxd\build_vs\_deps\nlohmann_json-src\single_include\nlohmann\json.hpp'
$dst = 'F:\rawrxd\include\nlohmann\json.hpp'
Copy-Item -LiteralPath $src -Destination $dst -Force
$item = Get-Item -LiteralPath $dst
Write-Output ("Copied real nlohmann/json.hpp -> {0} ({1} bytes)" -f $dst, $item.Length)
