param([string]$RepoRoot = ".")
$ErrorActionPreference = "Stop"
$root = (Resolve-Path $RepoRoot).Path
$cpp = Join-Path $root "src\win32app\HeadlessIDE.cpp"
$hdr = Join-Path $root "src\win32app\HeadlessIDE_ProductLocalOnly.hpp"
if (!(Test-Path $cpp) -or !(Test-Path $hdr)) { throw "G4 source files missing" }
$s = [IO.File]::ReadAllText($cpp)
$checks = [ordered]@{
    HELPER_INCLUDED              = $s.Contains('HeadlessIDE_ProductLocalOnly.hpp')
    LOCAL_FLAG_PARSED            = $s.Contains('arg == "--local"')
    EARLY_LISTENER               = $s.Contains('G4_EARLY_LISTENER')
    RUNTIME_READY_GATE           = $s.Contains('G4_RUNTIME_READY')
    LOCAL_ONLY_POLICY            = $s.Contains('LOCAL_ONLY_NO_OLLAMA')
    NATIVE_ENGINE_LOAD           = $s.Contains('G4_NATIVE_ENGINE_LOAD')
    NATIVE_GENERATE              = $s.Contains('HeadlessProduct::GenerateNative')
    OPTIONS_ROUTE                = $s.Contains('method == "OPTIONS"')
    CORS_METHODS                 = $s.Contains('Access-Control-Allow-Methods: GET, POST, OPTIONS')
    CHAT_ALIAS                   = $s.Contains('path == "/api/chat"')
    BACKENDS_ALIAS               = $s.Contains('path == "/api/backends"')
    TOOL_PATH_PATCHED            = $s.Contains('path == "/api/tool"')
    COMBINED_LOCAL_OLLAMA_ROUTE  = $s.Contains('AIBackendType::Ollama || m_activeBackend == AIBackendType::LocalGGUF')
    DEFAULT_OLLAMA_PROBE_COMMENT = $s.Contains('Probe Ollama availability (primary backend)')
}
$pass = $true
foreach ($kv in $checks.GetEnumerator()) {
    $v = $kv.Value
    if ($kv.Key -in @('TOOL_PATH_PATCHED','COMBINED_LOCAL_OLLAMA_ROUTE','DEFAULT_OLLAMA_PROBE_COMMENT')) {
        $ok = -not $v
    } else { $ok = [bool]$v }
    if (!$ok) { $pass = $false }
    Write-Host ($kv.Key + '=' + $(if ($ok) {'PASS'} else {'FAIL'}))
}
Write-Host ('G4_SOURCE_AUDIT=' + $(if ($pass) {'PASS'} else {'FAIL'}))
if (!$pass) { exit 2 }
