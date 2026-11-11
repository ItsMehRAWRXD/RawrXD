param(
    [string]$Root = 'F:\RawrXD',
    [string]$Output = '',
    [switch]$RunSafeTests
)
$ErrorActionPreference = 'Stop'
if (!(Test-Path -LiteralPath $Root -PathType Container)) { throw "Root not found: $Root" }
$Root = (Resolve-Path -LiteralPath $Root).Path
if (!$Output) { $Output = Join-Path $Root '.rawrxd\audits\RAWRXD_FULL_IDE_AUDIT_001' }
New-Item -ItemType Directory -Force -Path $Output | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$report = Join-Path $Output "audit_$stamp.json"
$markdown = Join-Path $Output "audit_$stamp.md"
$findings = [System.Collections.Generic.List[object]]::new()
$inventory = [System.Collections.Generic.List[object]]::new()
function Add-Finding([string]$id,[string]$severity,[string]$component,[string]$description,[string]$evidence,[string]$recommendation) {
  $findings.Add([pscustomobject]@{id=$id;severity=$severity;component=$component;description=$description;evidence=$evidence;recommendation=$recommendation})
}
function Check-Path([string]$id,[string]$relative,[string]$component) {
  $p=Join-Path $Root $relative
  $exists=Test-Path -LiteralPath $p
  $inventory.Add([pscustomobject]@{id=$id;component=$component;path=$relative;exists=$exists})
  return $exists
}
$cli=Check-Path 'CLI' 'build\bin-msvc\Release\rawr.exe' 'Production CLI'
$cliSrc=Check-Path 'CLI_SOURCE' 'src\rawrxd_cli_v2.cpp' 'Production CLI'
$ollama=Check-Path 'OLLAMA_BACKEND' 'src\agentic\OllamaBackend.cpp' 'Inference'
$ollamaBench=Check-Path 'OLLAMA_SWEEP' '.rawrxd\evidence\ollama_bench.json' 'Inference'
$cmake=Check-Path 'CMAKE' 'CMakeLists.txt' 'Build'
$git=Check-Path 'GIT' '.git' 'Source control'
if (!$cli) { Add-Finding 'CLI-MISSING' 'P0' 'Production CLI' 'Production executable not found' 'build\bin-msvc\Release\rawr.exe' 'Build RawrXD-CLI-V2 with the existing CMake configuration' }
if ($cli -and $cliSrc) {
  $exe=Get-Item -LiteralPath (Join-Path $Root 'build\bin-msvc\Release\rawr.exe')
  $src=Get-Item -LiteralPath (Join-Path $Root 'src\rawrxd_cli_v2.cpp')
  if ($exe.LastWriteTimeUtc -lt $src.LastWriteTimeUtc) { Add-Finding 'CLI-STALE' 'P1' 'Production CLI' 'Executable timestamp precedes CLI source timestamp' "exe=$($exe.LastWriteTimeUtc.ToString('o'));src=$($src.LastWriteTimeUtc.ToString('o'))" 'Rebuild production CLI and run certification' }
}
if (!$ollamaBench) { Add-Finding 'SWEEP-MISSING' 'P1' 'Ollama' 'Sweep evidence absent at project-root evidence path' '.rawrxd\evidence\ollama_bench.json' 'Locate the original report without regenerating or overwriting it' }
$patterns=[ordered]@{
  'IDE/UI'='Win32|WebView2|WndProc|CreateWindow|Dock|TabBar|Editor';
  'Extensions'='extension|plugin|LSP|language.server';
  'Debugging'='debugger|breakpoint|DAP|DebugActiveProcess';
  'Agent'='AgentLoop|MakeAgentAction|ToolAuthority|tool.call';
  'Inference'='Deep2|OllamaBackend|Vulkan|GGUF';
  'Compiler'='lexer|parser|codegen|linker|frontend';
  'Testing'='add_test\(|enable_testing\(|Catch2|CTest';
  'Security'='sandbox|allowlist|permission|workspace.policy';
  'Build'='add_executable\(|add_library\(|target_link_libraries\('
}
$sourceExtensions=@('.cpp','.c','.cc','.cxx','.h','.hpp','.hh','.asm','.s','.cmake','.json','.ps1','.bat')
$skipDirs=@('build','.git','.rawrxd','node_modules','.vs','Debug','Release','_deps','third_party','vendor')
$sourceFiles=Get-ChildItem -LiteralPath $Root -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
  $sourceExtensions -contains $_.Extension.ToLowerInvariant() -and
  -not (@($_.FullName.Substring($Root.Length).TrimStart('\').Split('\')) | Where-Object { $skipDirs -contains $_ }).Count
}
$matches=[ordered]@{}
foreach ($key in $patterns.Keys) { $matches[$key]=[System.Collections.Generic.List[string]]::new() }
foreach ($f in $sourceFiles) {
  $rel=$f.FullName.Substring($Root.Length).TrimStart('\')
  foreach ($key in $patterns.Keys) {
    try { if (Select-String -LiteralPath $f.FullName -Pattern $patterns[$key] -Quiet -ErrorAction SilentlyContinue) { $matches[$key].Add($rel) } } catch {}
  }
}
$coverage=@(foreach($key in $patterns.Keys) { [pscustomobject]@{component=$key;source_files_with_signals=$matches[$key].Count;examples=@($matches[$key] | Select-Object -First 12);verification='SOURCE_SIGNAL_ONLY_NOT_CERTIFIED'} })
if (!$git) { Add-Finding 'GIT-NOT-DETECTED' 'P2' 'Source control' 'No .git entry detected at audit root' '.git' 'Confirm the intended repository root or worktree' }
$gitInfo=$null
if (Get-Command git -ErrorAction SilentlyContinue) {
  try {
    $gitInfo=[pscustomobject]@{branch=((& git -C $Root branch --show-current 2>$null) -join '');status=@(& git -C $Root status --short 2>$null | Select-Object -First 100);head=((& git -C $Root rev-parse HEAD 2>$null) -join '')}
  } catch { Add-Finding 'GIT-INSPECT' 'P2' 'Source control' 'Could not inspect git state' $_.Exception.Message 'Check repository and Git availability' }
}
$cert=$null
if ($RunSafeTests -and $cli) {
  $exePath=Join-Path $Root 'build\bin-msvc\Release\rawr.exe'
  $certLog=Join-Path $Output "ollama_cert_$stamp.log"
  try {
    Push-Location $Root
    try { & $exePath certify ollama *>&1 | Out-File -LiteralPath $certLog -Encoding utf8; $exitCode=$LASTEXITCODE } finally { Pop-Location }
    $cert=[pscustomobject]@{command='rawr certify ollama';exit_code=$exitCode;log=$certLog}
    if ($exitCode -ne 0) { Add-Finding 'OLLAMA-CERT-FAIL' 'P1' 'Ollama' 'Live certification returned nonzero exit status' $certLog 'Review individual gate failures and fix root causes' }
  } catch { Add-Finding 'OLLAMA-CERT-ERROR' 'P1' 'Ollama' 'Certification invocation failed' $_.Exception.Message 'Inspect invocation and executable' }
}
$summary=[pscustomobject]@{audit='RAWRXD_FULL_IDE_AUDIT_001';generated_utc=(Get-Date).ToUniversalTime().ToString('o');root=$Root;mode=$(if($RunSafeTests){'READ_ONLY_PLUS_EXPLICIT_LIVE_CERT'}else{'READ_ONLY_STATIC'});source_files_scanned=$sourceFiles.Count;findings_count=$findings.Count;verification_note='Source signals do not prove feature completeness, runtime integration, or parity';inventory=@($inventory);coverage=@($coverage);findings=@($findings);git=$gitInfo;live_cert=$cert}
$summary | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $report -Encoding utf8
$lines=[System.Collections.Generic.List[string]]::new()
$lines.Add('# RAWRXD_FULL_IDE_AUDIT_001')
$lines.Add('')
$lines.Add("Generated UTC: $($summary.generated_utc)")
$lines.Add("Root: $Root")
$lines.Add("Mode: $($summary.mode)")
$lines.Add("Source files scanned: $($sourceFiles.Count)")
$lines.Add('')
$lines.Add('## Findings')
if (!$findings.Count) { $lines.Add('No automated findings; this is NOT a clean bill of health.') }
foreach($f in $findings) { $lines.Add("- **$($f.severity) $($f.id)** [$($f.component)]: $($f.description). Evidence: $($f.evidence). Next: $($f.recommendation)") }
$lines.Add('')
$lines.Add('## Source discovery (not certification)')
foreach($c in $coverage) { $lines.Add("- **$($c.component)**: $($c.source_files_with_signals) files with keyword signals; status: NOT VERIFIED") }
$lines.Add('')
$lines.Add('## Manual certification backlog')
$lines.Add('1. Map entrypoints and actual CMake-linked source closure for each shipped binary.')
$lines.Add('2. Test editor open/save/undo/redo, Unicode, large files, crash recovery, and multi-window behavior.')
$lines.Add('3. Verify language services, extensions activation, isolation, API compatibility, and update lifecycle.')
$lines.Add('4. Run native compiler/linker fixtures across supported languages and inspect diagnostics.')
$lines.Add('5. Execute debugger breakpoints, step, watches, call stacks, and attach/detach against live programs.')
$lines.Add('6. Certify agent read/write/shell/git/build/test workflows with policy denial and rollback tests.')
$lines.Add('7. Certify Deep2 and Ollama streaming, cancel, context limits, model fit, and numerical parity separately.')
$lines.Add('8. Run reproducible performance, memory, startup, soak, and failure-injection tests.')
$lines.Add('9. Validate installer, update, rollback, signatures, accessibility, and offline operation.')
$lines.Add('10. Compare feature-level evidence against a named IDE competitor matrix; do not assign parity from source presence.')
$lines | Set-Content -LiteralPath $markdown -Encoding utf8
Write-Host "JSON: $report"
Write-Host "Markdown: $markdown"
Write-Host "Findings: $($findings.Count); source files: $($sourceFiles.Count)"
