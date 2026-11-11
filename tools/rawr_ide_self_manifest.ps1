[CmdletBinding()]
param(
    [Parameter(Position=0)] [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$Executable = '',
    [string]$Output = ''
)

$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
if (-not $Output) { $Output = Join-Path $RepoRoot 'evidence\rawr_ide_self_manifest.json' }
if (-not $Executable) {
    $Executable = Join-Path $RepoRoot 'build_ide\bin\RawrXD-Win32IDE-Native.exe'
}

$cpp = Join-Path $RepoRoot 'src\win32app\Win32IDE.cpp'
$header = Join-Path $RepoRoot 'src\win32app\Win32IDE.h'
$lifecycle = Join-Path $RepoRoot 'src\win32app\Win32IDE_lifecycle.cpp'
$commands = Join-Path $RepoRoot 'src\win32app\Win32IDE_AgentCommands.cpp'
$routeHeader = Get-ChildItem -LiteralPath $RepoRoot -Filter GeneratedChatRouteMenu.h -Recurse -File -ErrorAction SilentlyContinue |
    Select-Object -First 1

function Test-SourcePattern([string]$Path, [string]$Pattern) {
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    return [bool](Select-String -LiteralPath $Path -Pattern $Pattern -Quiet)
}
function Add-Check([System.Collections.Generic.List[object]]$List, [string]$Id,
    [string]$Area, [string]$Status, [string]$Evidence, [string]$NextAction) {
    $List.Add([ordered]@{ id=$Id; area=$Area; status=$Status;
        evidence=$Evidence; next_action=$NextAction })
}

$checks = [System.Collections.Generic.List[object]]::new()
$panels = @(
    @{id='TAB-DOCUMENTS'; name='document tabs'; file=$header; patterns=@('m_hwndDocTabs','createDocumentTabs','switchDocumentTab')},
    @{id='TAB-OUTPUT'; name='output tabs'; file=$lifecycle; patterns=@('m_hwndOutputTabs','createOutputTabs','IDC_OUTPUT_TABS')},
    @{id='TAB-EXPLORER'; name='file explorer'; file=$header; patterns=@('m_hwndFileTree','createFileExplorer','expandTreeNode')},
    @{id='TAB-SEARCH'; name='search'; file=$header; patterns=@('m_hwndSearchInput','showFindDialog','findNext')},
    @{id='TAB-SCM'; name='source control'; file=$header; patterns=@('m_hwndSCMFileList','refreshGitPanel','showGitPanel')},
    @{id='TAB-DEBUG'; name='debug'; file=$header; patterns=@('m_hwndDebugConsole','m_hwndDebugVariables','onDebug')},
    @{id='TAB-EXTENSIONS'; name='extensions'; file=(Join-Path $RepoRoot 'src\win32app\Win32ExtensionHostBridge.cpp'); patterns=@('Win32ExtensionHostBridge','extAddOutputTab','appendToOutput')},
    @{id='TAB-OUTLINE'; name='outline'; file=$header; patterns=@('m_hwndOutlineTree','outline')},
    @{id='TAB-TIMELINE'; name='timeline'; file=$header; patterns=@('m_hwndTimelineList','timeline')},
    @{id='TAB-TERMINAL'; name='terminal'; file=$header; patterns=@('Win32TerminalManager','m_hwndPanelNewTerminalBtn','createTerminal')},
    @{id='TAB-AI'; name='AI chat/model selector'; file=$header; patterns=@('m_hwndCopilotChatInput','m_hwndModelSelector','generateResponseAsync')},
    @{id='TAB-AUTONOMY'; name='agentic loop'; file=$commands; patterns=@('onAgenticLoopRunTask','m_agenticLoopBridge','handleAgenticLoopComplete')}
)
foreach ($panel in $panels) {
    $missing = @($panel.patterns | Where-Object { -not (Test-SourcePattern $panel.file $_) })
    if ($missing.Count -eq 0) {
        Add-Check $checks $panel.id 'ui-wiring' 'PASS' "$($panel.name): symbols present in $([IO.Path]::GetFileName($panel.file))" ''
    } else {
        Add-Check $checks $panel.id 'ui-wiring' 'BLOCKED' "$($panel.name): missing $($missing -join ', ')" 'Connect the missing creation, state, or event symbols before claiming the tab is wired.'
    }
}

$routes = @(
    @{id='ROUTE-DEEP2'; name='Deep2'; patterns=@('initializeDeep2Bridge','onDeep2Generate','Deep2Bridge')},
    @{id='ROUTE-OLLAMA'; name='Ollama'; patterns=@('generateOllamaModel','ollama-http','Source::Ollama')},
    @{id='ROUTE-KILO'; name='Kilo'; patterns=@('KILO_API_KEY','cloud-api','Source::KiloFree')},
    @{id='ROUTE-LOCAL'; name='native local'; patterns=@('native-agent','Source::LocalFile','hasGgufModelTensors')}
)
foreach ($route in $routes) {
    $routeFile = if ($route.id -eq 'ROUTE-DEEP2') {
        Join-Path $RepoRoot 'src\win32app\Win32IDE_AgentCommands.cpp'
    } else { $cpp }
    $missing = @($route.patterns | Where-Object { -not (Test-SourcePattern $routeFile $_) })
    Add-Check $checks $route.id 'provider-wiring' $(if ($missing.Count) {'BLOCKED'} else {'PASS'}) `
        "$($route.name): $(if ($missing.Count) { 'missing ' + ($missing -join ', ') } else { 'route selection and execution symbols present' })" `
        $(if ($missing.Count) {'Connect provider selection to the existing inference path.'} else {''})
}

$routePatterns = @('RouteKind::LocalFile','RouteKind::Ollama','RouteKind::KiloFree')
$routeMissing = @($routePatterns | Where-Object { -not $routeHeader -or -not (Test-SourcePattern $routeHeader.FullName $_) })
Add-Check $checks 'ROUTE-MENU' 'route-menu' $(if ($routeMissing.Count) {'BLOCKED'} else {'PASS'}) `
    "Generated route menu: $(if ($routeMissing.Count) {'missing ' + ($routeMissing -join ', ')} else {'all native routes present'})" `
    $(if ($routeMissing.Count) {'Regenerate or repair the route menu before shipping provider selection.'} else {''})

if (Test-Path -LiteralPath $Executable) {
    $hash = (Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash
    $healthOutputPath = Join-Path $env:TEMP 'rawrxd_self_manifest_health.txt'
    $healthErrorPath = Join-Path $env:TEMP 'rawrxd_self_manifest_health.err.txt'
    $healthProcess = Start-Process -FilePath $Executable -ArgumentList '--health-check' -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput $healthOutputPath -RedirectStandardError $healthErrorPath
    $healthExit = $healthProcess.ExitCode
    $healthOutput = ''
    if (Test-Path -LiteralPath $healthOutputPath) { $healthOutput += Get-Content -LiteralPath $healthOutputPath -Raw }
    if (Test-Path -LiteralPath $healthErrorPath) { $healthOutput += Get-Content -LiteralPath $healthErrorPath -Raw }
    Add-Check $checks 'RUNTIME-HEALTH' 'runtime' $(if ($healthExit -eq 0) {'PASS'} else {'BLOCKED'}) `
        "executable=$Executable sha256=$hash exit=$healthExit output=$($healthOutput -join ' ')" `
        $(if ($healthExit -eq 0) {''} else {'Run the native health check and repair startup initialization.'})
} else {
    Add-Check $checks 'RUNTIME-HEALTH' 'runtime' 'MISSING' "executable not found: $Executable" 'Build RawrXD-Win32IDE-Native, then rerun this manifest.'
}

$blocked = @($checks | Where-Object { $_.status -in @('BLOCKED','MISSING') })
$report = [ordered]@{
    schema='rawrxd.ide.self_manifest.v1'
    generated_utc=[DateTime]::UtcNow.ToString('o')
    repository=$RepoRoot
    source_revision=((& git -C $RepoRoot rev-parse HEAD 2>$null).Trim())
    policy='source wiring and runtime health are checked separately; this manifest never certifies model inference'
    checks=$checks
    check_count=$checks.Count
    blocked_count=$blocked.Count
    verdict=$(if ($blocked.Count) {'BLOCKED'} else {'WIRED_AND_HEALTHY'})
}
$parent = Split-Path -Parent $Output
if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Output -Encoding UTF8
Write-Host "MANIFEST=$Output"
Write-Host "CHECKS=$($checks.Count)"
Write-Host "BLOCKED=$($blocked.Count)"
Write-Host "VERDICT=$($report.verdict)"
exit $(if ($blocked.Count) { 4 } else { 0 })
