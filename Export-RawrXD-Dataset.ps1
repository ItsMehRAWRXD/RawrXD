param(
    [string]$Root = "D:\rawrxd",
    [string]$Binary = "D:\rawrxd\build\RawrXD-Win32IDE.exe",
    [string]$OutDir = ".\rawrxd_dataset"
)

# ============================================================
# Setup
# ============================================================

if (!(Test-Path $OutDir)) {
    New-Item -ItemType Directory -Path $OutDir | Out-Null
}

Write-Host "Extracting RawrXD structural dataset..."

# ============================================================
# Collect Source Files
# ============================================================

$cpp = Get-ChildItem $Root -Recurse -Include *.cpp -ErrorAction SilentlyContinue
$hpp = Get-ChildItem $Root -Recurse -Include *.hpp -ErrorAction SilentlyContinue
$asm = Get-ChildItem $Root -Recurse -Include *.asm -ErrorAction SilentlyContinue

$files = $cpp + $hpp + $asm

if ($files.Count -eq 0) {
    Write-Error "No source files found in $Root"
    exit 1
}

$allContent = $files | ForEach-Object {
    Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue
}

$combined = $allContent -join "`n"

# ============================================================
# TOPOLOGY.JSON - File structure and dependencies
# ============================================================

Write-Host "Extracting topology..."

$topology = @{
    files = @()
    includes = @()
    dependencies = @()
}

foreach ($file in $files) {
    $topology.files += @{
        path = $file.FullName
        type = $file.Extension
        size = $file.Length
    }
}

# Find includes
$includes = Select-String -Path $files.FullName -Pattern '^#include\s+["<]([^">]+)[">]' |
    ForEach-Object { $_.Matches.Groups[1].Value } |
    Sort-Object -Unique

$topology.includes = $includes

# Basic dependencies (simplified)
$topology.dependencies = $includes | Where-Object { $_ -match '\.h(pp)?$' }

$topology | ConvertTo-Json -Depth 5 | Out-File "$OutDir\topology.json"

# ============================================================
# COMMANDS.JSON - Command table and handlers
# ============================================================

Write-Host "Extracting commands..."

$commands = @{
    table = @()
    handlers = @()
}

# Find COMMAND_TABLE entries
$commandMatches = Select-String -Path $files.FullName -Pattern 'COMMAND_TABLE\[.*?\]\s*=\s*\{(.*?)\}' -AllMatches |
    ForEach-Object { $_.Matches } |
    ForEach-Object { $_.Groups[1].Value }

foreach ($match in $commandMatches) {
    $entries = $match -split '},' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    foreach ($entry in $entries) {
        if ($entry -match '\{\s*"([^"]+)"\s*,\s*([^}]+)\}') {
            $commands.table += @{
                name = $matches[1]
                handler = $matches[2].Trim()
            }
        }
    }
}

# Find handler functions
$handlerMatches = Select-String -Path $files.FullName -Pattern 'void\s+(handle\w+)\s*\(' |
    ForEach-Object { $_.Matches.Groups[1].Value } |
    Sort-Object -Unique

$commands.handlers = $handlerMatches

$commands | ConvertTo-Json -Depth 5 | Out-File "$OutDir\commands.json"

# ============================================================
# SUBSYSTEMS.JSON - Core subsystems and features
# ============================================================

Write-Host "Extracting subsystems..."

$subsystems = @{
    windowing = @{}
    rendering = @{}
    messaging = @{}
    features = @{}
}

# Windowing
$subsystems.windowing = @{
    WM_CREATE = ($combined -match "WM_CREATE")
    WM_PAINT = ($combined -match "WM_PAINT")
    WM_DESTROY = ($combined -match "WM_DESTROY")
    CreateWindow = ($combined -match "CreateWindow")
    RegisterClass = ($combined -match "RegisterClass")
}

# Rendering
$subsystems.rendering = @{
    Direct2D = ($combined -match "D2D1CreateFactory")
    DirectWrite = ($combined -match "DWriteCreateFactory")
    GDI = ($combined -match "BeginPaint|EndPaint")
    RichEdit = ($combined -match "RichEdit")
}

# Messaging
$subsystems.messaging = @{
    DispatchTable = ($combined -match "COMMAND_TABLE|dispatch")
    MessageLoop = ($combined -match "GetMessage|DispatchMessage")
    WinProc = ($combined -match "WndProc|LRESULT CALLBACK")
}

# Features
$subsystems.features = @{
    FileOperations = ($combined -match "handleFile|openFile")
    CodeGeneration = ($combined -match "generateCode|AI")
    BuildSystem = ($combined -match "build|compile")
    DebugTools = ($combined -match "debug|trace")
}

$subsystems | ConvertTo-Json -Depth 5 | Out-File "$OutDir\subsystems.json"

# ============================================================
# ENTRYPOINTS.JSON - Main entry points
# ============================================================

Write-Host "Extracting entrypoints..."

$entrypoints = @{
    main = @()
    dll = @()
    exports = @()
}

# Find main functions
$mainMatches = Select-String -Path $files.FullName -Pattern 'int\s+(main|WinMain|wmain|DllMain)\s*\(' |
    ForEach-Object {
        @{
            function = $_.Matches.Groups[1].Value
            file = $_.Filename
            line = $_.LineNumber
        }
    }

$entrypoints.main = $mainMatches

# Find DLL exports
$exportMatches = Select-String -Path $files.FullName -Pattern '__declspec\(dllexport\)|\.def|EXPORTS' |
    ForEach-Object {
        @{
            type = "export"
            content = $_.Line
            file = $_.Filename
        }
    }

$entrypoints.dll = $exportMatches

# Find PUBLIC in ASM
$asmExports = Select-String -Path $asm.FullName -Pattern 'PUBLIC\s+(\w+)' |
    ForEach-Object { $_.Matches.Groups[1].Value } |
    Sort-Object -Unique

$entrypoints.exports = $asmExports

$entrypoints | ConvertTo-Json -Depth 5 | Out-File "$OutDir\entrypoints.json"

# ============================================================
# AGENTS.JSON - AI agents and autonomous systems
# ============================================================

Write-Host "Extracting agents..."

$agents = @{
    systems = @()
    models = @()
    interfaces = @()
}

# Find agent-related code
$agentMatches = Select-String -Path $files.FullName -Pattern '(CompletionEngine|ContextAnalyzer|CodeGenerator|SecurityValidator|PerformanceOptimizer|DocumentationGenerator|TestRunner)' |
    ForEach-Object { $_.Matches.Value } |
    Sort-Object -Unique

$agents.systems = $agentMatches

# Find model references
$modelMatches = Select-String -Path $files.FullName -Pattern '(bigdaddyg|gemma|gpt-oss|llama)' |
    ForEach-Object { $_.Matches.Value } |
    Sort-Object -Unique

$agents.models = $modelMatches

# Find API interfaces
$interfaceMatches = Select-String -Path $files.FullName -Pattern '(Ollama|HTTP|API|REST)' |
    ForEach-Object { $_.Matches.Value } |
    Sort-Object -Unique

$agents.interfaces = $interfaceMatches

$agents | ConvertTo-Json -Depth 5 | Out-File "$OutDir\agents.json"

# ============================================================
# ASM_BRIDGES.JSON - MASM assembly bridges
# ============================================================

Write-Host "Extracting ASM bridges..."

$asm_bridges = @{
    functions = @()
    exports = @()
    imports = @()
}

# Find PROC declarations
$procMatches = Select-String -Path $asm.FullName -Pattern '(\w+)\s+PROC' |
    ForEach-Object { $_.Matches.Groups[1].Value } |
    Sort-Object -Unique

$asm_bridges.functions = $procMatches

# Find PUBLIC declarations
$publicMatches = Select-String -Path $asm.FullName -Pattern 'PUBLIC\s+(\w+)' |
    ForEach-Object { $_.Matches.Groups[1].Value } |
    Sort-Object -Unique

$asm_bridges.exports = $publicMatches

# Find EXTERN declarations
$externMatches = Select-String -Path $asm.FullName -Pattern 'EXTERN\s+(\w+)' |
    ForEach-Object { $_.Matches.Groups[1].Value } |
    Sort-Object -Unique

$asm_bridges.imports = $externMatches

$asm_bridges | ConvertTo-Json -Depth 5 | Out-File "$OutDir\asm_bridges.json"

# ============================================================
# RANDOM.JSON - Unclassified symbols and entropy
# ============================================================

Write-Host "Detecting unclassified symbols..."

$random = @()

# Find functions not referenced in COMMAND_TABLE
$functions = Select-String -Path $files.FullName -Pattern 'void\s+(\w+)\s*\(' |
    ForEach-Object { $_.Matches.Groups[1].Value } |
    Sort-Object -Unique

foreach ($fn in $functions) {
    if ($combined -notmatch "COMMAND_TABLE.*$fn") {
        $random += @{
            type = "UnmappedFunction"
            name = $fn
        }
    }
}

# Find .asm exports not linked in C++
foreach ($exp in $asm_bridges.exports) {
    if ($combined -notmatch $exp) {
        $random += @{
            type = "UnreferencedASMExport"
            name = $exp
        }
    }
}

# Find unhandled messages
$messageMatches = Select-String -Path $files.FullName -Pattern 'case\s+WM_\w+:' |
    ForEach-Object { $_.Matches.Value } |
    Sort-Object -Unique

foreach ($msg in $messageMatches) {
    if ($msg -notmatch "WM_CREATE|WM_PAINT|WM_DESTROY") {
        $random += @{
            type = "UnhandledMessage"
            name = $msg
        }
    }
}

$random | ConvertTo-Json -Depth 5 | Out-File "$OutDir\random.json"

# ============================================================
# REBUILD_INSTRUCTIONS.MD
# ============================================================

Write-Host "Generating rebuild instructions..."

$instructions = @"
# RawrXD IDE Deterministic Rebuild Instructions

## Dataset Overview
This dataset contains the complete structural truth of the RawrXD IDE.
All files in rawrxd_dataset/ are generated from source analysis.

## Critical Rule
random.json MUST be empty before release.
If random.json contains entries, the build is incomplete.

## Rebuild Process
1. Run deterministic_rebuild.ps1
2. Check random.json - if not empty, fix wiring
3. Build with ml64.exe and link.exe
4. Test WM_PAINT and WM_CREATE handlers
5. Verify all subsystems initialize

## Common Issues
- White window: WM_PAINT handler missing or failing
- No features: COMMAND_TABLE not wired
- Crashes: ASM bridges not linked properly

## Validation
After rebuild:
- Window should show content, not be white
- All commands in commands.json should work
- All agents in agents.json should respond
"@

$instructions | Out-File "$OutDir\rebuild_instructions.md"

# ============================================================
# DETERMINISTIC_REBUILD.PS1
# ============================================================

Write-Host "Generating deterministic rebuild script..."

$rebuildScript = @'
param(
    [string]$Root = "D:\rawrxd",
    [string]$Dataset = ".\rawrxd_dataset"
)

# Load dataset
$topology = Get-Content "$Dataset\topology.json" | ConvertFrom-Json
$commands = Get-Content "$Dataset\commands.json" | ConvertFrom-Json
$subsystems = Get-Content "$Dataset\subsystems.json" | ConvertFrom-Json
$entrypoints = Get-Content "$Dataset\entrypoints.json" | ConvertFrom-Json
$agents = Get-Content "$Dataset\agents.json" | ConvertFrom-Json
$asm_bridges = Get-Content "$Dataset\asm_bridges.json" | ConvertFrom-Json
$random = Get-Content "$Dataset\random.json" | ConvertFrom-Json

# Validation
if ($random.Count -gt 0) {
    Write-Error "Unclassified structures detected. Cannot rebuild."
    $random | Format-Table
    exit 1
}

# Generate missing WM_PAINT if needed
if (-not $subsystems.rendering.WM_PAINT) {
    Write-Host "Injecting WM_PAINT handler..."
    $paintCode = @"
case WM_PAINT:
{
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(hwnd, &ps);
    RECT r;
    GetClientRect(hwnd, &r);
    DrawTextA(hdc, "RawrXD IDE", -1, &r, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    EndPaint(hwnd, &ps);
    return 0;
}
"@

    # Find WndProc and inject
    $wndProcFile = Get-ChildItem $Root -Recurse -Include *.cpp |
        Where-Object { Select-String -Path $_.FullName -Pattern "WndProc" } |
        Select-Object -First 1

    if ($wndProcFile) {
        Add-Content $wndProcFile.FullName $paintCode
    }
}

# Generate COMMAND_TABLE if missing
if (-not $subsystems.messaging.DispatchTable) {
    Write-Host "Generating COMMAND_TABLE..."
    $tableCode = @"
struct CommandEntry {
    const char* name;
    void(*handler)();
};

void handleBootTest() { MessageBoxA(NULL, "Boot test", "RawrXD", MB_OK); }

CommandEntry COMMAND_TABLE[] = {
    {"boot_test", handleBootTest}
};
"@

    $tableCode | Out-File "$Root\generated_command_table.cpp"
}

# Build instructions
Write-Host "Ready to build. Run:"
Write-Host "ml64.exe /c *.asm"
Write-Host "cl.exe *.cpp /link /SUBSYSTEM:WINDOWS"
'@

$rebuildScript | Out-File "$OutDir\deterministic_rebuild.ps1"

# ============================================================
# Output Summary
# ============================================================

Write-Host "`n=== RawrXD Dataset Extraction Complete ==="
Write-Host "Output directory: $OutDir"
Write-Host "Files generated:"
Get-ChildItem $OutDir | ForEach-Object { Write-Host " - $($_.Name)" }

$randomCount = (Get-Content "$OutDir\random.json" | ConvertFrom-Json).Count
if ($randomCount -gt 0) {
    Write-Warning "Found $randomCount unclassified items in random.json"
    Write-Host "Review and fix before rebuilding."
} else {
    Write-Host "All structures classified. Ready for deterministic rebuild."
}