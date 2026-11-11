# RawrXD Unified CLI PowerShell Wrapper
# Version: 4.0
# Provides easy access to the unified command interface

param(
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$Arguments
)

$UnifiedExe = "d:\rawrxd\src\RawrXD_Unified.exe"

function Show-Help {
    Write-Host @"
RawrXD Unified CLI Wrapper
==========================

USAGE:
    .\Unified-CLI.ps1 [command] [arguments]
    .\Unified-CLI.ps1 --status
    .\Unified-CLI.ps1 ide
    .\Unified-CLI.ps1 python script.py

COMMANDS:
    --status        Show tool availability status
    --tools         List all available tools
    --compilers     List all compilers
    --help          Show this help

IDE Commands:
    ide             Launch RawrXD IDE
    hybrid          Launch RawrXD Hybrid
    sovereign       Launch Sovereign CLI
    titan           Launch Titan 800B
    production      Launch Production build
    autonomous      Launch Autonomous IDE

Compiler Commands (50+ languages):
    cc, python, javascript, bash, powershell, csharp, java
    rust, go, ruby, php, typescript, lua, perl, kotlin
    scala, swift, cpp, fortran, cobol, julia, dart, r
    matlab, groovy, clojure, haskell, erlang, elixir
    ocaml, lisp, scheme, fsharp, vb, objc, d, nim
    zig, crystal, v, odin

Testing Commands:
    test, benchmark, soak, contention, lock, golden
    phase19-26, phase3c, rbtree, diagnostic, fusion

Model Commands:
    model, gemm, lora, rmsnorm, http-chat, p2p

GPU Commands:
    gpu, amphibious

Debug Commands:
    debug-rms, debug-acc, debug-micro, debug-rax, debug-hang
    minimal, direct, stub

Batch Operations:
    run-all         Run all IDE, test, and benchmark tools
    test-all        Run all test tools
    benchmark-all   Run all benchmarks
    compiler-all    Run all compilers
    titan-all       Run all Titan tools
    gpu-all         Run all GPU tools
    debug-all       Run all debug tools

EXAMPLES:
    .\Unified-CLI.ps1 ide
    .\Unified-CLI.ps1 titan
    .\Unified-CLI.ps1 python myscript.py
    .\Unified-CLI.ps1 benchmark
    .\Unified-CLI.ps1 test-all

"@ -ForegroundColor Cyan
}

# Check if unified executable exists
if (-not (Test-Path $UnifiedExe)) {
    Write-Error "Unified CLI not found at: $UnifiedExe"
    Write-Error "Please ensure RawrXD_Unified.exe is built."
    exit 1
}

# Process arguments
if ($Arguments.Count -eq 0) {
    # No arguments - launch interactive mode
    & $UnifiedExe
}
elseif ($Arguments[0] -eq "--help" -or $Arguments[0] -eq "-h" -or $Arguments[0] -eq "/?") {
    Show-Help
}
elseif ($Arguments[0] -eq "--status") {
    & $UnifiedExe --status
}
elseif ($Arguments[0] -eq "--tools") {
    & $UnifiedExe --tools
}
elseif ($Arguments[0] -eq "--compilers") {
    & $UnifiedExe --compilers
}
else {
    # Pass all arguments to the unified CLI
    & $UnifiedExe @Arguments
}
