# ============================================================================
# generate_version_manifest.ps1 - Version Manifest Generator
# ============================================================================
# Generates version_manifest.json and build_info.txt for release
# ============================================================================

param(
    [string]$OutputDir = ".",
    [string]$Version = "1.0.0"
)

$ErrorActionPreference = "Stop"

# ============================================================================
# Helper Functions
# ============================================================================
function Get-GitCommit {
    try {
        $commit = git rev-parse HEAD 2>$null
        return $commit
    } catch {
        return "unknown"
    }
}

function Get-GitBranch {
    try {
        $branch = git rev-parse --abbrev-ref HEAD 2>$null
        return $branch
    } catch {
        return "unknown"
    }
}

function Get-BuildDate {
    return Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
}

function Get-CommandRegistryHash {
    try {
        $files = Get-ChildItem -Path "src\core\*command*" -Recurse -Include "*.cpp", "*.hpp", "*.h" 2>$null
        if ($files) {
            $hash = $files | Get-FileHash -Algorithm SHA256 | Select-Object -ExpandProperty Hash
            $combined = $hash -join ""
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($combined)
            $sha256 = [System.Security.Cryptography.SHA256]::Create()
            $hashBytes = $sha256.ComputeHash($bytes)
            return [BitConverter]::ToString($hashBytes).Replace("-", "").ToLower()
        }
    } catch {}
    return "unknown"
}

function Get-CompilerInfo {
    try {
        $cl = & cl 2>&1 | Select-Object -First 1
        if ($cl -match "Version\s+(\d+\.\d+)") {
            return "MSVC $($matches[1])"
        }
    } catch {}
    return "unknown"
}

function Get-CMakeVersion {
    try {
        $cmake = cmake --version 2>$null | Select-Object -First 1
        if ($cmake -match "(\d+\.\d+\.\d+)") {
            return $matches[1]
        }
    } catch {}
    return "unknown"
}

# ============================================================================
# Generate version_manifest.json
# ============================================================================
$manifest = @{
    version = $Version
    build_date = Get-BuildDate
    git_commit = Get-GitCommit
    git_branch = Get-GitBranch
    command_registry_hash = Get-CommandRegistryHash
    runtime_abi_version = "1.0"
    model_engine_abi = "1.0"
    
    components = @{
        ghost_text = "1.0.0"
        ai_bridge = "1.0.0"
        ai_settings_dialog = "1.0.0"
        inference_engine = "1.0.0"
        compression = "1.0.0"
        vulkan_loader = "1.0.0"
        zlib_loader = "1.0.0"
        lsp_ui = "1.0.0"
        ansi_terminal = "1.0.0"
        git_integration = "1.0.0"
        project_explorer = "1.0.0"
    }
    
    build_environment = @{
        compiler = Get-CompilerInfo
        cmake_version = Get-CMakeVersion
        platform = "Windows"
        architecture = "x64"
    }
    
    capabilities = @{
        vulkan_runtime = $true
        zlib_runtime = $true
        gpu_acceleration = $true
        cpu_fallback = $true
        streaming_inference = $true
        ghost_text = $true
        lsp_support = $true
    }
}

$manifestJson = $manifest | ConvertTo-Json -Depth 10
$manifestPath = Join-Path $OutputDir "version_manifest.json"
$manifestJson | Out-File -FilePath $manifestPath -Encoding UTF8

Write-Host "Generated: $manifestPath" -ForegroundColor Green

# ============================================================================
# Generate build_info.txt
# ============================================================================
$buildInfo = @"
RawrXD IDE Build Information
============================

Version: $Version
Build Date: $(Get-BuildDate)
Git Commit: $(Get-GitCommit)
Git Branch: $(Get-GitBranch)

Build Environment
-----------------
Compiler: $(Get-CompilerInfo)
CMake: $(Get-CMakeVersion)
Platform: Windows x64

Component Versions
------------------
Ghost Text: 1.0.0
AI Bridge: 1.0.0
AI Settings Dialog: 1.0.0
Inference Engine: 1.0.0
Compression: 1.0.0
Vulkan Loader: 1.0.0
ZLIB Loader: 1.0.0
LSP UI: 1.0.0
ANSI Terminal: 1.0.0
Git Integration: 1.0.0
Project Explorer: 1.0.0

Capabilities
------------
- Vulkan Runtime Loading: Yes
- ZLIB Runtime Loading: Yes
- GPU Acceleration: Yes
- CPU Fallback: Yes
- Streaming Inference: Yes
- Ghost Text: Yes
- LSP Support: Yes

ABI Versions
------------
Runtime ABI: 1.0
Model Engine ABI: 1.0

Command Registry Hash: $(Get-CommandRegistryHash)
"@

$buildInfoPath = Join-Path $OutputDir "build_info.txt"
$buildInfo | Out-File -FilePath $buildInfoPath -Encoding UTF8

Write-Host "Generated: $buildInfoPath" -ForegroundColor Green

# ============================================================================
# Generate RawrXD_RUNTIME_DEPENDENCIES.txt
# ============================================================================
$dependencies = @"
RawrXD IDE Runtime Dependencies
===============================

REQUIRED (System)
-----------------
- Windows 10/11 (64-bit)
- MSVC Runtime (vcruntime140.dll, msvcp140.dll)
- kernel32.dll
- user32.dll
- gdi32.dll
- shell32.dll
- ole32.dll
- oleaut32.dll
- uuid.dll
- comdlg32.dll
- advapi32.dll
- version.dll
- ws2_32.dll

OPTIONAL (Runtime Loaded)
-------------------------
- vulkan-1.dll
  * Purpose: GPU acceleration for inference
  * Source: Vulkan SDK or graphics driver
  * Fallback: CPU inference if not present
  
- zlib1.dll
  * Purpose: Checkpoint compression
  * Source: zlib.net or system package
  * Fallback: Uncompressed checkpoints if not present

BUNDLED
-------
- None (all dependencies are system or runtime-loaded)

NOTES
-----
- RawrXD IDE uses runtime loading for optional components
- No external SDKs required at build time
- CPU fallback always available
- GPU acceleration requires compatible hardware + drivers
"@

$depsPath = Join-Path $OutputDir "RawrXD_RUNTIME_DEPENDENCIES.txt"
$dependencies | Out-File -FilePath $depsPath -Encoding UTF8

Write-Host "Generated: $depsPath" -ForegroundColor Green

Write-Host "`nVersion manifest generation complete!" -ForegroundColor Green
Write-Host "Output directory: $(Resolve-Path $OutputDir)" -ForegroundColor Cyan
