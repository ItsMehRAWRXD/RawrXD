# RawrXD CMake Generator
# Automatically generates and updates CMakeLists.txt based on discovered source files

param(
    [string]$SourceDir = "D:\rawrxd\src",
    [string]$OutputFile = "D:\rawrxd\CMakeLists.txt",
    [switch]$UpdateExisting,
    [switch]$DetectQt,
    [switch]$DetectCUDA,
    [switch]$DetectVulkan,
    [string[]]$ExcludePatterns = @("*.tmp", "*.bak", "test_*", "*_test.*"),
    [string]$ProjectName = "RawrXD",
    [string]$Version = "3.2.0",
    [switch]$Backup,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

$script:GenState = @{
    StartTime = Get-Date
    FilesDiscovered = 0
    FilesAdded = 0
    TargetsCreated = 0
    Warnings = @()
}

function Write-Status { param([string]$Message) Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[✓] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "[✗] $Message" -ForegroundColor Red }

function Get-SourceFiles {
    $extensions = @("*.cpp", "*.c", "*.cc", "*.h", "*.hpp", "*.asm", "*.S")
    $files = @()
    
    foreach ($ext in $extensions) {
        $found = Get-ChildItem -Path $SourceDir -Recurse -Filter $ext -File -ErrorAction SilentlyContinue
        $files += $found
    }
    
    # Filter out excluded patterns
    $filtered = $files | Where-Object {
        $file = $_
        $excluded = $false
        foreach ($pattern in $ExcludePatterns) {
            if ($file.Name -like $pattern) {
                $excluded = $true
                break
            }
        }
        -not $excluded
    }
    
    return $filtered | Select-Object -ExpandProperty FullName | Sort-Object
}

function Categorize-SourceFiles {
    param([array]$Files)
    
    $categories = @{
        Core = @()
        GGML = @()
        GPU = @()
        Vulkan = @()
        CUDA = @()
        ASM = @()
        UI = @()
        Tests = @()
        Utils = @()
    }
    
    foreach ($file in $Files) {
        $relPath = $file.Replace($SourceDir, "").TrimStart("\")
        $lowerPath = $relPath.ToLower()
        
        if ($lowerPath -match "test|spec|mock") {
            $categories.Tests += $relPath
        }
        elseif ($lowerPath -match "\.asm$|\.s$") {
            $categories.ASM += $relPath
        }
        elseif ($lowerPath -match "ggml|gguf|tensor|compute") {
            $categories.GGML += $relPath
        }
        elseif ($lowerPath -match "vulkan|vk_|shader") {
            $categories.Vulkan += $relPath
        }
        elseif ($lowerPath -match "cuda|cudnn|gpu") {
            $categories.CUDA += $relPath
        }
        elseif ($lowerPath -match "qt|widget|dialog|window\.h") {
            $categories.UI += $relPath
        }
        elseif ($lowerPath -match "core|kernel|engine|main") {
            $categories.Core += $relPath
        }
        elseif ($lowerPath -match "util|helper|common") {
            $categories.Utils += $relPath
        }
        else {
            $categories.Core += $relPath
        }
    }
    
    return $categories
}

function Generate-CMakeLists {
    param([hashtable]$Categories)
    
    $cmake = @"
# RawrXD Vision & Generation System
# Auto-generated CMakeLists.txt
# Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
# Version: $Version

cmake_minimum_required(VERSION 3.16)
project($ProjectName VERSION $Version LANGUAGES CXX C)

# C++ Standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build options
option(BUILD_TESTS "Build test suite" ON)
option(BUILD_GPU "Build GPU backends" ON)
option(BUILD_VULKAN "Build Vulkan backend" ON)
option(BUILD_CUDA "Build CUDA backend" OFF)
option(BUILD_QT_UI "Build Qt-based UI" OFF)

# Compiler flags
if(MSVC)
    add_compile_options(/W4 /WX- /permissive- /Zc:__cplusplus)
    add_compile_options(/arch:AVX2)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
    add_compile_options(-march=native)
endif()

# Include directories
include_directories(
    `${CMAKE_SOURCE_DIR}/include
    `${CMAKE_SOURCE_DIR}/src
)

"@

    # Core library
    if ($Categories.Core.Count -gt 0) {
        $cmake += @"

# Core Library
set(CORE_SOURCES
"@
        foreach ($file in $Categories.Core) {
    $cmake += "    src/$file`n"
}
        $cmake += @"
)

add_library(`${PROJECT_NAME}_core STATIC `${CORE_SOURCES})
target_include_directories(`${PROJECT_NAME}_core PUBLIC include)

"@
    }

    # GGML Backend
    if ($Categories.GGML.Count -gt 0) {
        $cmake += @"
# GGML Backend
set(GGML_SOURCES
"@
        foreach ($file in $Categories.GGML) {
    $cmake += "    src/$file`n"
}
        $cmake += @"
)

add_library(ggml STATIC `${GGML_SOURCES})
target_link_libraries(ggml PUBLIC `${PROJECT_NAME}_core)

"@
    }

    # ASM Kernels
    if ($Categories.ASM.Count -gt 0) {
        $cmake += @"
# ASM Optimized Kernels
enable_language(ASM_MASM)
set(ASM_SOURCES
"@
        foreach ($file in $Categories.ASM) {
    $cmake += "    src/$file`n"
}
        $cmake += @"
)

add_library(asm_kernels OBJECT `${ASM_SOURCES})

"@
    }

    # Vulkan Backend
    if ($DetectVulkan -and $Categories.Vulkan.Count -gt 0) {
        $cmake += @"
# Vulkan Backend
if(BUILD_VULKAN)
    find_package(Vulkan REQUIRED)
    set(VULKAN_SOURCES
"@
        foreach ($file in $Categories.Vulkan) {
    $cmake += "        src/$file`n"
}
        $cmake += @"
    )
    add_library(vulkan_backend STATIC `${VULKAN_SOURCES})
    target_link_libraries(vulkan_backend PUBLIC Vulkan::Vulkan)
endif()

"@
    }

    # CUDA Backend
    if ($DetectCUDA -and $Categories.CUDA.Count -gt 0) {
        $cmake += @"
# CUDA Backend
if(BUILD_CUDA)
    enable_language(CUDA)
    find_package(CUDA REQUIRED)
    set(CUDA_SOURCES
"@
        foreach ($file in $Categories.CUDA) {
    $cmake += "        src/$file`n"
}
        $cmake += @"
    )
    add_library(cuda_backend STATIC `${CUDA_SOURCES})
    set_target_properties(cuda_backend PROPERTIES CUDA_SEPARABLE_COMPILATION ON)
endif()

"@
    }

    # Qt UI
    if ($DetectQt -and $Categories.UI.Count -gt 0) {
        $cmake += @"
# Qt UI
if(BUILD_QT_UI)
    find_package(Qt6 REQUIRED COMPONENTS Core Widgets)
    set(UI_SOURCES
"@
        foreach ($file in $Categories.UI) {
    $cmake += "        src/$file`n"
}
        $cmake += @"
    )
    add_executable(Win32IDE `${UI_SOURCES})
    target_link_libraries(Win32IDE PRIVATE Qt6::Core Qt6::Widgets)
endif()

"@
    }

    # Test Suite
    if ($Categories.Tests.Count -gt 0) {
        $cmake += @"
# Test Suite
if(BUILD_TESTS)
    enable_testing()
    find_package(GTest REQUIRED)
    set(TEST_SOURCES
"@
        foreach ($file in $Categories.Tests) {
    $cmake += "        src/$file`n"
}
        $cmake += @"
    )
    add_executable(test_suite `${TEST_SOURCES})
    target_link_libraries(test_suite PRIVATE GTest::gtest_main `${PROJECT_NAME}_core)
    add_test(NAME RawrXDTests COMMAND test_suite)
endif()

"@
    }

    # Main executable
    $cmake += @"
# Main Executable
add_executable(`${PROJECT_NAME}_cli src/main.cpp)
target_link_libraries(`${PROJECT_NAME}_cli PRIVATE
    `${PROJECT_NAME}_core
"@
    if ($Categories.GGML.Count -gt 0) { $cmake += "    ggml`n" }
    if ($Categories.ASM.Count -gt 0) { $cmake += "    asm_kernels`n" }
    $cmake += @"
)

# Installation
install(TARGETS `${PROJECT_NAME}_cli DESTINATION bin)
install(DIRECTORY include/ DESTINATION include)

# Print configuration
message(STATUS "RawrXD Configuration:")
message(STATUS "  Version: `${PROJECT_VERSION}")
message(STATUS "  Build type: `${CMAKE_BUILD_TYPE}")
message(STATUS "  Tests: `${BUILD_TESTS}")
message(STATUS "  GPU: `${BUILD_GPU}")
message(STATUS "  Vulkan: `${BUILD_VULKAN}")
message(STATUS "  CUDA: `${BUILD_CUDA}")
message(STATUS "  Qt UI: `${BUILD_QT_UI}")
"@

    return $cmake
}

function Update-ExistingCMake {
    param([string]$Content, [hashtable]$Categories)
    
    if (-not (Test-Path $OutputFile)) {
        return $Content
    }
    
    $existing = Get-Content $OutputFile -Raw
    
    # Preserve custom sections
    $customSections = @{}
    if ($existing -match "# BEGIN CUSTOM[\s\S]*?# END CUSTOM") {
        $customSections["CUSTOM"] = $Matches[0]
    }
    
    # Merge with existing
    $updated = $Content
    
    foreach ($section in $customSections.GetEnumerator()) {
        $updated = $updated -replace "# Place for $($section.Key)", $section.Value
    }
    
    return $updated
}

function Backup-CMakeLists {
    if ($Backup -and (Test-Path $OutputFile)) {
        $backupFile = "$OutputFile.backup.$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        Copy-Item $OutputFile $backupFile
        Write-Success "Backup created: $backupFile"
    }
}

function Test-CMakeSyntax {
    param([string]$Content)
    
    $tempFile = [System.IO.Path]::GetTempFileName()
    $tempFile = [System.IO.Path]::ChangeExtension($tempFile, ".txt")
    $Content | Out-File $tempFile -Encoding UTF8
    
    try {
        # Basic syntax validation
        $issues = @()
        
        # Check for balanced parentheses
        $openParens = ($Content -split "\(").Count - 1
        $closeParens = ($Content -split "\)").Count - 1
        if ($openParens -ne $closeParens) {
            $issues += "Unbalanced parentheses"
        }
        
        # Check for required sections
        if (-not ($Content -match "cmake_minimum_required")) {
            $issues += "Missing cmake_minimum_required"
        }
        if (-not ($Content -match "project\s*\(")) {
            $issues += "Missing project declaration"
        }
        
        return @{ Valid = $issues.Count -eq 0; Issues = $issues }
    }
    finally {
        Remove-Item $tempFile -ErrorAction SilentlyContinue
    }
}

# Main execution
function Main {
    Write-Host "RawrXD CMake Generator" -ForegroundColor Cyan
    Write-Host "=====================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Status "Discovering source files in $SourceDir..."
    $files = Get-SourceFiles
    $script:GenState.FilesDiscovered = $files.Count
    
    Write-Success "Found $($files.Count) source files"
    
    Write-Status "Categorizing files..."
    $categories = Categorize-SourceFiles -Files $files
    
    Write-Host ""
    Write-Host "Categories:" -ForegroundColor White
    foreach ($cat in $categories.GetEnumerator() | Sort-Object Key) {
        if ($cat.Value.Count -gt 0) {
            Write-Host "  $($cat.Key): $($cat.Value.Count) files" -ForegroundColor Gray
        }
    }
    
    Write-Host ""
    Write-Status "Generating CMakeLists.txt..."
    $cmakeContent = Generate-CMakeLists -Categories $categories
    
    if ($UpdateExisting -and (Test-Path $OutputFile)) {
        $cmakeContent = Update-ExistingCMake -Content $cmakeContent -Categories $categories
    }
    
    # Validate syntax
    $validation = Test-CMakeSyntax -Content $cmakeContent
    if (-not $validation.Valid) {
        Write-Warning "CMake syntax issues detected:"
        foreach ($issue in $validation.Issues) {
            Write-Host "  - $issue" -ForegroundColor Yellow
        }
    }
    
    if ($DryRun) {
        Write-Host ""
        Write-Warning "DRY RUN - No changes made"
        Write-Host ""
        Write-Host "Generated CMakeLists.txt preview (first 50 lines):" -ForegroundColor White
        ($cmakeContent -split "`n" | Select-Object -First 50) -join "`n" | Write-Host
    } else {
        Backup-CMakeLists
        $cmakeContent | Out-File $OutputFile -Encoding UTF8
        Write-Success "CMakeLists.txt generated: $OutputFile"
    }
    
    Write-Host ""
    Write-Host "Summary:" -ForegroundColor White
    Write-Host "  Files discovered: $($script:GenState.FilesDiscovered)" -ForegroundColor Gray
    Write-Host "  Categories: $($categories.Count)" -ForegroundColor Gray
    Write-Host "  Output: $OutputFile" -ForegroundColor Gray
    
    Write-Host ""
    Write-Success "CMake generation complete!"
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor White
    Write-Host "  1. Review $OutputFile" -ForegroundColor Gray
    Write-Host "  2. mkdir build && cd build" -ForegroundColor Gray
    Write-Host "  3. cmake .." -ForegroundColor Gray
    Write-Host "  4. cmake --build . --parallel" -ForegroundColor Gray
}

Main
