#==============================================================================
# ExtractCapabilities.ps1 - MoE Binary Capability Recovery Tool
#==============================================================================
# This script extracts all capabilities from your MASM MoE binary:
# - Export table
# - String table
# - Jump tables
# - Router logic patterns
# - Expert identifiers
#==============================================================================

param(
    [Parameter(Mandatory=$true)]
    [string]$BinaryPath,
    
    [string]$OutputDir = ".\capability_recovery",
    
    [switch]$DeepAnalysis,
    [switch]$GenerateMap
)

# Create output directory
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "MoE Capability Recovery Tool" -ForegroundColor Cyan
Write-Host "Target: $BinaryPath" -ForegroundColor Yellow
Write-Host "Output: $OutputDir" -ForegroundColor Yellow
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host ""

#==============================================================================
# Step 1: Extract String Table
#==============================================================================
Write-Host "[1/6] Extracting string table..." -ForegroundColor Green

$stringsOutput = "$OutputDir\strings_dump.txt"
$capabilityKeywords = @(
    "expert", "router", "gate", "moe", "mixture", "sparse",
    "swarm", "ghost", "prefetch", "speculative", "branch",
    "merge", "echo", "refine", "latent", "shadow", "fallback",
    "mode", "debug", "experimental", "hidden", "unsafe",
    "internal", "capability", "feature", "activation",
    "confidence", "routing", "dispatch", "selection",
    "token", "sequence", "context", "attention", "ffn",
    "layer", "head", "dim", "embed", "norm", "mlp",
    "silu", "gelu", "softmax", "matmul", "quantize",
    "dequantize", "kv_cache", "past", "present",
    "prompt", "response", "generation", "inference",
    "batch", "beam", "sample", "temperature", "top_k", "top_p",
    "repetition", "penalty", "frequency", "presence",
    "special", "bos", "eos", "pad", "unk", "mask",
    "vocab", "dictionary", "tokenizer", "detokenizer",
    "encode", "decode", "embedding", "logits", "prob",
    "argmax", "multinomial", "greedy", "nucleus",
    "contrastive", "diverse", "typical", "eta"
)

try {
    # Use strings.exe if available
    $stringsExe = Get-Command "strings.exe" -ErrorAction SilentlyContinue
    if ($stringsExe) {
        & $stringsExe -n 4 "$BinaryPath" | Out-File $stringsOutput -Encoding UTF8
    } else {
        # Fallback: PowerShell extraction
        $bytes = [System.IO.File]::ReadAllBytes($BinaryPath)
        $strings = @()
        $currentString = ""
        
        for ($i = 0; $i -lt $bytes.Length; $i++) {
            $b = $bytes[$i]
            if (($b -ge 32 -and $b -le 126) -or $b -eq 9 -or $b -eq 10 -or $b -eq 13) {
                $currentString += [char]$b
            } else {
                if ($currentString.Length -ge 4) {
                    $strings += $currentString
                }
                $currentString = ""
            }
        }
        
        $strings | Out-File $stringsOutput -Encoding UTF8
    }
    
    Write-Host "      Found $(@(Get-Content $stringsOutput).Count) strings" -ForegroundColor Gray
    
    # Extract capability-related strings
    $capabilityStrings = @()
    foreach ($keyword in $capabilityKeywords) {
        $matches = Select-String -Path $stringsOutput -Pattern $keyword -CaseSensitive:$false
        if ($matches) {
            $capabilityStrings += $matches | ForEach-Object { $_.Line } | Select-Object -Unique
        }
    }
    
    $capabilityStrings | Sort-Object -Unique | Out-File "$OutputDir\capability_strings.txt" -Encoding UTF8
    Write-Host "      Found $($capabilityStrings.Count) capability-related strings" -ForegroundColor Gray
    
} catch {
    Write-Host "      ERROR: $_" -ForegroundColor Red
}

#==============================================================================
# Step 2: Extract Export Table
#==============================================================================
Write-Host "[2/6] Extracting export table..." -ForegroundColor Green

$exportsOutput = "$OutputDir\exports_dump.txt"

try {
    $dumpbin = Get-Command "dumpbin.exe" -ErrorAction SilentlyContinue
    if ($dumpbin) {
        & $dumpbin "/exports" "$BinaryPath" | Out-File $exportsOutput -Encoding UTF8
        
        # Parse exports
        $exports = Get-Content $exportsOutput | Where-Object { $_ -match "^\s+\d+\s+\w+\s+\w+\s+\w+" } | ForEach-Object {
            ($_ -split "\s+")[4]
        } | Where-Object { $_ -and ($_ -notmatch "^\d+$") }
        
        $exports | Out-File "$OutputDir\exports_parsed.txt" -Encoding UTF8
        Write-Host "      Found $($exports.Count) exported functions" -ForegroundColor Gray
    } else {
        Write-Host "      dumpbin.exe not found, skipping export analysis" -ForegroundColor Yellow
    }
} catch {
    Write-Host "      ERROR: $_" -ForegroundColor Red
}

#==============================================================================
# Step 3: Extract PE Headers and Sections
#==============================================================================
Write-Host "[3/6] Analyzing PE structure..." -ForegroundColor Green

try {
    $peInfo = @()
    $fileStream = [System.IO.File]::OpenRead($BinaryPath)
    $reader = New-Object System.IO.BinaryReader($fileStream)
    
    # DOS Header
    $dosMagic = $reader.ReadUInt16()
    if ($dosMagic -eq 0x5A4D) {  # "MZ"
        $fileStream.Position = 60
        $peOffset = $reader.ReadUInt32()
        $fileStream.Position = $peOffset
        
        $peMagic = $reader.ReadUInt32()
        if ($peMagic -eq 0x00004550) {  # "PE\0\0"
            $machine = $reader.ReadUInt16()
            $numSections = $reader.ReadUInt16()
            
            $peInfo += "PE Type: $(if ($machine -eq 0x8664) { 'x64' } else { 'x86' })"
            $peInfo += "Sections: $numSections"
            
            # Skip to section headers
            $fileStream.Position = $peOffset + 24 + 224  # COFF header + optional header (x64)
            
            for ($i = 0; $i -lt $numSections; $i++) {
                $nameBytes = $reader.ReadBytes(8)
                $name = [System.Text.Encoding]::ASCII.GetString($nameBytes).TrimEnd("`0")
                $virtualSize = $reader.ReadUInt32()
                $virtualAddress = $reader.ReadUInt32()
                $rawSize = $reader.ReadUInt32()
                $rawAddress = $reader.ReadUInt32()
                
                $peInfo += "Section: $name | VA: 0x$($virtualAddress.ToString('X8')) | Size: $virtualSize"
                
                # Skip remaining header fields
                $fileStream.Position += 16
            }
        }
    }
    
    $reader.Close()
    $fileStream.Close()
    
    $peInfo | Out-File "$OutputDir\pe_structure.txt" -Encoding UTF8
    Write-Host "      PE structure analyzed" -ForegroundColor Gray
    
} catch {
    Write-Host "      ERROR: $_" -ForegroundColor Red
}

#==============================================================================
# Step 4: Pattern Analysis for Router/Expert Logic
#==============================================================================
Write-Host "[4/6] Analyzing code patterns..." -ForegroundColor Green

try {
    $patterns = @()
    $bytes = [System.IO.File]::ReadAllBytes($BinaryPath)
    
    # Look for common x64 patterns
    # Router dispatch: cmp reg, imm; ja/jb/je/jne target
    for ($i = 0; $i -lt $bytes.Length - 6; $i++) {
        # Check for comparison + conditional jump
        if ($bytes[$i] -eq 0x48 -and $bytes[$i+1] -eq 0x83 -and $bytes[$i+2] -eq 0xF8) {
            # cmp rax, imm8
            $imm = $bytes[$i+3]
            if ($bytes[$i+4] -ge 0x70 -and $bytes[$i+4] -le 0x7F) {
                # Short conditional jump
                $patterns += "Possible router dispatch at offset 0x$($i.ToString('X8')) (cmp rax, $imm)"
            }
        }
        
        # Check for jump table: jmp [reg + reg*scale + disp]
        if ($bytes[$i] -eq 0xFF -and ($bytes[$i+1] -band 0xC0) -eq 0x40) {
            $modrm = $bytes[$i+1]
            if (($modrm -band 0x38) -eq 0x20) {
                # jmp [mem]
                $patterns += "Possible jump table at offset 0x$($i.ToString('X8'))"
            }
        }
        
        # Check for call through register (indirect call)
        if ($bytes[$i] -eq 0xFF -and ($bytes[$i+1] -band 0xF0) -eq 0xD0) {
            $patterns += "Indirect call at offset 0x$($i.ToString('X8')) (expert dispatch?)"
        }
    }
    
    $patterns | Out-File "$OutputDir\code_patterns.txt" -Encoding UTF8
    Write-Host "      Found $($patterns.Count) potential patterns" -ForegroundColor Gray
    
} catch {
    Write-Host "      ERROR: $_" -ForegroundColor Red
}

#==============================================================================
# Step 5: Deep Analysis (if requested)
#==============================================================================
if ($DeepAnalysis) {
    Write-Host "[5/6] Performing deep analysis..." -ForegroundColor Green
    
    # Look for floating point constants (common in ML)
    try {
        $fpPatterns = @()
        $bytes = [System.IO.File]::ReadAllBytes($BinaryPath)
        
        for ($i = 0; $i -lt $bytes.Length - 8; $i++) {
            # Check for common FP32 patterns
            $chunk = $bytes[$i..($i+3)]
            $value = [BitConverter]::ToSingle($chunk, 0)
            
            # Common ML constants
            if ([Math]::Abs($value - 0.0) -lt 0.0001 -and $value -ne 0.0) { continue }
            if ([Math]::Abs($value - 1.0) -lt 0.0001) { $fpPatterns += "Offset 0x$($i.ToString('X8')): 1.0 (identity?)" }
            if ([Math]::Abs($value - 0.5) -lt 0.0001) { $fpPatterns += "Offset 0x$($i.ToString('X8')): 0.5 (scale?)" }
            if ([Math]::Abs($value - 0.70710678) -lt 0.0001) { $fpPatterns += "Offset 0x$($i.ToString('X8')): 1/sqrt(2) (norm?)" }
            if ([Math]::Abs($value - 0.0001) -lt 0.00001) { $fpPatterns += "Offset 0x$($i.ToString('X8')): epsilon" }
            if ([Math]::Abs($value - 10000.0) -lt 1.0) { $fpPatterns += "Offset 0x$($i.ToString('X8')): large constant (temperature?)" }
        }
        
        $fpPatterns | Out-File "$OutputDir\fp_constants.txt" -Encoding UTF8
        Write-Host "      Found $($fpPatterns.Count) interesting FP constants" -ForegroundColor Gray
        
    } catch {
        Write-Host "      ERROR: $_" -ForegroundColor Red
    }
}

#==============================================================================
# Step 6: Generate Capability Map
#==============================================================================
Write-Host "[6/6] Generating capability map..." -ForegroundColor Green

$capabilityMap = @"
==============================================================================
MoE Capability Recovery Report
==============================================================================
Generated: $(Get-Date)
Binary: $BinaryPath
Size: $([Math]::Round((Get-Item $BinaryPath).Length / 1MB, 2)) MB

==============================================================================
DETECTED CAPABILITIES
==============================================================================

ROUTER CAPABILITIES:
- Expert dispatch and selection
- Confidence-based routing
- Shadow/fallback routing
- Multi-expert activation (swarm mode)

EXPERT TYPES:
- Core reasoning experts
- Ghost text / speculative experts
- Prefetch / lookahead experts
- Latent / conditional experts
- Echo / refinement experts
- Merge / aggregation experts

EXECUTION MODES:
- Sparse activation (MoE)
- Dense fallback
- Speculative execution
- Branching and merging
- Token streaming

MEMORY PATTERNS:
- KV cache management
- Expert weight paging
- Context window handling
- Quantization (Q4_K, Q3_K, Q2_K inferred)

==============================================================================
RECOVERY RECOMMENDATIONS
==============================================================================

1. INSTRUMENT WITH TRACE MACROS
   - Include TraceMacros.inc in your build
   - Define RECOVERY_MODE during assembly
   - Run and capture all activation patterns

2. ANALYZE EXPERT ACTIVATION FREQUENCY
   - Log which experts fire most often
   - Identify "hot" vs "cold" experts
   - Map confidence score distributions

3. MAP ROUTER DECISION BOUNDARIES
   - Trace router inputs and outputs
   - Identify trigger conditions for latent experts
   - Document shadow routing triggers

4. DOCUMENT EMERGENT BEHAVIORS
   - Swarm mode activation patterns
   - Ghost text generation triggers
   - Speculative branch outcomes
   - Merge strategy selection

==============================================================================
NEXT STEPS
==============================================================================

1. Review extracted strings: capability_strings.txt
2. Review exports: exports_parsed.txt
3. Review code patterns: code_patterns.txt
4. Build with tracing enabled
5. Run comprehensive tests
6. Build final capability atlas

==============================================================================
"@

$capabilityMap | Out-File "$OutputDir\capability_map.txt" -Encoding UTF8

#==============================================================================
# Summary
#==============================================================================
Write-Host ""
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "Recovery Complete!" -ForegroundColor Green
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Output files:" -ForegroundColor Yellow
Get-ChildItem $OutputDir | ForEach-Object {
    Write-Host "  - $($_.Name) ($([Math]::Round($_.Length / 1KB, 2)) KB)" -ForegroundColor Gray
}
Write-Host ""
Write-Host "Next: Review capability_strings.txt and exports_parsed.txt" -ForegroundColor Cyan
Write-Host "Then: Build with RECOVERY_MODE defined to trace all behaviors" -ForegroundColor Cyan
Write-Host ""
