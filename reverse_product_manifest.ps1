# reverse_product_manifest.ps1
# RawrXD reverse-completion inspector.
#
# Purpose:
#   Inspect the real source tree and determine which product responsibilities
#   are actually implemented, partially implemented, absent, or not applicable.
#
# Rules:
#   - Never mark DONE from filename presence alone.
#   - Require implementation-pattern evidence.
#   - Header/declaration-only evidence => PARTIAL.
#   - TODO/stub/throw/not-implemented dominance => PARTIAL/STUB.
#   - No evidence => MISSING.
#   - Optional capability absent from product scope => NOT_APPLICABLE only when
#     explicitly declared optional below.
#
# Usage:
#   pwsh .\reverse_product_manifest.ps1
#   pwsh .\reverse_product_manifest.ps1 -Root "G:\~dev\rawrxd"
#   pwsh .\reverse_product_manifest.ps1 -Root "G:\~dev\rawrxd" -Json
#
# Output:
#   evidence\PRODUCT_REVERSE_MANIFEST_001\
#       MANIFEST.txt
#       MANIFEST.json
#       MISSING.txt
#       PARTIAL.txt
#       DONE.txt
#       NEXT_15.txt

[CmdletBinding()]
param(
    [string]$Root = "G:\~dev\rawrxd",
    [switch]$Json,
    [int]$NextCount = 15
)

$ErrorActionPreference = "Stop"

$Root = (Resolve-Path $Root).Path
$EvidenceRoot = Join-Path $Root "evidence\PRODUCT_REVERSE_MANIFEST_001"
New-Item -ItemType Directory -Force -Path $EvidenceRoot | Out-Null

# ---------------------------------------------------------------------------
# File inventory
# ---------------------------------------------------------------------------

$SourceExtensions = @(
    ".cpp", ".cc", ".cxx", ".c",
    ".hpp", ".hh", ".hxx", ".h",
    ".asm", ".inc",
    ".ps1", ".psm1", ".bat", ".cmd",
    ".html", ".htm", ".js", ".mjs", ".ts", ".tsx",
    ".css",
    ".json", ".toml", ".yaml", ".yml",
    ".cmake"
)

# Live product tree only. Archive dumps would promote names from reconstructed
# stubs and are skipped the same way as build outputs.
$SkipDirs = @(
    "\.git\",
    "\build\",
    "\build-fd\",
    "\build3\",
    "\out\",
    "\dist\",
    "\node_modules\",
    "\evidence\",
    "\.vs\",
    "\.idea\",
    "\history\",
    "\reconstructed\",
    "\runoff\",
    "\Full Source\",
    "\asm_obj_sweep\",
    "\release\",
    "\native_toolchain\",
    "\backup\",
    "\certs\archive\"
)

$Files = Get-ChildItem -LiteralPath $Root -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object {
        $ext = $_.Extension.ToLowerInvariant()
        $full = $_.FullName
        ($SourceExtensions -contains $ext) -and
        -not ($SkipDirs | Where-Object { $full -like "*$_*" })
    }

Write-Host "ROOT=$Root"
Write-Host "SOURCE_FILES=$($Files.Count)"

# Cache text once.
$TextCache = @{}

function Get-FileText {
    param([System.IO.FileInfo]$File)

    if ($TextCache.ContainsKey($File.FullName)) {
        return $TextCache[$File.FullName]
    }

    try {
        $text = [IO.File]::ReadAllText($File.FullName)
    }
    catch {
        $text = ""
    }

    $TextCache[$File.FullName] = $text
    return $text
}

# ---------------------------------------------------------------------------
# Evidence matching
# ---------------------------------------------------------------------------

function Find-Evidence {
    param(
        [string[]]$Patterns,
        [string[]]$FilePatterns = @("*"),
        [int]$Limit = 20
    )

    $hits = [System.Collections.Generic.List[object]]::new()

    foreach ($file in $Files) {
        $relative = $file.FullName.Substring($Root.Length).TrimStart("\")

        $fileAllowed = $false
        foreach ($fp in $FilePatterns) {
            if ($relative -like $fp -or $file.Name -like $fp) {
                $fileAllowed = $true
                break
            }
        }

        if (-not $fileAllowed) {
            continue
        }

        $text = Get-FileText $file
        if ([string]::IsNullOrEmpty($text)) {
            continue
        }

        foreach ($pattern in $Patterns) {
            $m = [regex]::Match(
                $text,
                $pattern,
                [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
            )

            if ($m.Success) {
                $line =
                    ($text.Substring(0, $m.Index) -split "`n").Count

                $hits.Add([pscustomobject]@{
                    File    = $relative
                    Line    = $line
                    Pattern = $pattern
                    Match   = ($m.Value -replace "\s+", " ").Trim()
                })

                break
            }
        }

        if ($hits.Count -ge $Limit) {
            break
        }
    }

    return @($hits)
}

function Get-StubEvidence {
    param([object[]]$Evidence)

    $StubPatterns = @(
        '\bTODO\b',
        '\bFIXME\b',
        '\bXXX\b',
        '\bNOT_IMPLEMENTED\b',
        '\bUNIMPLEMENTED\b',
        'throw\s+std::(runtime_error|logic_error)\s*\([^)]*(not implemented|todo)',
        'return\s+false\s*;\s*//\s*(stub|todo)',
        'return\s+nullptr\s*;\s*//\s*(stub|todo)',
        '\bstub\b',
        '\bplaceholder\b',
        '\bfake\b',
        '\bmock\b'
    )

    $result = [System.Collections.Generic.List[object]]::new()

    foreach ($e in $Evidence) {
        $full = Join-Path $Root $e.File
        if (-not (Test-Path $full)) { continue }

        $text = [IO.File]::ReadAllText($full)

        foreach ($pattern in $StubPatterns) {
            if ([regex]::IsMatch(
                $text,
                $pattern,
                [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
            )) {
                $result.Add([pscustomobject]@{
                    File    = $e.File
                    Pattern = $pattern
                })
                break
            }
        }
    }

    return @($result)
}

# ---------------------------------------------------------------------------
# Reverse product definition
#
# Required evidence:
#   StrongPatterns: executable implementation evidence.
#   WeakPatterns: declaration / naming / interface evidence.
#
# DONE:
#   strong implementation evidence and not stub-dominated.
#
# PARTIAL:
#   weak evidence only, or implementation exists with obvious stub markers.
#
# MISSING:
#   neither.
#
# NOT_APPLICABLE:
#   only explicit optional features can receive this state.
# ---------------------------------------------------------------------------

$Manifest = @(

    # 1-15 Product core
    @{
        Id=1; Name="Single ProductRun entrypoint"
        Strong=@(
            '\bProductRun\s*\([^;{]*\)\s*(?:noexcept\s*)?\{',
            '\bRunProduct\s*\([^;{]*\)\s*(?:noexcept\s*)?\{'
        )
        Weak=@('\bProductRun\b','\bRunProduct\b')
    },
    @{
        Id=2; Name="CLI wired to production runtime"
        Strong=@(
            '\bProductRun\s*\(',
            '\bgenerateStream\s*\(',
            '\brunModel\s*\('
        )
        Weak=@('\brawr\s+run\b','\bCLI\b')
        Files=@('*cli*','*main*','*rawr*')
    },
    @{
        Id=3; Name="IDE wired to production runtime"
        Strong=@(
            '\bProductRun\s*\(',
            '\bgenerateStream\s*\(',
            '\bGenerationRequest\b'
        )
        Weak=@('\bIDE\b','\bchat\b','\binference\b')
        Files=@('*ide*','*win32*','*chat*','*ui*')
    },
    @{
        Id=4; Name="Agent wired to production runtime"
        Strong=@(
            '\bProductRun\s*\(',
            '\bgenerateStream\s*\(',
            '\bAgent.*(?:infer|generate|run)\s*\('
        )
        Weak=@('\bAgent\b','\bPlanner\b')
        Files=@('*agent*','*planner*','*tool*')
    },
    @{
        Id=5; Name="Central model resolver"
        Strong=@(
            '\bResolveModel\s*\([^;{]*\)\s*\{',
            '\bresolveModel\s*\([^;{]*\)\s*\{',
            '\bresolveModelPath\s*\([^;{]*\)\s*\{'
        )
        Weak=@('\bResolveModel\b','\bresolveModelPath\b')
    },
    @{
        Id=6; Name="Central GGUF loader"
        Strong=@(
            '\b(?:Load|Open)GGUF\s*\([^;{]*\)\s*\{',
            '\bloadModel\s*\([^;{]*\)\s*\{'
        )
        Weak=@('\bGGUF\b','\bloadModel\b')
    },
    @{
        Id=7; Name="Tokenizer construction"
        Strong=@(
            '\b(?:Build|Create|Load)Tokenizer\s*\([^;{]*\)\s*\{',
            '\btokenize\s*\([^;{]*\)\s*\{',
            '\bdecodeToken\s*\([^;{]*\)\s*\{'
        )
        Weak=@('\bTokenizer\b','\btokenize\b')
    },
    @{
        Id=8; Name="KV cache implementation"
        Strong=@(
            '\bKVCache::[A-Za-z_]\w*\s*\(',
            '\bclass\s+KVCache\b',
            '\bstruct\s+KVCache\b'
        )
        Weak=@('\bKVCache\b','\bKV_CACHE\b')
    },
    @{
        Id=9; Name="Execution graph builder"
        Strong=@(
            '\bBuildExecutionGraph\s*\([^;{]*\)\s*\{',
            '\bExecutionGraph::[A-Za-z_]\w*\s*\(',
            '\bbuildGraph\s*\([^;{]*\)\s*\{'
        )
        Weak=@('\bExecutionGraph\b','\bBuildExecutionGraph\b')
    },
    @{
        Id=10; Name="Production GenerateStream"
        Strong=@(
            '\bgenerateStream\s*\([^;{]*\)\s*\{',
            '\bGenerateStream\s*\([^;{]*\)\s*\{'
        )
        Weak=@('\bgenerateStream\b','\bGenerateStream\b')
    },
    @{
        Id=11; Name="Forward layer implementation"
        Strong=@(
            '\bforwardLayer\s*\([^;{]*\)\s*\{',
            '\bForwardLayer\s*\([^;{]*\)\s*\{',
            '\bforwardMLA(?:Layer|Layers)\s*\([^;{]*\)\s*\{'
        )
        Weak=@('\bforwardLayer\b','\bForwardLayer\b','\bforwardMLA\b')
    },
    @{
        Id=12; Name="Sampler implementation"
        Strong=@(
            '\bSample\s*\([^;{]*\)\s*\{',
            '\bsampleToken\s*\([^;{]*\)\s*\{',
            '\bSampler::[A-Za-z_]\w*\s*\('
        )
        Weak=@('\bSampler\b','\bsampleToken\b')
    },
    @{
        Id=13; Name="Streaming token emitter"
        Strong=@(
            '\bEmitToken\s*\([^;{]*\)\s*\{',
            '\bemitToken\s*\([^;{]*\)\s*\{',
            '\bonToken\s*\('
        )
        Weak=@('\bEmitToken\b','\bonToken\b')
    },
    @{
        Id=14; Name="Unified teardown"
        Strong=@(
            '\b(?:Shutdown|Teardown|DestroyRuntime|UnloadModel)\s*\([^;{]*\)\s*\{',
            '\b~[A-Za-z_]\w*\s*\(\s*\)\s*\{'
        )
        Weak=@('\bteardown\b','\bshutdown\b','\bunload\b')
    },
    @{
        Id=15; Name="Canonical product receipt"
        Strong=@(
            '\bProductReceipt\b',
            'PRODUCT_PASS\s*=',
            'GENERATED_TOKENS\s*=',
            'EXIT_REASON\s*='
        )
        Weak=@('\bReceipt\b','PRODUCT_PASS')
    },

    # 16-30 Runtime/decode
    @{
        Id=16; Name="Runtime state owner"
        Strong=@('\bstruct\s+ProductRuntime\b','\bclass\s+ProductRuntime\b')
        Weak=@('\bProductRuntime\b')
    },
    @{
        Id=17; Name="Architecture dispatch"
        Strong=@(
            '\bARCH(?:ITECTURE)?\b.*\b(?:switch|if)\b',
            '\bArchitectureRegistry\b',
            '\bregisterArchitecture\b'
        )
        Weak=@('\bnemotron_h\b','\bqwen\b','\bllama\b')
    },
    @{
        Id=18; Name="Attention implementation"
        Strong=@(
            '\battention\s*\([^;{]*\)\s*\{',
            '\bcomputeAttention\s*\([^;{]*\)\s*\{',
            '\bforwardAttention\s*\([^;{]*\)\s*\{'
        )
        Weak=@('\battention\b')
    },
    @{
        Id=19; Name="FFN implementation"
        Strong=@(
            '\bforwardFFN\s*\([^;{]*\)\s*\{',
            '\bfeedForward\s*\([^;{]*\)\s*\{',
            '\bFFN::[A-Za-z_]\w*\s*\('
        )
        Weak=@('\bFFN\b','\bfeed.?forward\b')
    },
    @{
        Id=20; Name="SSM implementation"
        Strong=@(
            '\bSSM::[A-Za-z_]\w*\s*\(',
            '\bforwardSSM\s*\([^;{]*\)\s*\{',
            '\bssmStep\s*\([^;{]*\)\s*\{'
        )
        Weak=@('\bSSM\b','\bnemotron_h\b')
    },
    @{
        Id=21; Name="MoE router"
        Strong=@(
            '\bMoE.*Router\b',
            '\brouteExperts\s*\([^;{]*\)\s*\{',
            '\bselectExperts\s*\([^;{]*\)\s*\{'
        )
        Weak=@('\bMoE\b','\bexpert\b')
        Optional=$true
    },
    @{
        Id=22; Name="Logits implementation"
        Strong=@(
            '\bcomputeLogits\s*\([^;{]*\)\s*\{',
            '\bComputeLogits\s*\([^;{]*\)\s*\{'
        )
        Weak=@('\bcomputeLogits\b','\blogits\b')
    },
    @{
        Id=23; Name="Prompt prefill"
        Strong=@(
            '\bprefill\s*\([^;{]*\)\s*\{',
            '\bprocessPrompt\s*\([^;{]*\)\s*\{'
        )
        Weak=@('\bprefill\b','\bprompt\b')
    },
    @{
        Id=24; Name="Autoregressive decode loop"
        Strong=@(
            'for\s*\([^)]*(?:token|step)[^)]*\)\s*\{',
            'while\s*\([^)]*(?:token|generate|decode)[^)]*\)\s*\{'
        )
        Weak=@('\bdecode\b','\bmaxTokens\b')
    },
    @{
        Id=25; Name="Stop conditions"
        Strong=@(
            '\b(?:eos|stopToken|stopSequence|maxTokens)\b.*(?:break|return)',
            '\bshouldStop\s*\([^;{]*\)\s*\{'
        )
        Weak=@('\bEOS\b','\bmaxTokens\b')
    },
    @{
        Id=26; Name="Cancellation"
        Strong=@(
            '\b(?:cancelled|canceled|cancelRequested|stopRequested)\b.*(?:break|return)',
            '\bCancelGeneration\b'
        )
        Weak=@('\bcancel\b')
    },
    @{
        Id=27; Name="First failure ownership"
        Strong=@(
            '\bFAILED_OWNER\b',
            '\bFIRST_OWNER\b',
            '\bfailedStage\b',
            '\bfailedOwner\b'
        )
        Weak=@('\bowner\b','\bstage\b')
    },
    @{
        Id=28; Name="Normal completion state"
        Strong=@(
            'EXIT_REASON\s*=\s*["'']?COMPLETE',
            '\bSTREAM_FINISHED\b',
            '\bGenerationStatus::Complete\b'
        )
        Weak=@('\bCOMPLETE\b','\bfinished\b')
    },
    @{
        Id=29; Name="Generated-token accounting"
        Strong=@(
            '\bGENERATED_TOKENS\b',
            '\bgeneratedTokens\b\s*(?:\+\+|\+=)',
            '\btokenCount\b\s*(?:\+\+|\+=)'
        )
        Weak=@('\bgeneratedTokens\b','GENERATED_TOKENS')
    },
    @{
        Id=30; Name="Runtime error propagation"
        Strong=@(
            '\bResult<',
            '\bExpected<',
            '\bRuntimeError\b',
            '\bGenerationError\b'
        )
        Weak=@('\berror\b','\bexception\b')
    },

    # 31-45 Model/tensor system
    @{
        Id=31; Name="GGUF metadata parsing"
        Strong=@(
            '\bGGUF.*metadata\b',
            '\breadMetadata\s*\(',
            '\bparseGGUF\s*\('
        )
        Weak=@('\bGGUF\b')
    },
    @{
        Id=32; Name="Tensor registry"
        Strong=@(
            '\bTensorRegistry\b',
            '\bunordered_map<[^>]*Tensor',
            '\bmap<[^>]*Tensor'
        )
        Weak=@('\btensor\b')
    },
    @{
        Id=33; Name="Tensor lookup"
        Strong=@(
            '\bfindTensor\s*\(',
            '\bgetTensor\s*\(',
            '\blookupTensor\s*\('
        )
        Weak=@('\btensorMap\b')
    },
    @{
        Id=34; Name="Split GGUF"
        Strong=@(
            '-00001-of-',
            '\bsplitGGUF\b',
            '\bshardCount\b'
        )
        Weak=@('\bshard\b')
    },
    @{
        Id=35; Name="Quant dispatch"
        Strong=@(
            '\bQ[234568]_[0K]\b',
            '\bQuantType\b',
            '\bquantType\b.*(?:switch|if)'
        )
        Weak=@('\bQ4_K\b','\bQ8_0\b')
    },
    @{
        Id=36; Name="Q2_K implementation"
        Strong=@('\bQ2_K\b.*(?:gemv|dequant|kernel)','(?:gemv|dequant|kernel).*Q2_K')
        Weak=@('\bQ2_K\b')
    },
    @{
        Id=37; Name="Q3_K implementation"
        Strong=@('\bQ3_K\b.*(?:gemv|dequant|kernel)','(?:gemv|dequant|kernel).*Q3_K')
        Weak=@('\bQ3_K\b')
    },
    @{
        Id=38; Name="Q4_K implementation"
        Strong=@('\bQ4_K\b.*(?:gemv|dequant|kernel)','(?:gemv|dequant|kernel).*Q4_K')
        Weak=@('\bQ4_K\b')
    },
    @{
        Id=39; Name="Q5_K implementation"
        Strong=@('\bQ5_K\b.*(?:gemv|dequant|kernel)','(?:gemv|dequant|kernel).*Q5_K')
        Weak=@('\bQ5_K\b')
    },
    @{
        Id=40; Name="Q6_K implementation"
        Strong=@('\bQ6_K\b.*(?:gemv|dequant|kernel)','(?:gemv|dequant|kernel).*Q6_K')
        Weak=@('\bQ6_K\b')
    },
    @{
        Id=41; Name="Q8_0 implementation"
        Strong=@('\bQ8_0\b.*(?:gemv|dequant|kernel)','(?:gemv|dequant|kernel).*Q8_0')
        Weak=@('\bQ8_0\b')
    },
    @{
        Id=42; Name="Model dimension authority"
        Strong=@(
            '\bhiddenSize\b',
            '\bnumHeads\b',
            '\bnumKVHeads\b',
            '\bheadDim\b'
        )
        Weak=@('\bn_embd\b','\bhidden\b')
    },
    @{
        Id=43; Name="Tensor validation"
        Strong=@(
            '\bvalidateTensor\s*\(',
            '\bvalidateShape\s*\(',
            '\bshapeMismatch\b'
        )
        Weak=@('\bshape\b','\bdimension\b')
    },
    @{
        Id=44; Name="Residency/working set"
        Strong=@(
            '\bRawrWorkingSet\b',
            '\bRawrSpaceState\b',
            '\bRawrSpaceSufficient\b',
            '\bresidency\b'
        )
        Weak=@('\bworking.?set\b','\bVRAM\b')
    },
    @{
        Id=45; Name="Weight streaming"
        Strong=@(
            '\bprefetch\b',
            '\bweightWindow\b',
            '\bloadWeight.*(?:async|window)',
            '\bstreamWeight'
        )
        Weak=@('\bweight\b')
    },

    # 46-60 Backend
    @{
        Id=46; Name="CPU backend"
        Strong=@(
            '\bCPUBackend\b',
            '\bHostBackend\b',
            '\bhost.*gemv\b'
        )
        Weak=@('\bCPU\b')
    },
    @{
        Id=47; Name="Vulkan backend"
        Strong=@(
            '\bVkInstance\b',
            '\bvkCreateDevice\b',
            '\bVulkanBackend\b'
        )
        Weak=@('\bVulkan\b')
    },
    @{
        Id=48; Name="Vulkan compute pipeline"
        Strong=@(
            '\bvkCreateComputePipelines\b',
            '\bVkComputePipelineCreateInfo\b'
        )
        Weak=@('\bSPIR-V\b','\.spv')
    },
    @{
        Id=49; Name="Device discovery"
        Strong=@(
            '\bvkEnumeratePhysicalDevices\b',
            '\benumerateDevices\s*\('
        )
        Weak=@('\bphysicalDevice\b')
    },
    @{
        Id=50; Name="Capability-based GPU selection"
        Strong=@(
            '\bdeviceScore\b',
            '\bcapability\b.*\bdevice\b',
            '\bselectDevice\s*\('
        )
        Weak=@('\bGPU\b','\bdevice\b')
    },
    @{
        Id=51; Name="GPU memory allocator"
        Strong=@(
            '\bvkAllocateMemory\b',
            '\bGpuAllocator\b',
            '\bVulkanAllocator\b'
        )
        Weak=@('\bmemoryTypeIndex\b')
    },
    @{
        Id=52; Name="Command buffer execution"
        Strong=@(
            '\bvkAllocateCommandBuffers\b',
            '\bvkQueueSubmit\b'
        )
        Weak=@('\bcommandBuffer\b')
    },
    @{
        Id=53; Name="GPU synchronization"
        Strong=@(
            '\bvkWaitForFences\b',
            '\bvkQueueWaitIdle\b',
            '\bVkSemaphore\b'
        )
        Weak=@('\bfence\b','\bsemaphore\b')
    },
    @{
        Id=54; Name="Shader registry"
        Strong=@(
            '\bShaderRegistry\b',
            '\bloadShader\s*\(',
            '\bcreateShaderModule\s*\('
        )
        Weak=@('\.spv','\bshader\b')
    },
    @{
        Id=55; Name="QKV GPU path"
        Strong=@(
            '\bQKV\b.*(?:kernel|dispatch|gemv)',
            '(?:kernel|dispatch|gemv).*\bQKV\b'
        )
        Weak=@('\bQKV\b')
    },
    @{
        Id=56; Name="KVA GPU path"
        Strong=@(
            '\bKVA\b.*(?:kernel|dispatch|gemv)',
            '(?:kernel|dispatch|gemv).*\bKVA\b'
        )
        Weak=@('\bKVA\b')
    },
    @{
        Id=57; Name="O_PROJ GPU path"
        Strong=@(
            '\bO_PROJ\b.*(?:kernel|dispatch|gemv)',
            '(?:kernel|dispatch|gemv).*\bO_PROJ\b'
        )
        Weak=@('\bO_PROJ\b')
    },
    @{
        Id=58; Name="Multiple GPU support"
        Strong=@(
            '\bdeviceCount\b.*(?:>|>=)\s*2',
            '\bmulti.?gpu\b',
            '\bdeviceAssignments\b'
        )
        Weak=@('\bGPU\b')
        Optional=$true
    },
    @{
        Id=59; Name="Backend fallback"
        Strong=@(
            '\bfallback.*(?:CPU|host)',
            '\btryVulkan\b.*\bCPU\b'
        )
        Weak=@('\bfallback\b')
    },
    @{
        Id=60; Name="Backend metrics"
        Strong=@(
            '\bTPS\b',
            '\bDECODE_TPS\b',
            '\bGENERATION_WALL\b'
        )
        Weak=@('\bbenchmark\b')
    },

    # 61-75 IDE shell
    @{
        Id=61; Name="Native IDE main window"
        Strong=@(
            '\bCreateWindowEx[AW]?\b',
            '\bWinMain\b',
            '\bwWinMain\b'
        )
        Weak=@('\bWin32\b','\bIDE\b')
        Files=@('*ide*','*win32*','*main*')
    },
    @{
        Id=62; Name="Editor component"
        Strong=@(
            '\bEditor\b.*\bCreateWindow',
            '\bScintilla\b',
            '\bCodeEditor\b'
        )
        Weak=@('\bEditor\b')
    },
    @{
        Id=63; Name="Workspace open"
        Strong=@(
            '\bOpenWorkspace\s*\(',
            '\bopenWorkspace\s*\(',
            '\bWorkspaceManager\b'
        )
        Weak=@('\bworkspace\b')
    },
    @{
        Id=64; Name="File explorer"
        Strong=@(
            '\bFileExplorer\b',
            '\bTreeView\b.*\bfile',
            '\bworkspaceTree\b'
        )
        Weak=@('\bexplorer\b','\bTreeView\b')
    },
    @{
        Id=65; Name="File open/save"
        Strong=@(
            '\bSaveFile\s*\(',
            '\bOpenFile\s*\(',
            '\bWriteFile\b.*\beditor'
        )
        Weak=@('\bSaveFile\b','\bOpenFile\b')
    },
    @{
        Id=66; Name="Terminal"
        Strong=@(
            '\bCreateProcess[AW]?\b',
            '\bTerminalPanel\b',
            '\bConPTY\b',
            '\bCreatePseudoConsole\b'
        )
        Weak=@('\bterminal\b')
    },
    @{
        Id=67; Name="Chat panel"
        Strong=@(
            '\bChatPanel\b',
            '\bchat.*generateStream\b',
            '\bSendChat\b'
        )
        Weak=@('\bchat\b')
    },
    @{
        Id=68; Name="Streaming chat rendering"
        Strong=@(
            '\bonToken\b.*(?:chat|append|render)',
            '\bappendToken\b',
            '\bstream.*chat'
        )
        Weak=@('\bstream\b','\btoken\b')
        Files=@('*chat*','*ide*','*ui*')
    },
    @{
        Id=69; Name="Cancel generation UI"
        Strong=@(
            '\bCancelGeneration\b',
            '\bcancel.*button\b',
            '\bIDC_.*CANCEL\b'
        )
        Weak=@('\bcancel\b')
    },
    @{
        Id=70; Name="Git integration"
        Strong=@(
            '\bgit\s+(?:status|diff|commit|checkout)',
            '\bGitManager\b',
            '\bGitIntegration\b'
        )
        Weak=@('\bgit\b')
    },
    @{
        Id=71; Name="Search"
        Strong=@(
            '\bSearchWorkspace\s*\(',
            '\bFindInFiles\s*\(',
            '\bworkspaceSearch\b'
        )
        Weak=@('\bsearch\b')
    },
    @{
        Id=72; Name="Build command"
        Strong=@(
            '\bBuildProject\s*\(',
            '\bcmake\s+--build\b',
            '\bmsbuild\b'
        )
        Weak=@('\bbuild\b')
    },
    @{
        Id=73; Name="Diagnostics"
        Strong=@(
            '\bDiagnostic\b',
            '\bparse.*(?:compiler|diagnostic)',
            '\berrorList\b'
        )
        Weak=@('\berror\b','\bwarning\b')
    },
    @{
        Id=74; Name="Session persistence"
        Strong=@(
            '\bsaveSession\s*\(',
            '\bloadSession\s*\(',
            '\bSessionState\b'
        )
        Weak=@('\bsession\b')
    },
    @{
        Id=75; Name="IDE runtime status"
        Strong=@(
            '\bTPS\b.*(?:status|window|panel)',
            '\bRuntimeStatus\b',
            '\bstatusBar\b.*(?:model|token|runtime)'
        )
        Weak=@('\bstatusBar\b')
    },

    # 76-90 Agentic IDE
    @{
        Id=76; Name="Agent loop"
        Strong=@(
            '\bAgentLoop\b',
            '\bwhile\s*\([^)]*agent[^)]*\)',
            '\bRunAgent\s*\('
        )
        Weak=@('\bagent\b')
    },
    @{
        Id=77; Name="Planner"
        Strong=@(
            '\bPlanner::',
            '\bPlanTask\s*\(',
            '\bcreatePlan\s*\('
        )
        Weak=@('\bplanner\b')
    },
    @{
        Id=78; Name="Tool registry"
        Strong=@(
            '\bToolRegistry\b',
            '\bregisterTool\s*\(',
            '\bToolDispatcher\b'
        )
        Weak=@('\btool\b')
    },
    @{
        Id=79; Name="File read tool"
        Strong=@(
            '\breadFile\s*\(',
            '\bFileReadTool\b'
        )
        Weak=@('\bread.?file\b')
        Files=@('*agent*','*tool*')
    },
    @{
        Id=80; Name="File write/edit tool"
        Strong=@(
            '\bwriteFile\s*\(',
            '\bEditFileTool\b',
            '\bapplyPatch\s*\('
        )
        Weak=@('\bwrite.?file\b','\bpatch\b')
        Files=@('*agent*','*tool*','*patch*')
    },
    @{
        Id=81; Name="Diff engine"
        Strong=@(
            '\bDiffEngine\b',
            '\bGenerateDiff\s*\(',
            '\bcomputeDiff\s*\('
        )
        Weak=@('\bdiff\b')
    },
    @{
        Id=82; Name="Patch application"
        Strong=@(
            '\bApplyPatch\s*\(',
            '\bapplyPatch\s*\('
        )
        Weak=@('\bpatch\b')
    },
    @{
        Id=83; Name="Undo"
        Strong=@(
            '\bUndoManager\b',
            '\bundo\s*\([^;{]*\)\s*\{'
        )
        Weak=@('\bundo\b')
    },
    @{
        Id=84; Name="Shell/process tool"
        Strong=@(
            '\bCreateProcess[AW]?\b',
            '\bRunCommand\s*\(',
            '\bShellTool\b'
        )
        Weak=@('\bshell\b','\bcommand\b')
        Files=@('*agent*','*tool*','*terminal*')
    },
    @{
        Id=85; Name="Agent progress events"
        Strong=@(
            '\bAgentProgress\b',
            '\bprogressCallback\b',
            '\bonProgress\b'
        )
        Weak=@('\bprogress\b')
    },
    @{
        Id=86; Name="Agent cancellation"
        Strong=@(
            '\bcancelAgent\b',
            '\bAgent.*cancel',
            '\bstopRequested\b'
        )
        Weak=@('\bcancel\b')
        Files=@('*agent*')
    },
    @{
        Id=87; Name="Agent state persistence"
        Strong=@(
            '\bsaveAgentState\b',
            '\bAgentState\b.*(?:serialize|json)'
        )
        Weak=@('\bAgentState\b')
    },
    @{
        Id=88; Name="Autonomous build/test loop"
        Strong=@(
            '\b(?:build|compile).*(?:test).*(?:fix|retry)',
            '\bReverseAutoExpert\b'
        )
        Weak=@('\bauto\b','\btest\b')
        Files=@('*agent*','*expert*','*planner*')
    },
    @{
        Id=89; Name="Execution policy"
        Strong=@(
            '\bExecutionPolicy\b',
            '\bAuto\b.*\bExpert\b'
        )
        Weak=@('\bpolicy\b')
    },
    @{
        Id=90; Name="Agent-to-runtime generation"
        Strong=@(
            '\bagent.*ProductRun\s*\(',
            '\bagent.*generateStream\s*\('
        )
        Weak=@('\bagent\b.*\bgenerate\b')
    },

    # 91-105 Product behavior
    @{
        Id=91; Name="Markdown rendering"
        Strong=@(
            '\bMarkdownRenderer\b',
            '\brenderMarkdown\s*\('
        )
        Weak=@('\bmarkdown\b')
        Optional=$true
    },
    @{
        Id=92; Name="Code syntax highlighting"
        Strong=@(
            '\bSyntaxHighlight\b',
            '\blexer\b.*\bcode\b'
        )
        Weak=@('\bsyntax\b')
        Optional=$true
    },
    @{
        Id=93; Name="Context management"
        Strong=@(
            '\bcontextWindow\b',
            '\bcontextLength\b',
            '\btruncateContext\b'
        )
        Weak=@('\bcontext\b')
    },
    @{
        Id=94; Name="Conversation history"
        Strong=@(
            '\bConversationHistory\b',
            '\bmessages\b.*(?:push_back|emplace_back|append)'
        )
        Weak=@('\bhistory\b','\bmessages\b')
    },
    @{
        Id=95; Name="Model selection UI"
        Strong=@(
            '\bModelSelector\b',
            '\bmodelCombo\b',
            '\bIDC_.*MODEL\b'
        )
        Weak=@('\bmodel\b')
        Files=@('*ide*','*ui*','*win32*')
    },
    @{
        Id=96; Name="Generation settings UI"
        Strong=@(
            '\btemperature\b.*(?:edit|combo|slider)',
            '\btop_k\b.*(?:edit|combo|slider)',
            '\bmax_tokens\b.*(?:edit|combo|slider)'
        )
        Weak=@('\btemperature\b','\btop_k\b')
        Files=@('*ide*','*ui*')
    },
    @{
        Id=97; Name="Workspace context injection"
        Strong=@(
            '\bworkspace.*context\b',
            '\bcontext.*workspace\b'
        )
        Weak=@('\bworkspace\b')
        Files=@('*agent*','*chat*','*ide*')
    },
    @{
        Id=98; Name="Build output capture"
        Strong=@(
            '\bRedirect.*stdout\b',
            '\bCreatePipe\b',
            '\bbuildOutput\b'
        )
        Weak=@('\bstdout\b')
    },
    @{
        Id=99; Name="Crash handling"
        Strong=@(
            '\bSetUnhandledExceptionFilter\b',
            '\bUnhandledException\b',
            '\bcrashDump\b'
        )
        Weak=@('\bcrash\b')
    },
    @{
        Id=100; Name="Graceful runtime unload"
        Strong=@(
            '\bunloadModel\s*\(',
            '\bdestroyRuntime\s*\(',
            '\bshutdownRuntime\s*\('
        )
        Weak=@('\bunload\b')
    },
    @{
        Id=101; Name="Model reload"
        Strong=@(
            '\breloadModel\s*\(',
            '\bReloadModel\b'
        )
        Weak=@('\breload\b')
    },
    @{
        Id=102; Name="Concurrent/busy rejection"
        Strong=@(
            '\bBUSY\b',
            '\balreadyGenerating\b',
            '\bcompare_exchange.*generation'
        )
        Weak=@('\bbusy\b')
    },
    @{
        Id=103; Name="Local-only execution"
        Strong=@(
            '\bLOCAL_ONLY\b',
            '\bNO_CLOUD\b',
            '\bdisable.*network\b'
        )
        Weak=@('\boffline\b','\blocal\b')
    },
    @{
        Id=104; Name="No mandatory Ollama runtime dependency"
        Strong=@(
            '\bDeep2\b',
            '\bSovereignRuntime\b',
            '\bProductRun\b'
        )
        Weak=@('\bOllama\b')
    },
    @{
        Id=105; Name="256-token product completion path"
        Strong=@(
            'GENERATED_TOKENS\s*=\s*256',
            '\bmaxTokens\b\s*=\s*256',
            '\b256.?token'
        )
        Weak=@('\b256\b')
    },

    # 106-120 Build/release
    @{
        Id=106; Name="CMake/project build definition"
        Strong=@(
            '\badd_executable\s*\(',
            '\badd_library\s*\(',
            '\bproject\s*\('
        )
        Weak=@('\bcmake\b')
        Files=@('CMakeLists.txt','*.cmake')
    },
    @{
        Id=107; Name="Rawr CLI executable target"
        Strong=@(
            'add_executable\s*\(\s*rawr\b',
            '\brawr\.exe\b'
        )
        Weak=@('\brawr\b')
    },
    @{
        Id=108; Name="IDE executable target"
        Strong=@(
            'add_executable\s*\([^)]*(?:ide|rawrxd)',
            '\bRawrXD.*\.exe\b'
        )
        Weak=@('\bIDE\b')
        Files=@('CMakeLists.txt','*.cmake','*.vcxproj')
    },
    @{
        Id=109; Name="Runtime library target"
        Strong=@(
            'add_library\s*\([^)]*(?:runtime|deep2|engine)',
            '\bDeep2\b'
        )
        Weak=@('\bruntime\b')
    },
    @{
        Id=110; Name="Release build configuration"
        Strong=@(
            '\bRelease\b',
            '\bCMAKE_BUILD_TYPE\b'
        )
        Weak=@('\bbuild\b')
    },
    @{
        Id=111; Name="Portable configuration"
        Strong=@(
            '\bportable\b',
            '\bAppData\b.*(?:fallback|config)'
        )
        Weak=@('\bconfig\b')
        Optional=$true
    },
    @{
        Id=112; Name="Installer"
        Strong=@(
            '\bNSIS\b',
            '\bWiX\b',
            '\bInno Setup\b',
            '\binstaller\b'
        )
        Weak=@('\binstall\b')
        Optional=$true
    },
    @{
        Id=113; Name="Regression tests"
        Strong=@(
            '\badd_test\s*\(',
            '\bctest\b',
            '\bTEST\s*\('
        )
        Weak=@('\btest\b')
    },
    @{
        Id=114; Name="Runtime tests use production code"
        Strong=@(
            '\bProductRun\s*\(',
            '\bgenerateStream\s*\('
        )
        Weak=@('\btest\b')
        Files=@('*test*','*benchmark*')
    },
    @{
        Id=115; Name="Benchmark uses production decode"
        Strong=@(
            '\bgenerateStream\s*\(',
            '\bProductRun\s*\('
        )
        Weak=@('\bbenchmark\b')
        Files=@('*benchmark*')
    },
    @{
        Id=116; Name="Evidence/product receipt output"
        Strong=@(
            '\bevidence[\\/]',
            '\bProductReceipt\b',
            'PRODUCT_PASS'
        )
        Weak=@('\breceipt\b')
    },
    @{
        Id=117; Name="Version metadata"
        Strong=@(
            '\bVERSION\b',
            '\bPRODUCT_VERSION\b',
            '\bRAWRXD_VERSION\b'
        )
        Weak=@('\bversion\b')
    },
    @{
        Id=118; Name="Configuration loader"
        Strong=@(
            '\bloadConfig\s*\(',
            '\bConfiguration::',
            '\bSettings::'
        )
        Weak=@('\bconfig\b')
    },
    @{
        Id=119; Name="Logging"
        Strong=@(
            '\bLogger::',
            '\blogInfo\s*\(',
            '\blogError\s*\(',
            '\bRAWR_LOG\b'
        )
        Weak=@('\blog\b')
    },
    @{
        Id=120; Name="Product acceptance receipt"
        Strong=@(
            'PRODUCT_PASS\s*=\s*1',
            'EXIT_REASON\s*=\s*COMPLETE',
            '\bProductReceipt\b'
        )
        Weak=@('PRODUCT_PASS')
    }
)

# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

$Results = [System.Collections.Generic.List[object]]::new()

foreach ($item in $Manifest) {

    $filesFilter =
        if ($item.ContainsKey("Files")) { $item.Files }
        else { @("*") }

    $strong = Find-Evidence `
        -Patterns $item.Strong `
        -FilePatterns $filesFilter

    $weak = Find-Evidence `
        -Patterns $item.Weak `
        -FilePatterns $filesFilter

    $stub = Get-StubEvidence -Evidence $strong

    $status = "MISSING"
    $reason = "No matching implementation evidence."

    if ($strong.Count -gt 0) {
        if ($stub.Count -eq 0) {
            $status = "DONE"
            $reason = "Implementation-pattern evidence found."
        }
        else {
            $status = "PARTIAL"
            $reason = "Implementation evidence exists but matched files contain stub/TODO markers."
        }
    }
    elseif ($weak.Count -gt 0) {
        $status = "PARTIAL"
        $reason = "Declaration/name/interface evidence exists without strong implementation evidence."
    }
    elseif ($item.ContainsKey("Optional") -and $item.Optional) {
        # Do NOT automatically mark N/A merely because optional.
        # Keep missing unless the capability truly is out-of-scope.
        $status = "MISSING_IF_APPLICABLE"
        $reason = "Optional capability has no implementation evidence."
    }

    $evidenceFiles = @(
        $strong.File
        $weak.File
    ) | Where-Object { $_ } | Sort-Object -Unique

    $Results.Add([pscustomobject]@{
        Id             = [int]$item.Id
        Name           = $item.Name
        Status         = $status
        StrongHits     = $strong.Count
        WeakHits       = $weak.Count
        StubHits       = $stub.Count
        Reason         = $reason
        EvidenceFiles  = @($evidenceFiles)
        StrongEvidence = @($strong)
        WeakEvidence   = @($weak)
    })
}

# ---------------------------------------------------------------------------
# Dependency promotion guard
#
# Some responsibilities cannot be honestly DONE if their prerequisites
# are missing. This prevents misleading leaf-level promotion.
# ---------------------------------------------------------------------------

$Dependencies = @{
    2   = @(5,6,10)        # CLI -> resolve/load/stream
    3   = @(5,6,10)        # IDE -> same
    4   = @(10)            # Agent -> production stream
    10  = @(6,7,8)         # GenerateStream needs model/tokenizer/KV
    24  = @(10,11,12,13)   # decode loop
    28  = @(24,25)         # completion
    68  = @(3,10,13)       # IDE streaming
    90  = @(4,10)          # agent runtime integration
    105 = @(24,28,29)      # 256 token complete
    114 = @(10)            # tests must use prod path
    115 = @(10)            # benchmark must use prod path
    120 = @(2,3,10,24,28)  # product acceptance
}

$resultById = @{}
foreach ($r in $Results) {
    $resultById[$r.Id] = $r
}

foreach ($id in $Dependencies.Keys) {
    if (-not $resultById.ContainsKey($id)) { continue }

    $r = $resultById[$id]

    if ($r.Status -ne "DONE") {
        continue
    }

    $blockedBy = @()

    foreach ($dep in $Dependencies[$id]) {
        if (
            $resultById.ContainsKey($dep) -and
            $resultById[$dep].Status -ne "DONE"
        ) {
            $blockedBy += $dep
        }
    }

    if ($blockedBy.Count -gt 0) {
        $r.Status = "PARTIAL"
        $r.Reason =
            "Implementation exists, but required dependencies are not DONE: " +
            ($blockedBy -join ",")
    }
}

# ---------------------------------------------------------------------------
# Detect suspicious duplicate implementations
# ---------------------------------------------------------------------------

$DuplicateDomains = @(
    @{
        Name="GenerateStream"
        Pattern='\b(?:generateStream|GenerateStream)\s*\([^;{]*\)\s*\{'
    },
    @{
        Name="ModelResolver"
        Pattern='\b(?:ResolveModel|resolveModel|resolveModelPath)\s*\([^;{]*\)\s*\{'
    },
    @{
        Name="Tokenizer"
        Pattern='\b(?:tokenize|BuildTokenizer|CreateTokenizer)\s*\([^;{]*\)\s*\{'
    },
    @{
        Name="Sampler"
        Pattern='\b(?:sampleToken|Sample)\s*\([^;{]*\)\s*\{'
    },
    @{
        Name="GGUFLoader"
        Pattern='\b(?:LoadGGUF|OpenGGUF|loadModel)\s*\([^;{]*\)\s*\{'
    }
)

$DuplicateResults = @()

foreach ($domain in $DuplicateDomains) {
    $hits = Find-Evidence -Patterns @($domain.Pattern) -Limit 100

    if ($hits.Count -gt 1) {
        $DuplicateResults += [pscustomobject]@{
            Domain = $domain.Name
            Count = $hits.Count
            Files = @($hits.File | Sort-Object -Unique)
        }
    }
}

# ---------------------------------------------------------------------------
# Product-path cross-reference
# ---------------------------------------------------------------------------

$ProductPathIds = @(5,6,7,8,9,10,11,12,13,14,15,24,25,28,29,105,120)
$ProductPath = @(
    foreach ($id in $ProductPathIds) {
        if ($resultById.ContainsKey($id)) {
            $resultById[$id]
        }
    }
)

$ProductPathComplete =
    (@($ProductPath | Where-Object Status -ne "DONE").Count -eq 0)

# ---------------------------------------------------------------------------
# Priority scoring
#
# Reverse priority:
#   product-path missing > IDE integration > agent integration >
#   backend optimization > optional polish
# ---------------------------------------------------------------------------

function Get-PriorityScore {
    param($r)

    $score = 0

    if ($r.Status -eq "MISSING")              { $score += 100 }
    elseif ($r.Status -eq "PARTIAL")          { $score += 70 }
    elseif ($r.Status -eq "MISSING_IF_APPLICABLE") { $score += 20 }
    else                                      { return -1 }

    if ($ProductPathIds -contains $r.Id) { $score += 200 }

    if ($r.Id -ge 61 -and $r.Id -le 75) { $score += 90 }
    if ($r.Id -ge 76 -and $r.Id -le 90) { $score += 70 }
    if ($r.Id -ge 16 -and $r.Id -le 45) { $score += 60 }
    if ($r.Id -ge 46 -and $r.Id -le 60) { $score += 40 }
    if ($r.Id -ge 106)                   { $score += 30 }

    return $score
}

$Next = $Results |
    ForEach-Object {
        [pscustomobject]@{
            Id = $_.Id
            Name = $_.Name
            Status = $_.Status
            Score = Get-PriorityScore $_
            Reason = $_.Reason
        }
    } |
    Where-Object Score -ge 0 |
    Sort-Object `
        @{Expression="Score";Descending=$true},
        @{Expression="Id";Descending=$false} |
    Select-Object -First $NextCount

# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

$Done = @($Results | Where-Object Status -eq "DONE")
$Partial = @($Results | Where-Object Status -eq "PARTIAL")
$Missing = @(
    $Results |
    Where-Object {
        $_.Status -eq "MISSING" -or
        $_.Status -eq "MISSING_IF_APPLICABLE"
    }
)

$summary = @"
RAWRXD_PRODUCT_REVERSE_MANIFEST_001

ROOT=$Root
SOURCE_FILES=$($Files.Count)

TOTAL=$($Results.Count)
DONE=$($Done.Count)
PARTIAL=$($Partial.Count)
MISSING=$($Missing.Count)

PRODUCT_PATH_COMPLETE=$([int]$ProductPathComplete)
DUPLICATE_RUNTIME_DOMAINS=$($DuplicateResults.Count)

RULES:
DONE=strong implementation evidence + dependencies satisfied
PARTIAL=declaration/stub/dependency-incomplete
MISSING=no implementation evidence
MISSING_IF_APPLICABLE=optional product capability absent
NOT_APPLICABLE=never inferred automatically

"@

$lines = [System.Collections.Generic.List[string]]::new()
$lines.Add($summary)

foreach ($r in $Results | Sort-Object Id) {
    $lines.Add(
        ("{0:D3} [{1,-21}] {2}" -f $r.Id, $r.Status, $r.Name)
    )

    if ($r.EvidenceFiles.Count -gt 0) {
        foreach ($f in ($r.EvidenceFiles | Select-Object -First 4)) {
            $lines.Add("      EVIDENCE=$f")
        }
    }

    $lines.Add("      REASON=$($r.Reason)")
}

if ($DuplicateResults.Count -gt 0) {
    $lines.Add("")
    $lines.Add("DUPLICATE_IMPLEMENTATION_CANDIDATES")

    foreach ($d in $DuplicateResults) {
        $lines.Add("$($d.Domain) COUNT=$($d.Count)")

        foreach ($f in $d.Files) {
            $lines.Add("      $f")
        }
    }
}

$lines.Add("")
$lines.Add("PRODUCT_PATH")

foreach ($r in $ProductPath) {
    $lines.Add(
        ("{0:D3} [{1}] {2}" -f $r.Id, $r.Status, $r.Name)
    )
}

$lines.Add("")
$lines.Add("NEXT_$NextCount")

foreach ($n in $Next) {
    $lines.Add(
        ("{0:D3} [{1}] SCORE={2} {3}" -f
            $n.Id,
            $n.Status,
            $n.Score,
            $n.Name
        )
    )
}

$ManifestTxt = Join-Path $EvidenceRoot "MANIFEST.txt"
$ManifestJson = Join-Path $EvidenceRoot "MANIFEST.json"
$MissingTxt = Join-Path $EvidenceRoot "MISSING.txt"
$PartialTxt = Join-Path $EvidenceRoot "PARTIAL.txt"
$DoneTxt = Join-Path $EvidenceRoot "DONE.txt"
$NextTxt = Join-Path $EvidenceRoot "NEXT_15.txt"

$lines | Set-Content -LiteralPath $ManifestTxt -Encoding UTF8

$Results |
    ConvertTo-Json -Depth 10 |
    Set-Content -LiteralPath $ManifestJson -Encoding UTF8

$Missing |
    ForEach-Object {
        "{0:D3} [{1}] {2}`n    {3}" -f
            $_.Id, $_.Status, $_.Name, $_.Reason
    } |
    Set-Content -LiteralPath $MissingTxt -Encoding UTF8

$Partial |
    ForEach-Object {
        "{0:D3} {1}`n    {2}" -f
            $_.Id, $_.Name, $_.Reason
    } |
    Set-Content -LiteralPath $PartialTxt -Encoding UTF8

$Done |
    ForEach-Object {
        "{0:D3} {1}" -f $_.Id, $_.Name
    } |
    Set-Content -LiteralPath $DoneTxt -Encoding UTF8

$Next |
    ForEach-Object {
        "{0:D3} [{1}] SCORE={2} {3}`n    {4}" -f
            $_.Id,
            $_.Status,
            $_.Score,
            $_.Name,
            $_.Reason
    } |
    Set-Content -LiteralPath $NextTxt -Encoding UTF8

Write-Host ""
Write-Host "==== REVERSE PRODUCT MANIFEST ===="
Write-Host "DONE=$($Done.Count)"
Write-Host "PARTIAL=$($Partial.Count)"
Write-Host "MISSING=$($Missing.Count)"
Write-Host "PRODUCT_PATH_COMPLETE=$([int]$ProductPathComplete)"

Write-Host ""
Write-Host "==== NEXT $NextCount ===="

$Next | Format-Table Id, Status, Score, Name -AutoSize

Write-Host ""
Write-Host "MANIFEST=$ManifestTxt"
Write-Host "JSON=$ManifestJson"

if (-not $ProductPathComplete) {
    Write-Host ""
    Write-Host "PRODUCT_STATUS=INCOMPLETE"
    Write-Host "FIRST_ACTION=$(
        ($Next | Select-Object -First 1).Name
    )"
    exit 1
}

Write-Host ""
Write-Host "PRODUCT_PATH_COMPLETE=1"
exit 0
