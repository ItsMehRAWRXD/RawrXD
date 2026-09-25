param(
    [string]$RepoRoot = "F:\~dev\rawrxd"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$DropRoot = $PSScriptRoot
$SrcDir   = Join-Path $RepoRoot "src\deep2"
$Cpp      = Join-Path $SrcDir "Deep2Engine.cpp"
$Hdr      = Join-Path $SrcDir "Deep2Engine.h"

if (!(Test-Path $Cpp) -or !(Test-Path $Hdr)) {
    throw "Deep2Engine.cpp/.h not found under $SrcDir"
}

# Copy the pack first. Header-only: no CMake target changes required.
Copy-Item (Join-Path $DropRoot "src\deep2\Deep2ModelArchitecture.hpp") $SrcDir -Force
Copy-Item (Join-Path $DropRoot "src\deep2\Deep2RecurrentMath.hpp")      $SrcDir -Force
Copy-Item (Join-Path $DropRoot "src\deep2\Deep2ArchitectureRuntime.hpp") $SrcDir -Force

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
Copy-Item $Cpp "$Cpp.archpack_$stamp.bak" -Force
Copy-Item $Hdr "$Hdr.archpack_$stamp.bak" -Force

$h = [IO.File]::ReadAllText($Hdr)
$c = [IO.File]::ReadAllText($Cpp)

function Replace-Once([string]$Text,[string]$Old,[string]$New,[string]$Name) {
    $count = ([regex]::Matches($Text,[regex]::Escape($Old))).Count
    if ($count -ne 1) { throw "$Name expected 1 exact match; found $count. No blind patch." }
    return $Text.Replace($Old,$New)
}

# 1. Forward declaration.
if (!$h.Contains("class ArchitectureRuntime; // RAWRXD_MODEL_ARCH_PACK_001")) {
    $h = Replace-Once $h "namespace Deep2 {" @"
namespace Deep2 {
namespace Arch { class ArchitectureRuntime; } // RAWRXD_MODEL_ARCH_PACK_001
"@ "header forward declaration"
}

# 2. Engine-owned architecture runtime.
if (!$h.Contains("architectureRuntime_; // RAWRXD_MODEL_ARCH_PACK_001")) {
    $needle = 'std::string modelArchitecture_;               // <<< set from GGUF metadata after loadModel()'
    $replacement = @'
std::string modelArchitecture_;               // <<< set from GGUF metadata after loadModel()
    std::unique_ptr<Deep2::Arch::ArchitectureRuntime> architectureRuntime_; // RAWRXD_MODEL_ARCH_PACK_001
'@
    $h = Replace-Once $h $needle $replacement "architecture runtime member"
}

# 3. Runtime include after engine header.
if (!$c.Contains('#include "Deep2ArchitectureRuntime.hpp"')) {
    $c = Replace-Once $c '#include "Deep2Engine.h"' @'
#include "Deep2Engine.h"
#include "Deep2ArchitectureRuntime.hpp" // RAWRXD_MODEL_ARCH_PACK_001
'@ "architecture runtime include"
}

# 4. Architecture must be recognized immediately, but special graphs are allowed
#    to load for admission diagnostics. They fail closed if generic forward is attempted.
if (!$c.Contains("ARCH_PACK_KIND=")) {
    $needle = 'modelArchitecture_ = arch;'
    $replacement = @'
modelArchitecture_ = arch;
    {
        const auto _traits = Deep2::Arch::resolve(arch);
        std::fprintf(stderr,
            "[Deep2Engine] ARCH_PACK_KIND=%s FAMILY=%s SAFE_GENERIC=%d SPECIAL=%d\n",
            _traits.canonical, Deep2::Arch::familyName(_traits.family),
            _traits.safeGeneric ? 1 : 0, _traits.requiresSpecialGraph ? 1 : 0);
        if (_traits.kind == Deep2::Arch::Kind::Unknown) {
            if (diag) {
                diag->stageCode = 31;
                diag->stageName = "LOAD_ARCH_UNSUPPORTED";
                diag->message = "Unknown GGUF architecture: " + arch;
            }
            return false;
        }
    }
'@
    $c = Replace-Once $c $needle $replacement "architecture recognition"
}

# 5. Bind architecture runtime immediately before declaring weights loaded.
#    The first occurrence is the production GGUF load path on current master.
if (!$c.Contains("ARCH_PACK_BIND_FAIL")) {
    $needle = 'modelWeights.loaded = true;'
    $replacement = @'
architectureRuntime_ = std::make_unique<Deep2::Arch::ArchitectureRuntime>();
    {
        std::string archError;
        if (!architectureRuntime_->bind(*loader, arch, modelWeights.numLayers,
                                        modelWeights.normEps, archError)) {
            std::fprintf(stderr, "[Deep2Engine] ARCH_PACK_BIND_FAIL %s\n", archError.c_str());
            if (diag) {
                diag->stageCode = 32;
                diag->stageName = "LOAD_ARCH_BIND";
                diag->message = archError;
            }
            return false;
        }
        std::fprintf(stderr, "[Deep2Engine] ARCH_PACK_BIND_OK recurrent_layers=%zu\n",
                     architectureRuntime_->recurrentLayerCount());
    }

    modelWeights.loaded = true;
'@
    # Because old trees may have more than one modelWeights.loaded assignment,
    # replace only when unambiguous.
    $count = ([regex]::Matches($c,[regex]::Escape($needle))).Count
    if ($count -ne 1) { throw "production modelWeights.loaded marker expected once, got $count" }
    $c = $c.Replace($needle,$replacement)
}

# 6. Reset recurrent state with conversation reset.
if (!$c.Contains("architectureRuntime_->reset(); // RAWRXD_MODEL_ARCH_PACK_001")) {
    $needle = 'void Deep2Engine::reset() {'
    $replacement = @'
void Deep2Engine::reset() {
    if (architectureRuntime_) architectureRuntime_->reset(); // RAWRXD_MODEL_ARCH_PACK_001
'@
    $c = Replace-Once $c $needle $replacement "reset hook"
}

# 7. Route recurrent layers instead of unconditional attention.
$oldAttention = 'computeAttention(layer, layerTemp, attentionOutput, seqLen);'
if (!$c.Contains("ARCH_PACK_RECURRENT_FORWARD")) {
    $replacement = @'
if (architectureRuntime_ && architectureRuntime_->isRecurrentLayer(layer)) {
        // ARCH_PACK_RECURRENT_FORWARD
        computeSSM(layer, layerTemp, attentionOutput);
    } else {
        computeAttention(layer, layerTemp, attentionOutput, seqLen);
    }
'@
    $count = ([regex]::Matches($c,[regex]::Escape($oldAttention))).Count
    if ($count -lt 1) { throw "attention dispatch marker not found" }
    # Patch only first production forward occurrence.
    $idx = $c.IndexOf($oldAttention)
    $c = $c.Substring(0,$idx) + $replacement + $c.Substring($idx+$oldAttention.Length)
}

# 8. Replace fail-closed computeSSM body with the reference provider.
if (!$c.Contains("ARCH_PACK_COMPUTE_SSM")) {
    $start = $c.IndexOf("void Deep2Engine::computeSSM(")
    if ($start -lt 0) { throw "computeSSM not found" }
    $next = $c.IndexOf("// ===================", $start + 20)
    if ($next -lt 0) { throw "computeSSM end marker not found" }

    $new = @'
void Deep2Engine::computeSSM(size_t layer, const float* input, float* output) {
    // ARCH_PACK_COMPUTE_SSM
    if (!architectureRuntime_)
        throw std::runtime_error("computeSSM: architecture runtime not bound");

    std::string err;
    auto linear = [this](const WeightTensor& wt,
                         const float* x, float* y, size_t rows) {
        this->LinearW(wt, x, nullptr, y, rows);
    };
    if (!architectureRuntime_->forward(layer, input, output,
                                       modelWeights.hiddenDim, linear, err)) {
        throw std::runtime_error("computeSSM: " + err);
    }
    ++ssmRealCalls_;
}

'@
    $c = $c.Substring(0,$start) + $new + $c.Substring($next)
}

[IO.File]::WriteAllText($Hdr,$h,[Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($Cpp,$c,[Text.UTF8Encoding]::new($false))

# Post-write assertions.
$h2=[IO.File]::ReadAllText($Hdr)
$c2=[IO.File]::ReadAllText($Cpp)
$must=@(
    "architectureRuntime_; // RAWRXD_MODEL_ARCH_PACK_001",
    '#include "Deep2ArchitectureRuntime.hpp"',
    "ARCH_PACK_KIND=",
    "ARCH_PACK_BIND_OK",
    "ARCH_PACK_RECURRENT_FORWARD",
    "ARCH_PACK_COMPUTE_SSM"
)
foreach($m in $must) {
    if(!$h2.Contains($m) -and !$c2.Contains($m)) { throw "post-write assertion failed: $m" }
}

Write-Host "RAWRXD_MODEL_ARCH_PACK_001_APPLY=PASS"
Write-Host "BACKUP_CPP=$Cpp.archpack_$stamp.bak"
Write-Host "BACKUP_HDR=$Hdr.archpack_$stamp.bak"
Write-Host ""
Write-Host "Next: rebuild RawrXD-Win32IDE and run architecture admission against real GGUFs."
