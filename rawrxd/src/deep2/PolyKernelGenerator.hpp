#pragma once
// ============================================================================
// PolyKernelGenerator.hpp — RAWRXD_POLYKERNEL_001
//
// A source-generating kernel form factory.
//
// The point is that the SOURCE is an output. A KernelIdentity is decomposed
// into a PrimitiveGraph; the graph plus the selected BackendForm produces
// actual C++ text; that text is hashed; it is handed to a real compiler; the
// resulting binary is hashed; the binary is loaded and executed; and a receipt
// records all of it.
//
// Nothing here reports success because generation was attempted. Every claim in
// the receipt corresponds to an observation:
//
//   SOURCE_GENERATED      source text was produced and is non-empty
//   SOURCE_DIGEST         FNV-1a 64 over the exact bytes handed to the compiler
//   COMPILE_EXIT          the real compiler's real exit code
//   BINARY_DIGEST         FNV-1a 64 over the loaded module file
//   REAL_KERNEL_ENTERED   the generated entry point was actually called
//   PARITY                max |generated - reference| over real inputs
//   FINITE_OUTPUT         every produced element is finite
//
// A generated form that cannot be compiled, loaded, entered, or shown to agree
// with the reference is STALE or REJECTED. It is never reported as available.
//
// The generated kernels implement y = W x for the quantized/f32 layouts Deep2
// actually dispatches, so PARITY against QuantKernelRegistry::GetGEMV is a
// comparison against the production reference, not against itself.
// ============================================================================

#include "ReverseLayer.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace Deep2 {

// ---------------------------------------------------------------------------
// Source generation — pure text. No filesystem, no compiler, no globals.
// ---------------------------------------------------------------------------
struct GeneratedSource {
    bool        produced = false;
    std::string text;
    uint64_t    digest   = 0;      // FNV-1a 64 over `text`
    uint32_t    bytes    = 0;
    std::string rejectReason;       // non-empty => produced == false
};

// Emits C++ implementing the primitive graph for the chosen form.
//   form == CPU_SCALAR / CPU_AVX2 / CPU_AVX512 : emits portable C
//   form == VULKAN_*                           : not emitted by this cut, and
//                                                says so rather than emitting
//                                                host code under a GPU name
GeneratedSource generatePolyKernelSource(const KernelIdentity& intent,
                                         const PrimitiveGraph& graph,
                                         BackendForm form);

// FNV-1a 64 over raw bytes. Exposed because the receipt must name the exact
// quantity it hashed, and a reader must be able to recompute it.
uint64_t fnv1a64(const void* data, size_t n);

// ---------------------------------------------------------------------------
// Compilation + execution + verification
// ---------------------------------------------------------------------------
struct PolyKernelReceipt {
    // --- generation ---
    bool        sourceGenerated = false;
    uint64_t    sourceDigest    = 0;
    uint32_t    sourceBytes     = 0;

    // --- reality at generation time ---
    BackendForm form            = BackendForm::NONE_AVAILABLE;
    uint64_t    beaconGeneration = 0;
    uint64_t    hardwareFingerprint = 0;

    // --- compilation ---
    int         compileExit     = -1;
    uint64_t    binaryDigest    = 0;
    uint32_t    binaryBytes     = 0;

    // --- execution ---
    uint64_t    executionCount  = 0;
    uint64_t    caseCount       = 0;   // how many inputs were actually supplied
    bool        invalidCase     = false;// a case was malformed and was skipped
    bool        kernelEntered   = false;
    bool        finiteOutput    = false;

    // --- parity against the production reference ---
    double      maxAbsDiff      = 0.0;
    double      rmsDiff         = 0.0;
    std::uint64_t relativeL2    = 0;     // floor(sqrt(sumSq/refSq) * 1e9)
    std::uint64_t comparisonCount = 0;
    std::uint64_t nonFiniteRef    = 0;

    // --- measured cost, the second promotion axis ---
    // Wall time is MEASURED by running the compiled kernel. Bytes read is
    // computed from the real geometry the case declares. Neither is a model.
    std::uint64_t wallTimeNs       = 0;   // total over all timed repetitions
    std::uint64_t wallReps         = 0;   // how many repetitions produced it
    std::uint64_t sourceBytesRead  = 0;   // packed weight bytes the case supplies
    std::uint64_t referenceWallNs  = 0;   // same loop over the production kernel

    // --- failure detail, always printed, never omitted ---
    std::string stage;            // last stage reached
    std::string detail;           // compiler stderr tail, loader error, etc.

    bool passed() const noexcept {
        return sourceGenerated && compileExit == 0 && kernelEntered &&
               finiteOutput && comparisonCount > 0 && caseCount > 0 &&
               !invalidCase && maxAbsDiff == 0.0 && nonFiniteRef == 0;
    }
};

// One concrete input case: real bytes, real activation, real geometry.
//
// A case is what makes the comparison specific. certifyCases() measures the
// generated kernel against the production reference ON THESE BYTES, using the
// same code path regardless of where the bytes came from. That is what allows
// the identical measurement to be applied to a synthetic tensor and to a real
// model weight without either path being a weaker copy of the other.
struct ExternalCase {
    const uint8_t* weightBytes = nullptr;   // packed, row-major, blocksPerRow
    const float*   x           = nullptr;   // length cols
    uint32_t       rows        = 0;
    uint32_t       cols        = 0;
    std::string    label;                   // e.g. "synthetic" or the GGUF tensor name
};

// Compile the given source text ONCE, then execute it on every case and
// compare each against the production reference kernel.
//
// This is the single measurement core. certifySourceText() and
// certifySourceTextOn() are both thin wrappers over it, so "synthetic" and
// "real model weight" cannot drift into two different measurements.
PolyKernelReceipt certifyCases(const KernelIdentity& intent,
                               const PrimitiveGraph& graph,
                               const std::string& text,
                               uint64_t beaconGeneration,
                               const std::vector<ExternalCase>& cases,
                               const std::string& extraFlags = std::string(),
                               double tol = 0.0);

// The /arch switch that actually enables each vector form. The emitted AVX
// bodies are guarded by #if defined(__AVX2__) / __AVX512F__ and carry a scalar
// fallback, so without this flag they compile out and the "vector" form is the
// scalar kernel wearing a vector label.
std::string isaFlagForForm(BackendForm form);

// Build valid-by-construction quantized tensors. These are NOT model weights;
// they exist to exercise the layout arithmetic over a known-good value range.
std::vector<ExternalCase> buildSyntheticCases(const KernelIdentity& intent,
                                             const PrimitiveGraph& graph,
                                             uint32_t rows, uint32_t cols,
                                             uint32_t trials, uint32_t seed);

// Compile + run + verify ONE generated form against the production reference
// kernel on synthetic cases. tol == 0.0 demands bit-exact agreement.
PolyKernelReceipt certifyPolyKernel(const KernelIdentity& intent,
                                    const PrimitiveGraph& graph,
                                    BackendForm form,
                                    uint64_t beaconGeneration,
                                    uint32_t rows,
                                    uint32_t cols,
                                    uint32_t trials,
                                    double tol = 0.0);

// Compile + run + verify ARBITRARY source text through the identical pipeline.
//
// This exists so the gate can falsify ITSELF. Feeding deliberately corrupted
// text through the same compile/execute/parity path must produce a FAILING
// receipt; if corrupted text also passes, then "PASS" from this pipeline means
// nothing and the pipeline itself is the defect. A parity check that cannot
// disagree with the thing it measures is not a check.
//
// It is deliberately NOT a fault-injection flag on generatePolyKernelSource:
// the semantic generator must not be able to emit a deliberately wrong kernel,
// and the falsifier must not have to ask it for one.
PolyKernelReceipt certifySourceText(const KernelIdentity& intent,
                                    const PrimitiveGraph& graph,
                                    const std::string& text,
                                    uint64_t beaconGeneration,
                                    uint32_t rows,
                                    uint32_t cols,
                                    uint32_t trials,
                                    double tol = 0.0);

// Same measurement, on caller-supplied inputs. This is the path a REAL GGUF
// weight block takes, so a real model weight and a synthetic tensor are graded
// by identical code rather than by two comparable-looking but separate paths.
PolyKernelReceipt certifySourceTextOn(const KernelIdentity& intent,
                                      const PrimitiveGraph& graph,
                                      const std::string& text,
                                      uint64_t beaconGeneration,
                                      const std::vector<ExternalCase>& cases,
                                      double tol = 0.0);

// Machine fingerprint of what the form was generated FOR. Two forms with
// different fingerprints are not interchangeable, and a fingerprint change
// invalidates every cached form.
uint64_t hardwareFingerprint(const Heartbeat& hb);

// True when a cached form is still legal: identity unchanged AND reality at the
// same generation. A form is never mutated in place; it goes STALE.
bool formIsCurrent(const KernelIdentity& intent,
                   const Heartbeat& hb,
                   uint64_t formBeaconGeneration);

} // namespace Deep2
