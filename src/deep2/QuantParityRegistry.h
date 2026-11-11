// =============================================================================
// QuantParityRegistry.h — Universal quantization registry + parity certification
// =============================================================================
// Model Genie P0 layer. Sits between the ModelGenome (frozen compiler input)
// and Deep2 native execution, and answers two questions:
//
//   1. KERNEL BINDING — for each ggml quant type, which native kernel runs it,
//      and is that kernel actually implemented? Source of geometry truth is
//      src/deep2/QuantTypeTable.hpp; this file adds the binding + gate, it
//      does not duplicate the geometry.
//
//   2. PARITY CERTIFICATION — has that path been PROVEN byte-identical (or
//      numerically within a recorded tolerance) against the ggml reference?
//      Status is only ever advanced by a real measurement recorded with an
//      evidence reference. There is no API that sets a type to Verified
//      without evidence, so a certificate cannot be fabricated.
//
// FAIL-CLOSED ADMISSION
//   A type is admissible for certified execution only when
//     geometry is known AND a kernel is bound AND packing parity is Verified.
//   A type with no kernel, or Packing Unverified, is admitted for PROBING
//   only and can never produce a certificate. An unknown/removed ggml id is
//   refused outright rather than silently falling back to {4,1}.
//
// MLA IS PRESERVED AS REQUIRED-BUT-UNIMPLEMENTED
//   ModelGenie::Primitive::MlaDecompressFwd is FIRST_UNIMPLEMENTED_PRIMITIVE.
//   KernelGate reports it with implementationRequired = true and never
//   reports the runtime as executable while it is unimplemented. The manifest
//   in modelgenie/CapabilityManifest.generated.hpp is the generated form of
//   the same fact; both are authoritative and neither is "fixed" to a false
//   positive.
// =============================================================================
#pragma once

#include "QuantTypeTable.hpp"
#include "../modelgenie/ModelGenome.hpp"

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <optional>

namespace RawrXD {
namespace Deep2 {

// QuantTypeTable.hpp declares its helpers in the GLOBAL namespace `Deep2`,
// while this registry lives in RawrXD::Deep2 (the Model Genie namespace).
// Pull the geometry owners in explicitly instead of renaming either one, so
// Geometry stays single-authority in QuantTypeTable.hpp.
using ::Deep2::GGMLType;
using ::Deep2::QuantTypeDescriptor;
using ::Deep2::QuantTypeTable;
using ::Deep2::LookupQuantType;
using ::Deep2::QuantTypeName;
using ::Deep2::QuantTypeIsKnown;
using ::Deep2::QuantTypeBlockBytes;
using ::Deep2::QuantTypeBlockElements;
using ::Deep2::QuantTypeIsQuantized;

// ---------------------------------------------------------------------------
// Parity status, advancing only on recorded evidence
// ---------------------------------------------------------------------------
enum class ParityStatus : uint8_t {
    Unverified = 0,   // no measurement recorded
    PackingVerified,  // packed representation matches the reference byte-for-byte
    DotVerified,      // quantized dot matches the reference within tolerance
    LogitsVerified,   // layer/logit outputs match the reference
    Failed,           // a recorded measurement DID NOT match
};

inline const char* ParityStatusName(ParityStatus s) {
    switch (s) {
        case ParityStatus::Unverified:      return "unverified";
        case ParityStatus::PackingVerified: return "packing_verified";
        case ParityStatus::DotVerified:     return "dot_verified";
        case ParityStatus::LogitsVerified:  return "logits_verified";
        case ParityStatus::Failed:          return "FAILED";
        default:                            return "unknown";
    }
}

// What path of the model a certification covers.
enum class ParityPath : uint8_t {
    Packing  = 0,  // activation/tensor packing
    Dot      = 1,  // quantized dot product
    Logits   = 2,  // layer outputs / logits
    Generation = 3, // autoregressive / KV-cache behaviour
};

inline const char* ParityPathName(ParityPath p) {
    switch (p) {
        case ParityPath::Packing:    return "packing";
        case ParityPath::Dot:        return "dot";
        case ParityPath::Logits:     return "logits";
        case ParityPath::Generation: return "generation";
        default:                     return "unknown";
    }
}

// ---------------------------------------------------------------------------
// One recorded certification
// ---------------------------------------------------------------------------
struct ParityEvidence {
    uint32_t    ggmlId;
    ParityPath  path;
    ParityStatus status;
    std::string evidenceRef;    // harness/artifact that produced the measurement
    std::string detail;         // what was measured, counts, tolerance
    int64_t     recordedAt;
};

// ---------------------------------------------------------------------------
// Kernel binding
// ---------------------------------------------------------------------------
struct KernelBinding {
    uint32_t    ggmlId;
    const char* quantName;      // from QuantTypeTable
    std::string kernelName;     // native kernel / dispatch entry
    bool        kernelReady;    // mirror of QuantTypeTable.kernelReady
    ParityStatus bestStatus = ParityStatus::Unverified;
    std::string evidenceRef;
};

// ---------------------------------------------------------------------------
// Admission decision
// ---------------------------------------------------------------------------
enum class Admission : uint8_t {
    Refused      = 0,  // unknown type, or no kernel at all
    ProbeOnly    = 1,  // kernel exists but packing parity unverified
    Certified    = 2,  // kernel + packing verified
};

struct AdmissionDecision {
    Admission    verdict = Admission::Refused;
    std::string  reason;
    const KernelBinding* binding = nullptr;
};

// ---------------------------------------------------------------------------
// Primitive gate result (MLA preservation)
// ---------------------------------------------------------------------------
struct PrimitiveGate {
    ModelGenie::Primitive primitive = ModelGenie::Primitive::None;
    bool available       = false;
    bool implementationRequired = false;   // true = MUST be implemented, not optional
    bool kernelPresent   = false;
};

// ---------------------------------------------------------------------------
// QuantParityRegistry
// ---------------------------------------------------------------------------
class QuantParityRegistry {
public:
    static QuantParityRegistry& Instance();

    // ---- Binding (geometry always read from QuantTypeTable) ----
    // Binds (or replaces) the kernel for a ggml id. Unknown/removed ids are
    // rejected so a caller cannot bind a kernel to a nonexistent geometry.
    bool BindKernel(uint32_t ggmlId, const std::string& kernelName);

    const KernelBinding* Find(uint32_t ggmlId) const;
    std::vector<KernelBinding> AllBindings() const;

    // ---- Certification: evidence-bearing only ----
    // Records a measurement. `evidenceRef` must name the harness/artifact that
    // produced it; an empty ref is rejected so no certificate can be invented.
    // Status is monotonic within Packing->Dot->Logits; a Failed record is
    // never overwritten by a later Unverified for the same (id,path).
    bool RecordParity(uint32_t ggmlId, ParityPath path, ParityStatus status,
                      const std::string& evidenceRef,
                      const std::string& detail = "");

    ParityStatus StatusOf(uint32_t ggmlId, ParityPath path) const;
    ParityStatus BestStatus(uint32_t ggmlId) const;
    std::vector<ParityEvidence> EvidenceFor(uint32_t ggmlId) const;
    std::vector<ParityEvidence> AllEvidence() const;

    // ---- Admission ----
    AdmissionDecision Admit(uint32_t ggmlId) const;
    bool IsCertified(uint32_t ggmlId) const;

    // ---- Coverage summary ----
    struct Coverage {
        int knownTypes = 0;
        int bound = 0;
        int packingVerified = 0;
        int dotVerified = 0;
        int logitsVerified = 0;
        int failed = 0;
        int kernelMissing = 0;   // persisted in GGUF but no kernel bound
    };
    Coverage ComputeCoverage() const;

    // ---- Primitive gate (MLA preserved) ----
    // Returns the gate for a ModelGenie primitive. Unimplemented primitives
    // are reported with implementationRequired = true, which keeps
    // runtimeExecutable false until they are actually implemented.
    static PrimitiveGate GatePrimitive(ModelGenie::Primitive p);

    // Is the runtime executable for this genome's required primitives?
    static bool RuntimeExecutable(const ModelGenie::ModelGenome& genome);

    // ---- Built-in bindings ----
    // Registers the native kernels Deep2 actually implements today. Types with
    // no entry stay unbound and are therefore never certified.
    void RegisterBuiltinKernels();

    // ---- Serialization for the evidence ledger ----
    std::string ToJson() const;

private:
    QuantParityRegistry() = default;
    mutable std::mutex m_mtx;
    std::map<uint32_t, KernelBinding>  m_bindings;
    std::vector<ParityEvidence>        m_evidence;
};

} // namespace Deep2
} // namespace RawrXD
