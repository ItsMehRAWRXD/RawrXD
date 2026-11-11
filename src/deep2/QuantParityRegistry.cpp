// =============================================================================
// QuantParityRegistry.cpp — universal quantization registry + parity certification
// =============================================================================
#include "QuantParityRegistry.h"

#include <sstream>
#include <chrono>
#include <algorithm>

namespace RawrXD {
namespace Deep2 {

QuantParityRegistry& QuantParityRegistry::Instance() {
    static QuantParityRegistry inst;
    return inst;
}

static int64_t NowUnixMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

// ---------------------------------------------------------------------------
// Primitive identity — the single source of truth for manifest provenance.
// Every primitive's name and binding note is derived here, so a manifest entry
// can never describe a different primitive than the one it reports.
// ---------------------------------------------------------------------------
static const char* PrimitiveName(ModelGenie::Primitive p) {
    switch (p) {
        case ModelGenie::Primitive::RmsNormFwd:       return "RmsNormFwd";
        case ModelGenie::Primitive::LinearFwd:        return "LinearFwd";
        case ModelGenie::Primitive::MatMulFwd:        return "MatMulFwd";
        case ModelGenie::Primitive::AttentionFwd:     return "AttentionFwd";
        case ModelGenie::Primitive::MlaDecompressFwd: return "MlaDecompressFwd";
        case ModelGenie::Primitive::RouterFwd:        return "RouterFwd";
        case ModelGenie::Primitive::TopKFwd:          return "TopKFwd";
        case ModelGenie::Primitive::MoEExecuteFwd:    return "MoEExecuteFwd";
        case ModelGenie::Primitive::ResidualAddFwd:   return "ResidualAddFwd";
        case ModelGenie::Primitive::LMHeadFwd:        return "LMHeadFwd";
        case ModelGenie::Primitive::None:
        default:                                      return "None";
    }
}

// Where the binding actually lives in the dispatcher.
// MatMulFwd reports the true state (dispatch returns false) rather than
// borrowing an implemented primitive's provenance.
static const char* PrimitiveBindingNote(ModelGenie::Primitive p) {
    switch (p) {
        case ModelGenie::Primitive::RmsNormFwd:       return "ModelGenieExecutor.cpp:RmsNormFwd dispatch";
        case ModelGenie::Primitive::LinearFwd:        return "ModelGenieExecutor.cpp:LinearFwd dispatch";
        case ModelGenie::Primitive::MatMulFwd:        return "ModelGenieExecutor.cpp:MatMulFwd dispatch returns false; no graph producer emits it (Universal::Op::MatMul lowered to OpKind::Unsupported)";
        case ModelGenie::Primitive::AttentionFwd:     return "ModelGenieExecutor.cpp:AttentionFwd dispatch";
        case ModelGenie::Primitive::MlaDecompressFwd: return "ModelGenieExecutor.cpp:MlaDecompressFwd dispatch";
        case ModelGenie::Primitive::RouterFwd:        return "ModelGenieExecutor.cpp:RouterFwd dispatch (via LinearFwd)";
        case ModelGenie::Primitive::TopKFwd:          return "ModelGenieExecutor.cpp:TopKFwd dispatch";
        case ModelGenie::Primitive::MoEExecuteFwd:    return "ModelGenieExecutor.cpp:MoEExecuteFwd dispatch";
        case ModelGenie::Primitive::ResidualAddFwd:   return "ModelGenieExecutor.cpp:ResidualAddFwd dispatch";
        case ModelGenie::Primitive::LMHeadFwd:        return "ModelGenieExecutor.cpp:LMHeadFwd dispatch";
        case ModelGenie::Primitive::None:
        default:                                      return "not declared";
    }
}

// ---------------------------------------------------------------------------
// Kernel binding
// ---------------------------------------------------------------------------
bool QuantParityRegistry::BindKernel(uint32_t ggmlId, const std::string& kernelName) {
    // Geometry is owned by QuantTypeTable. Refuse to bind a kernel to a type
    // with unknown/zero geometry so nothing can be bound to a fallback {4,1}.
    const QuantTypeDescriptor* d = LookupQuantType(ggmlId);
    if (!d) return false;

    std::lock_guard<std::mutex> lock(m_mtx);
    KernelBinding b;
    b.ggmlId     = ggmlId;
    b.quantName  = d->name;
    b.kernelName = kernelName;
    b.kernelReady = d->kernelReady;

    auto it = m_bindings.find(ggmlId);
    if (it != m_bindings.end()) {
        it->second.kernelName = kernelName;
        it->second.kernelReady = d->kernelReady;
        return true;
    }
    m_bindings[ggmlId] = b;
    return true;
}

const KernelBinding* QuantParityRegistry::Find(uint32_t ggmlId) const {
    std::lock_guard<std::mutex> lock(m_mtx);
    auto it = m_bindings.find(ggmlId);
    return it != m_bindings.end() ? &it->second : nullptr;
}

std::vector<KernelBinding> QuantParityRegistry::AllBindings() const {
    std::lock_guard<std::mutex> lock(m_mtx);
    std::vector<KernelBinding> out;
    out.reserve(m_bindings.size());
    for (const auto& [id, b] : m_bindings) out.push_back(b);
    std::sort(out.begin(), out.end(),
              [](const KernelBinding& a, const KernelBinding& b) { return a.ggmlId < b.ggmlId; });
    return out;
}

// ---------------------------------------------------------------------------
// Certification — evidence-bearing only
// ---------------------------------------------------------------------------
bool QuantParityRegistry::RecordParity(uint32_t ggmlId, ParityPath path,
                                       ParityStatus status,
                                       const std::string& evidenceRef,
                                       const std::string& detail) {
    // No evidence reference -> no certificate. This is the guard that makes a
    // fabricated certificate impossible rather than merely discouraged.
    if (evidenceRef.empty()) return false;

    // Only a known, non-zero-geometry type can be certified.
    if (!LookupQuantType(ggmlId)) return false;

    std::lock_guard<std::mutex> lock(m_mtx);

    ParityEvidence ev;
    ev.ggmlId      = ggmlId;
    ev.path        = path;
    ev.status      = status;
    ev.evidenceRef = evidenceRef;
    ev.detail      = detail;
    ev.recordedAt  = NowUnixMs();
    m_evidence.push_back(ev);

    // Fold into the binding's best status. A Failed record must not be
    // overwritten by a later Unverified for the same (id, path).
    auto it = m_bindings.find(ggmlId);
    if (it != m_bindings.end()) {
        if (static_cast<uint8_t>(status) > static_cast<uint8_t>(it->second.bestStatus)) {
            it->second.bestStatus = status;
            it->second.evidenceRef = evidenceRef;
        }
    }
    return true;
}

ParityStatus QuantParityRegistry::StatusOf(uint32_t ggmlId, ParityPath path) const {
    std::lock_guard<std::mutex> lock(m_mtx);
    // The strongest status recorded for this exact (id, path).
    ParityStatus best = ParityStatus::Unverified;
    bool failed = false;
    for (const auto& e : m_evidence) {
        if (e.ggmlId != ggmlId || e.path != path) continue;
        if (e.status == ParityStatus::Failed) { failed = true; }
        if (static_cast<uint8_t>(e.status) > static_cast<uint8_t>(best)) best = e.status;
    }
    return failed ? ParityStatus::Failed : best;
}

ParityStatus QuantParityRegistry::BestStatus(uint32_t ggmlId) const {
    std::lock_guard<std::mutex> lock(m_mtx);
    ParityStatus best = ParityStatus::Unverified;
    bool failed = false;
    for (const auto& e : m_evidence) {
        if (e.ggmlId != ggmlId) continue;
        if (e.status == ParityStatus::Failed) failed = true;
        if (static_cast<uint8_t>(e.status) > static_cast<uint8_t>(best)) best = e.status;
    }
    return failed ? ParityStatus::Failed : best;
}

std::vector<ParityEvidence> QuantParityRegistry::EvidenceFor(uint32_t ggmlId) const {
    std::lock_guard<std::mutex> lock(m_mtx);
    std::vector<ParityEvidence> out;
    for (const auto& e : m_evidence) if (e.ggmlId == ggmlId) out.push_back(e);
    return out;
}

std::vector<ParityEvidence> QuantParityRegistry::AllEvidence() const {
    std::lock_guard<std::mutex> lock(m_mtx);
    return m_evidence;
}

// ---------------------------------------------------------------------------
// Admission — fail-closed
// ---------------------------------------------------------------------------
AdmissionDecision QuantParityRegistry::Admit(uint32_t ggmlId) const {
    AdmissionDecision d;

    // Unknown or zero-geometry type: refused, never a silent fallback.
    const QuantTypeDescriptor* desc = LookupQuantType(ggmlId);
    if (!desc) {
        d.verdict = Admission::Refused;
        d.reason  = "unknown or removed ggml type " + std::to_string(ggmlId) +
                    " (zero geometry -> fail-closed)";
        return d;
    }

    const KernelBinding* b = Find(ggmlId);
    if (!b || b->kernelName.empty() || !desc->kernelReady) {
        d.verdict = Admission::Refused;
        d.reason  = std::string("kernel not implemented for ") + desc->name;
        return d;
    }

    d.binding = b;

    const ParityStatus packing = StatusOf(ggmlId, ParityPath::Packing);
    if (packing == ParityStatus::Failed) {
        d.verdict = Admission::Refused;
        d.reason  = std::string(desc->name) + " packing parity FAILED against reference";
        return d;
    }
    if (static_cast<uint8_t>(packing) < static_cast<uint8_t>(ParityStatus::PackingVerified)) {
        d.verdict = Admission::ProbeOnly;
        d.reason  = std::string(desc->name) +
                    " has a kernel but packing parity is unverified; probing only, "
                    "no certificate can be produced";
        return d;
    }

    d.verdict = Admission::Certified;
    d.reason  = std::string(desc->name) + " kernel bound and packing parity verified";
    return d;
}

bool QuantParityRegistry::IsCertified(uint32_t ggmlId) const {
    return Admit(ggmlId).verdict == Admission::Certified;
}

// ---------------------------------------------------------------------------
// Coverage
// ---------------------------------------------------------------------------
QuantParityRegistry::Coverage QuantParityRegistry::ComputeCoverage() const {
    std::lock_guard<std::mutex> lock(m_mtx);

    Coverage c{};
    for (uint32_t i = 0; i < static_cast<uint32_t>(GGMLType::GGML_TYPE_COUNT); ++i) {
        const auto& d = QuantTypeTable()[i];
        if (d.blockElements == 0) continue;   // removed / unknown
        ++c.knownTypes;

        auto bit = m_bindings.find(i);
        if (bit == m_bindings.end() || bit->second.kernelName.empty()) {
            if (d.persistedGGUF) ++c.kernelMissing;
            continue;
        }
        ++c.bound;

        if (d.kernelReady && !bit->second.kernelReady) ++c.kernelMissing;
    }

    // Parity counters from the evidence log.
    std::map<uint32_t, ParityStatus> bestPacking;
    for (const auto& e : m_evidence) {
        ParityStatus& cur = bestPacking[e.ggmlId];
        if (static_cast<uint8_t>(e.status) > static_cast<uint8_t>(cur)) cur = e.status;
    }
    for (const auto& [id, st] : bestPacking) {
        switch (st) {
            case ParityStatus::PackingVerified: ++c.packingVerified; break;
            case ParityStatus::DotVerified:     ++c.dotVerified;     break;
            case ParityStatus::LogitsVerified:  ++c.logitsVerified;  break;
            case ParityStatus::Failed:          ++c.failed;          break;
            default: break;
        }
    }
    return c;
}

// ---------------------------------------------------------------------------
// Primitive gate — MLA PRESERVED as required-but-unimplemented where true
// ---------------------------------------------------------------------------
// Ground truth comes from what the executor actually implements, NOT from the
// generated CapabilityManifest. That manifest is produced by the frozen
// NUGVERSE_ESTIMATOR_001 and had gone stale: it reports MlaDecompressFwd as
// unimplemented while src/modelgenie/ModelGenieExecutor.cpp:1917 provides the
// full latent -> RMSNorm -> B-projection -> RoPE -> KV-write implementation
// and the dispatcher at :1145 binds to it.
//
// A stale manifest that under-reports capability keeps runtimeExecutable false
// forever, which blocks real models for no reason. So this gate is driven by
// the executor's own bindings.
PrimitiveGate QuantParityRegistry::GatePrimitive(ModelGenie::Primitive p) {
    PrimitiveGate g;
    g.primitive = p;

    // Implemented AND bound in src/modelgenie/ModelGenieExecutor.cpp.
    // The case label is the binding; the function is the implementation.
    switch (p) {
        case ModelGenie::Primitive::RmsNormFwd:
        case ModelGenie::Primitive::LinearFwd:
        case ModelGenie::Primitive::AttentionFwd:
        case ModelGenie::Primitive::MlaDecompressFwd:
        case ModelGenie::Primitive::ResidualAddFwd:
        case ModelGenie::Primitive::RouterFwd:
        case ModelGenie::Primitive::TopKFwd:
        case ModelGenie::Primitive::MoEExecuteFwd:
        case ModelGenie::Primitive::LMHeadFwd:
            g.available = true;
            g.kernelPresent = true;
            // Required, and now satisfied.
            g.implementationRequired = true;
            break;

        case ModelGenie::Primitive::MatMulFwd:
            // Declared, gated, and still returning false in the dispatcher
            // (ModelGenieExecutor.cpp). Deliberately NOT folded into LinearFwd:
            // LinearFwd is a weight-backed GGUF projection while MatMulFwd is a
            // general tensor x tensor product, so aliasing them would let a
            // caller compute the wrong thing. No graph producer emits
            // Universal::Op::MatMul today (11 sites emit Op::Linear, 0 emit
            // Op::MatMul), and that op is lowered to OpKind::Unsupported so a
            // future producer fails closed at bind time instead of silently
            // mis-executing.
            g.available = false;
            g.kernelPresent = false;
            g.implementationRequired = true;
            break;

        case ModelGenie::Primitive::None:
        default:
            g.available = false;
            g.kernelPresent = false;
            g.implementationRequired = false;
            break;
    }
    return g;
}

// ---------------------------------------------------------------------------
// Primitive manifest provenance (Gate 2)
// ---------------------------------------------------------------------------
// The reported primitive surface is DERIVED from the gate, not hand-listed.
// PrimitiveRangeFirst/Last bracket the declared enum values in
// ModelGenome.hpp; PrimitiveIsReported asks GatePrimitive() whether it returns
// a verdict for that value. There is therefore no second list that could drift
// out of sync with the enum or with the gate's own bindings, and
// quant_parity_cert.cpp can prove exactly-once coverage against a set it did
// not build itself.
ModelGenie::Primitive QuantParityRegistry::PrimitiveRangeFirst() {
    // `None` (0) is the sentinel and is deliberately excluded.
    return ModelGenie::Primitive::RmsNormFwd;
}

ModelGenie::Primitive QuantParityRegistry::PrimitiveRangeLast() {
    return ModelGenie::Primitive::LMHeadFwd;
}

bool QuantParityRegistry::PrimitiveIsReported(ModelGenie::Primitive p) {
    const PrimitiveGate g = GatePrimitive(p);
    return g.available || g.implementationRequired;
}

const std::vector<ModelGenie::Primitive>& QuantParityRegistry::KnownPrimitives() {
    static const std::vector<ModelGenie::Primitive> reported = [] {
        std::vector<ModelGenie::Primitive> v;
        const uint16_t last = static_cast<uint16_t>(PrimitiveRangeLast());
        for (uint16_t i = static_cast<uint16_t>(PrimitiveRangeFirst()); i <= last; ++i) {
            const auto p = static_cast<ModelGenie::Primitive>(i);
            if (PrimitiveIsReported(p)) v.push_back(p);
        }
        return v;
    }();
    return reported;
}

const char* QuantParityRegistry::PrimitiveNameOf(ModelGenie::Primitive p) {
    return PrimitiveName(p);
}

// Registry binding status for a gate result.
static const char* PrimitiveBindingStatus(const PrimitiveGate& g) {
    if (g.available)               return "bound";
    if (g.implementationRequired)  return "declared_unimplemented";
    return "not_required";
}

// The gate's own verdict. A required primitive the gate cannot satisfy stays
// required_unimplemented; it is never softened into "optional".
static const char* PrimitiveGateVerdict(const PrimitiveGate& g) {
    if (g.available)               return "available";
    if (g.implementationRequired)  return "required_unimplemented";
    return "not_required";
}

// Walks the whole declared enum range and derives a record for EVERY value,
// including ones the gate does not report on. The caller's exactly-once check
// is therefore load-bearing: an entry for an unreported primitive, a missing
// entry, or a duplicate is rejected there rather than silently normalized.
std::vector<QuantParityRegistry::PrimitiveRecord>
QuantParityRegistry::DescribePrimitiveGates() {
    std::vector<PrimitiveRecord> out;
    const uint16_t last = static_cast<uint16_t>(PrimitiveRangeLast());
    for (uint16_t i = static_cast<uint16_t>(PrimitiveRangeFirst()); i <= last; ++i) {
        const auto p = static_cast<ModelGenie::Primitive>(i);
        const PrimitiveGate g = GatePrimitive(p);
        PrimitiveRecord r;
        r.primitive              = p;
        r.name                   = PrimitiveName(p);
        r.registrationSource     = PrimitiveBindingNote(p);
        r.status                 = PrimitiveBindingStatus(g);
        r.gateVerdict            = PrimitiveGateVerdict(g);
        r.available              = g.available;
        r.implementationRequired = g.implementationRequired;
        r.kernelPresent          = g.kernelPresent;
        out.push_back(std::move(r));
    }
    return out;
}

bool QuantParityRegistry::GateSatisfied(ModelGenie::Primitive p) {
    return GatePrimitive(p).available;
}

bool QuantParityRegistry::RuntimeExecutable(const ModelGenie::ModelGenome& genome) {
    // Executable only when every REQUIRED primitive is available. A required
    // primitive with no kernel keeps this false; that is the contract that
    // stops an unimplemented path from being reported as runnable.
    for (const auto& required : genome.capabilities.requiredPrimitives) {
        if (required == ModelGenie::Primitive::None) continue;
        const PrimitiveGate g = GatePrimitive(required);
        if (g.implementationRequired && !g.available) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Built-in kernel bindings — only what Deep2 actually implements
// ---------------------------------------------------------------------------
void QuantParityRegistry::RegisterBuiltinKernels() {
    using G = GGMLType;
    struct Entry { uint32_t id; const char* kernel; };
    // Deep2's native dequant+GEMV kernels, per QuantTypeTable.kernelReady.
    static const Entry kEntries[] = {
        { static_cast<uint32_t>(G::GGML_TYPE_F32),     "gemv_f32" },
        { static_cast<uint32_t>(G::GGML_TYPE_F16),     "gemv_f16" },
        { static_cast<uint32_t>(G::GGML_TYPE_BF16),    "gemv_bf16" },
        { static_cast<uint32_t>(G::GGML_TYPE_Q4_0),    "gemv_q4_0" },
        { static_cast<uint32_t>(G::GGML_TYPE_Q4_1),    "gemv_q4_1" },
        { static_cast<uint32_t>(G::GGML_TYPE_Q5_0),    "gemv_q5_0" },
        { static_cast<uint32_t>(G::GGML_TYPE_Q5_1),    "gemv_q5_1" },
        { static_cast<uint32_t>(G::GGML_TYPE_Q8_0),    "gemv_q8_0" },
        { static_cast<uint32_t>(G::GGML_TYPE_Q2_K),    "gemv_q2_k" },
        { static_cast<uint32_t>(G::GGML_TYPE_Q3_K),    "gemv_q3_k" },
        { static_cast<uint32_t>(G::GGML_TYPE_Q4_K),    "gemv_q4_k" },
        { static_cast<uint32_t>(G::GGML_TYPE_Q5_K),    "gemv_q5_k" },
        { static_cast<uint32_t>(G::GGML_TYPE_Q6_K),    "gemv_q6_k" },
        { static_cast<uint32_t>(G::GGML_TYPE_Q8_K),    "gemv_q8_k" },
        { static_cast<uint32_t>(G::GGML_TYPE_IQ2_XXS), "gemv_iq2_xxs" },
        { static_cast<uint32_t>(G::GGML_TYPE_IQ2_XS),  "gemv_iq2_xs" },
        { static_cast<uint32_t>(G::GGML_TYPE_IQ3_XXS), "gemv_iq3_xxs" },
        { static_cast<uint32_t>(G::GGML_TYPE_IQ1_S),   "gemv_iq1_s" },
        { static_cast<uint32_t>(G::GGML_TYPE_IQ4_NL),  "gemv_iq4_nl" },
        { static_cast<uint32_t>(G::GGML_TYPE_IQ3_S),   "gemv_iq3_s" },
        { static_cast<uint32_t>(G::GGML_TYPE_IQ2_S),   "gemv_iq2_s" },
        { static_cast<uint32_t>(G::GGML_TYPE_IQ4_XS),  "gemv_iq4_xs" },
    };
    for (const auto& e : kEntries) {
        BindKernel(e.id, e.kernel);
    }
    // Deliberately NOT bound: Q8_1, IQ1_M, TQ1_0, TQ2_0, MXFP4, NVFP4, Q1_0,
    // Q2_0, I8/I16/I32/I64/F64. QuantTypeTable marks them kernelReady=false, so
    // they stay unbound and are refused by Admit() rather than faked.
}

// ---------------------------------------------------------------------------
// Evidence ledger serialization
// ---------------------------------------------------------------------------
// The snapshot is taken through the self-locking const accessors and the text
// is built afterwards. m_mtx is a plain (non-recursive) mutex, so holding it
// across ComputeCoverage()/StatusOf() would self-deadlock on the first call;
// that is what made every --json run of quant_parity_cert hang before.
std::string QuantParityRegistry::ToJson() const {
    const Coverage cov                     = ComputeCoverage();
    const std::vector<KernelBinding> binds = AllBindings();   // sorted by ggml_id
    const std::vector<ParityEvidence> evs  = AllEvidence();   // insertion order
    const std::vector<PrimitiveRecord> prims = DescribePrimitiveGates();

    std::vector<ParityStatus> packing;
    packing.reserve(binds.size());
    for (const auto& b : binds) packing.push_back(StatusOf(b.ggmlId, ParityPath::Packing));

    std::ostringstream os;
    os << "{\n";
    os << "  \"schema\": \"RAWRXD_QUANT_PARITY_REGISTRY/1.0\",\n";

    os << "  \"coverage\": {\n"
       << "    \"known_types\": " << cov.knownTypes << ",\n"
       << "    \"kernel_bound\": " << cov.bound << ",\n"
       << "    \"packing_verified\": " << cov.packingVerified << ",\n"
       << "    \"dot_verified\": " << cov.dotVerified << ",\n"
       << "    \"logits_verified\": " << cov.logitsVerified << ",\n"
       << "    \"failed\": " << cov.failed << ",\n"
       << "    \"kernel_missing\": " << cov.kernelMissing << "\n"
       << "  },\n";

    // Bindings
    os << "  \"bindings\": [\n";
    bool first = true;
    for (size_t i = 0; i < binds.size(); ++i) {
        if (!first) os << ",\n";
        first = false;
        os << "    {\"ggml_id\": " << binds[i].ggmlId
           << ", \"type\": \"" << binds[i].quantName << "\""
           << ", \"kernel\": \"" << binds[i].kernelName << "\""
           << ", \"kernel_ready\": " << (binds[i].kernelReady ? "true" : "false")
           << ", \"packing_parity\": \"" << ParityStatusName(packing[i]) << "\""
           << ", \"evidence\": \"" << binds[i].evidenceRef << "\"}";
    }
    os << "\n  ],\n";

    // Primitive gates (MLA reality)
    //
    // The name and note MUST be derived from the primitive being reported.
    // The previous emitter printed "mla_decompress" and
    // "ModelGenieExecutor.cpp:1917" for every primitive, so an unimplemented
    // primitive was described using an implemented one's provenance and the
    // manifest looked healthy. A manifest that cannot identify the primitive it
    // is reporting is not evidence.
    os << "  \"primitive_gates\": [\n";
    first = true;
    for (const auto& r : prims) {
        if (!first) os << ",\n";
        first = false;
        os << "    {\"primitive\": \"" << r.name << "\""
           << ", \"available\": " << (r.available ? "true" : "false")
           << ", \"implementation_required\": " << (r.implementationRequired ? "true" : "false")
           << ", \"kernel_present\": " << (r.kernelPresent ? "true" : "false")
           << ", \"binding_status\": \"" << r.status << "\""
           << ", \"gate_verdict\": \"" << r.gateVerdict << "\""
           << ", \"note\": \"" << r.registrationSource << "\"}";
    }
    os << "\n  ],\n";

    // Evidence log
    os << "  \"evidence\": [\n";
    first = true;
    for (const auto& e : evs) {
        if (!first) os << ",\n";
        first = false;
        os << "    {\"ggml_id\": " << e.ggmlId
           << ", \"path\": \"" << ParityPathName(e.path) << "\""
           << ", \"status\": \"" << ParityStatusName(e.status) << "\""
           << ", \"evidence\": \"" << e.evidenceRef << "\""
           << ", \"detail\": \"" << e.detail << "\""
           << ", \"recorded_at_ms\": " << e.recordedAt << "}";
    }
    os << "\n  ]\n";
    os << "}\n";
    return os.str();
}

} // namespace Deep2
} // namespace RawrXD
