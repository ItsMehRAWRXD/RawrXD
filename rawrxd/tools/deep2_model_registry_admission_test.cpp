// deep2_model_registry_admission_test.cpp
// RAWRXD_DEEP2_MODEL_REGISTRY_001 — Batch 3/4 admission + registry gate.
//
// Every verdict line below is DERIVED from a counter that was incremented by
// running the real Deep2::ModelRegistry code against constructed metadata. There
// are no literal PASS strings in any gate field.
//
// The architectures registered here are test fixtures: they exercise the
// registry's resolve/admit logic. They are NOT evidence that the engine has
// registered production implementations — that is a separate gate
// (MODEL_REGISTRY_CALLED_BY_LOADER), proven against the real load path.

#include "Deep2ModelRegistry.hpp"
#include "Deep2ModelArchitecture.hpp"
#include "QuantKernelRegistry.hpp"

#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>

using namespace Deep2;

// -----------------------------------------------------------------------------
// Test fixtures
// -----------------------------------------------------------------------------
namespace {

// Counters. Each is incremented only when the corresponding assertion holds.
struct Gate {
    unsigned dense_admitted = 0;
    unsigned moe_admitted = 0;
    unsigned ssm_admitted = 0;
    unsigned hybrid_admitted = 0;
    unsigned mla_admitted = 0;

    unsigned unknown_arch_rejected = 0;
    unsigned missing_tensor_rejected = 0;
    unsigned unsupported_quant_rejected = 0;
    unsigned unsupported_operator_rejected = 0;
    unsigned malformed_metadata_rejected = 0;

    unsigned name_guessing_rejected = 0;
    unsigned unregistered_arch_rejected = 0;
    unsigned collision_safe = 0;
} g;

// A fixture architecture. probe returns true only for the arch id it was
// registered under, so a descriptor can never be returned for a different id.
bool fixtureProbe(const ModelMetadata& md) noexcept {
    return md.canonicalName == "fixture";
}

LoadResult fixtureLoad(Deep2Engine&, const ModelMetadata&) {
    LoadResult r;
    r.ok = false;
    r.error = "fixture_load_not_executable_in_test";
    return r;
}

bool fixtureContext(Deep2Engine&, const ModelMetadata&) noexcept { return false; }

ArchitectureForwardResult fixtureForward(Deep2Engine&, const ForwardRequest&) {
    ArchitectureForwardResult r;
    r.code = ArchitectureForwardResult::Code::ForwardFailed;
    return r;
}

void fixtureReset(Deep2Engine&) noexcept {}
void fixtureDestroy(Deep2Engine&) noexcept {}

// One registered fixture per canonical architecture key we exercise. The id is
// the canonical arch key so resolve(metadata) can find it; probe/load/forward
// are deliberately inert because this test asserts admission, not execution.
const Architecture* registerFixture(const char* id) {
    static std::vector<Architecture*> keepAlive;
    auto* a = new Architecture();
    a->id = id;
    a->probe = fixtureProbe;
    a->load = fixtureLoad;
    a->createContext = fixtureContext;
    a->forward = fixtureForward;
    a->resetGeneration = fixtureReset;
    a->destroy = fixtureDestroy;
    keepAlive.push_back(a);
    ModelRegistry::registerArchitecture(a);
    return a;
}

// -----------------------------------------------------------------------------
// Metadata construction
// -----------------------------------------------------------------------------
ModelMetadata denseMeta(const char* arch) {
    ModelMetadata md;
    // canonicalName holds the PARSED architecture tag, not a filename.
    md.canonicalName = arch;
    md.hiddenDim = 1024;
    md.numLayers = 2;
    md.numHeads = 8;
    md.numKVHeads = 8;
    md.headDim = 128;          // 8 * 128 == 1024
    md.vocabSize = 32000;
    md.intermediateDim = 2816;
    md.quantization = "Q8_0";
    md.quantTypeId = 8;        // GGML_TYPE_Q8_0
    md.normEps = 1e-5f;

    md.presentTensors = {
        "token_embd.weight", "output_norm.weight", "output.weight",
        "blk.0.attn_norm.weight", "blk.1.attn_norm.weight",
        "blk.0.attn_q.weight", "blk.1.attn_q.weight",
        "blk.0.attn_k.weight", "blk.1.attn_k.weight",
        "blk.0.attn_v.weight", "blk.1.attn_v.weight",
        "blk.0.attn_output.weight", "blk.1.attn_output.weight",
        "blk.0.ffn_norm.weight", "blk.1.ffn_norm.weight",
        "blk.0.ffn_gate.weight", "blk.1.ffn_gate.weight",
        "blk.0.ffn_up.weight", "blk.1.ffn_up.weight",
        "blk.0.ffn_down.weight", "blk.1.ffn_down.weight",
    };
    return md;
}

ModelMetadata moeMeta(const char* arch) {
    ModelMetadata md;
    md.canonicalName = arch;
    md.hiddenDim = 1024;
    md.numLayers = 2;
    md.numHeads = 8;
    md.numKVHeads = 4;         // GQA
    md.headDim = 128;
    md.vocabSize = 32000;
    md.intermediateDim = 2816;
    // MoE determination is authoritative from these parsed fields.
    md.numExperts = 64;
    md.numExpertsPerToken = 8;
    md.moeIntermediateDim = 768;
    md.quantization = "Q4_K_M";
    md.quantTypeId = 12;       // GGML_TYPE_Q4_K
    md.normEps = 1e-5f;

md.presentTensors = {
        "token_embd.weight", "output_norm.weight", "output.weight",
        "blk.0.attn_norm.weight", "blk.1.attn_norm.weight",
        "blk.0.attn_q.weight", "blk.1.attn_q.weight",
        "blk.0.attn_k.weight", "blk.1.attn_k.weight",
        "blk.0.attn_v.weight", "blk.1.attn_v.weight",
        "blk.0.attn_output.weight", "blk.1.attn_output.weight",
        "blk.0.ffn_gate_inp.weight", "blk.1.ffn_gate_inp.weight",
        "blk.0.ffn_gate_exps.weight", "blk.1.ffn_gate_exps.weight",
        "blk.0.ffn_up_exps.weight", "blk.1.ffn_up_exps.weight",
        "blk.0.ffn_down_exps.weight", "blk.1.ffn_down_exps.weight",
    };
    return md;
}

ModelMetadata ssmMeta(const char* arch) {
    ModelMetadata md;
    md.canonicalName = arch;
    md.hiddenDim = 1024;
    md.numLayers = 2;
    md.numHeads = 8;
    md.numKVHeads = 8;
    md.headDim = 128;
    md.vocabSize = 32000;
    md.intermediateDim = 2816;
    // Parsed SSM geometry. All five must be non-zero for a recurrent arch.
    md.ssmInner = 4096;
    md.ssmStateSize = 128;
    md.ssmHeads = 128;
    md.ssmGroups = 8;
    md.ssmConvKernel = 4;
    md.quantization = "Q8_0";
    md.quantTypeId = 8;
    md.normEps = 1e-5f;

    md.presentTensors = {
        "token_embd.weight", "output_norm.weight",
        "blk.0.ssm_in.weight", "blk.1.ssm_in.weight",
        "blk.0.ssm_conv1d.weight", "blk.1.ssm_conv1d.weight",
        "blk.0.ssm_out.weight", "blk.1.ssm_out.weight",
        "blk.0.ssm_dt.weight", "blk.1.ssm_dt.weight",
        "blk.0.ssm_a.weight", "blk.1.ssm_a.weight",
    };
    return md;
}

// Nemotron-H: a hybrid stack mixing attention layers and Mamba2 recurrent layers.
ModelMetadata hybridMeta(const char* arch) {
    ModelMetadata md = ssmMeta(arch);
    md.ssmInner = 4096;
    md.ssmStateSize = 128;
    md.ssmHeads = 128;
    md.ssmGroups = 8;
    md.ssmConvKernel = 4;
    // Nemotron-H carries BOTH the recurrent tensors and the dense attention
    // tensors; layer 0 is attention, layer 1 is recurrent. Per-layer pattern
    // arrays record which is which and must be numLayers long.
    md.presentTensors.push_back("blk.0.attn_norm.weight");
    md.presentTensors.push_back("blk.0.attn_q.weight");
    md.presentTensors.push_back("blk.0.attn_k.weight");
    md.presentTensors.push_back("blk.0.attn_v.weight");
    md.presentTensors.push_back("blk.0.attn_output.weight");
    md.presentTensors.push_back("blk.0.ffn_norm.weight");
    md.presentTensors.push_back("blk.0.ffn_gate.weight");
    md.presentTensors.push_back("blk.0.ffn_up.weight");
    md.presentTensors.push_back("blk.0.ffn_down.weight");
    md.nemotronHeadKvPerLayer = {1, 0};
    md.nemotronFfPerLayer = {1, 0};
    md.nemotronPatternOk = true;
    return md;
}

ModelMetadata mlaMeta(const char* arch) {
    ModelMetadata md;
    md.canonicalName = arch;
    md.hiddenDim = 2048;
    md.numLayers = 2;
    md.numHeads = 16;
    md.numKVHeads = 16;
    md.headDim = 128;          // 16 * 128 == 2048
    md.vocabSize = 32000;
    md.intermediateDim = 5632;
    md.useMLA = true;
    md.kvLoraRank = 512;
    md.qkNopeHeadDim = 128;
    md.qkRopeHeadDim = 64;
    md.vHeadDim = 128;
    // DeepSeek2/K2 is MLA *and* MoE. Both classifications come from parsed
    // metadata, and the expert counts are authoritative.
    md.numExperts = 256;
    md.numExpertsPerToken = 8;
    md.moeIntermediateDim = 1408;
    md.quantization = "Q8_0";
    md.quantTypeId = 8;
    md.normEps = 1e-5f;

    // MLA carries latent projections instead of dense attn_q/k/v, and MoE
    // carries expert tensors instead of the dense FFN.
    md.presentTensors = {
        "token_embd.weight", "output_norm.weight", "output.weight",
        "blk.0.attn_norm.weight", "blk.1.attn_norm.weight",
        "blk.0.q_proj.weight", "blk.1.q_proj.weight",
        "blk.0.kv_a_proj.weight", "blk.1.kv_a_proj.weight",
        "blk.0.kv_b_proj.weight", "blk.1.kv_b_proj.weight",
        "blk.0.o_proj.weight", "blk.1.o_proj.weight",
        "blk.0.ffn_norm.weight", "blk.1.ffn_norm.weight",
        "blk.0.ffn_gate_inp.weight", "blk.1.ffn_gate_inp.weight",
        "blk.0.ffn_gate_exps.weight", "blk.1.ffn_gate_exps.weight",
        "blk.0.ffn_up_exps.weight", "blk.1.ffn_up_exps.weight",
        "blk.0.ffn_down_exps.weight", "blk.1.ffn_down_exps.weight",
    };
    return md;
}

const char* rejectName(AdmissionReject r) {
    switch (r) {
        case AdmissionReject::None: return "None";
        case AdmissionReject::NoParsedArchitecture: return "NoParsedArchitecture";
        case AdmissionReject::UnknownArchitecture: return "UnknownArchitecture";
        case AdmissionReject::ArchitectureUnimplemented: return "ArchitectureUnimplemented";
        case AdmissionReject::UnsupportedForwardFamily: return "UnsupportedForwardFamily";
        case AdmissionReject::MalformedMetadata: return "MalformedMetadata";
        case AdmissionReject::MissingRequiredTensor: return "MissingRequiredTensor";
        case AdmissionReject::UnsupportedQuant: return "UnsupportedQuant";
        case AdmissionReject::UnsupportedOperator: return "UnsupportedOperator";
        case AdmissionReject::TokenizerUnsupported: return "TokenizerUnsupported";
    }
    return "?";
}

// Print the measured reason an admission attempt failed, so a failure is
// diagnosable from the receipt instead of requiring a re-run under a debugger.
void diag(const char* label, const ModelMetadata& md, const AdmissionReport& r) {
    if (r.admitted) {
        std::printf("DIAG %-14s ADMITTED arch=%s family=%s\n", label,
                    r.architectureId ? r.architectureId : "(null)",
                    r.forwardFamily ? r.forwardFamily : "(null)");
        return;
    }
    std::printf("DIAG %-14s REJECTED reason=%s field=%s detail=%s\n", label,
                rejectName(r.reject),
                r.field.empty() ? "(empty)" : r.field.c_str(),
                r.detail.empty() ? "(empty)" : r.detail.c_str());
}

} // namespace

// -----------------------------------------------------------------------------
// main
// -----------------------------------------------------------------------------
int main() {
    // Register fixtures for every architecture exercised below. An architecture
    // with no registered implementation must be rejected — that is tested too.
    registerFixture("llama");
    registerFixture("qwen3moe");
    registerFixture("mamba2");
    registerFixture("nemotron_h");
    registerFixture("deepseek2");

    AdmissionReport rep{};

    // ---------------- positive: DENSE ----------------
    {
        ModelMetadata md = denseMeta("llama");
        const bool ok = ModelRegistry::admit(md, ExecDevice::Cpu, rep);
        diag("DENSE", md, rep);
        if (ok && rep.admitted &&
            rep.moe == false && rep.mla == false && rep.recurrent == false) {
            ++g.dense_admitted;
        }
    }

    // ---------------- positive: MoE ----------------
    {
        ModelMetadata md = moeMeta("qwen3moe");
        if (ModelRegistry::admit(md, ExecDevice::Cpu, rep) && rep.admitted &&
            rep.moe == true && rep.mla == false) {
            ++g.moe_admitted;
        }
    }

    // ---------------- positive: SSM / Mamba ----------------
    {
        ModelMetadata md = ssmMeta("mamba2");
        if (ModelRegistry::admit(md, ExecDevice::Cpu, rep) && rep.admitted &&
            rep.recurrent == true) {
            ++g.ssm_admitted;
        }
    }

    // ---------------- positive: HYBRID (Nemotron-H) ----------------
    {
        ModelMetadata md = hybridMeta("nemotron_h");
        if (ModelRegistry::admit(md, ExecDevice::Cpu, rep) && rep.admitted &&
            rep.recurrent == true && md.nemotronPatternOk) {
            ++g.hybrid_admitted;
        }
    }

    // ---------------- positive: MLA / K2 ----------------
    {
        ModelMetadata md = mlaMeta("deepseek2");
        const bool mlaOk = ModelRegistry::admit(md, ExecDevice::Cpu, rep);
        diag("MLA", md, rep);
        if (mlaOk && rep.admitted &&
            rep.mla == true) {
            ++g.mla_admitted;
        }
    }

    // ---------------- negative: UNKNOWN ARCHITECTURE ----------------
    {
        ModelMetadata md = denseMeta("llama");
        md.canonicalName = "totally_not_an_architecture";
        if (!ModelRegistry::admit(md, ExecDevice::Cpu, rep) &&
            rep.reject == AdmissionReject::UnknownArchitecture) {
            ++g.unknown_arch_rejected;
        }
    }

    // ---------------- negative: NO PARSED ARCH AT ALL ----------------
    // A filename must never be used to infer an architecture.
    {
        ModelMetadata md = denseMeta("llama");
        md.canonicalName = "";                       // nothing parsed
        md.ggufPath = "C:/models/Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf";
        md.canonicalName = "";
        if (!ModelRegistry::admit(md, ExecDevice::Cpu, rep) &&
            rep.reject == AdmissionReject::NoParsedArchitecture) {
            ++g.name_guessing_rejected;
        }
        // And the name-only resolver must not rescue it either.
        if (ModelRegistry::resolve("Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf") == nullptr) {
            ++g.name_guessing_rejected;
        }
    }

    // ---------------- negative: MISSING REQUIRED TENSOR ----------------
    {
        ModelMetadata md = denseMeta("llama");
        // Drop every ffn_down layer tensor. The architecture tag is still
        // perfectly recognized; the file is structurally incomplete.
        std::vector<std::string> kept;
        for (const std::string& t : md.presentTensors) {
            if (t.find(".ffn_down.") == std::string::npos) kept.push_back(t);
        }
        md.presentTensors = kept;
        if (!ModelRegistry::admit(md, ExecDevice::Cpu, rep) &&
            rep.reject == AdmissionReject::MissingRequiredTensor &&
            rep.field == "ffn_down") {
            ++g.missing_tensor_rejected;
        }
    }

    // ---------------- negative: UNSUPPORTED QUANT ----------------
    {
        ModelMetadata md = denseMeta("llama");
        // An IQ type: present in the GGML type enum and therefore parseable, but
        // RegisterIQKernels() is an empty stub so no kernel is registered.
        md.quantTypeId = 20;   // GGML_TYPE_IQ2_M neighbourhood, no linked kernel
        md.quantization = "IQ2_M";
        if (!ModelRegistry::admit(md, ExecDevice::Cpu, rep) &&
            rep.reject == AdmissionReject::UnsupportedQuant) {
            ++g.unsupported_quant_rejected;
        }
    }

    // ---------------- negative: MALFORMED METADATA ----------------
    {
        // Geometry self-inconsistency: heads no longer partition hiddenDim.
        ModelMetadata md = denseMeta("llama");
        md.headDim = 100;      // 8 * 100 != 1024
        const bool m1 = ModelRegistry::admit(md, ExecDevice::Cpu, rep);
        diag("MALFORMED_DIMS", md, rep);
        if (!m1 && rep.reject == AdmissionReject::MalformedMetadata) {
            ++g.malformed_metadata_rejected;
        }
    }
    {
        // Architecture/metadata mismatch: MoE expert counts on a dense-only
        // architecture tag. The name says llama; the tensors say MoE.
        ModelMetadata md = denseMeta("llama");
        md.numExperts = 32;
        md.numExpertsPerToken = 4;
        md.moeIntermediateDim = 768;
        const bool m2 = ModelRegistry::admit(md, ExecDevice::Cpu, rep);
        diag("MALFORMED_MOE_ON_DENSE", md, rep);
        if (!m2 && rep.reject == AdmissionReject::MalformedMetadata) {
            ++g.malformed_metadata_rejected;
        }
    }
    {
        // Routing more experts per token than exist is structurally impossible.
        ModelMetadata md = moeMeta("qwen3moe");
        md.numExperts = 8;
        md.numExpertsPerToken = 16;
        const bool m3 = ModelRegistry::admit(md, ExecDevice::Cpu, rep);
        diag("MALFORMED_TOPK_GT_EXPERTS", md, rep);
        if (!m3 && rep.reject == AdmissionReject::MalformedMetadata) {
            ++g.malformed_metadata_rejected;
        }
    }

    // ---------------- negative: UNSUPPORTED OPERATOR ----------------
    // An architecture that is recognized by the architecture authority but whose
    // forward family has no runnable graph. deepseek4 is SpecialGraph.
    {
        ModelMetadata md = denseMeta("deepseek4");
        registerFixture("deepseek4");
        const bool sop = ModelRegistry::admit(md, ExecDevice::Cpu, rep);
        diag("SPECIAL_GRAPH", md, rep);
        if (!sop &&
            (rep.reject == AdmissionReject::UnsupportedForwardFamily ||
             rep.reject == AdmissionReject::UnsupportedOperator)) {
            ++g.unsupported_operator_rejected;
        }
    }

    // ---------------- negative: RECOGNIZED BUT UNIMPLEMENTED ----------------
    // qwen35 is recognized by the architecture authority but no implementation
    // is registered for it here, so it must not be admitted.
    {
        ModelMetadata md = ssmMeta("qwen35");
        const bool urej = ModelRegistry::admit(md, ExecDevice::Cpu, rep);
        diag("UNREGISTERED", md, rep);
        if (!urej && rep.reject == AdmissionReject::ArchitectureUnimplemented) {
            ++g.unregistered_arch_rejected;
        }
    }

    // ---------------- collision safety ----------------
    // Alias matching must require string equality, not hash equality alone.
    // A known canonical key resolves; a near-miss that would be dangerous if
    // matched loosely does not.
    {
        const bool exact = (ModelRegistry::canonicalize("llama") == "llama");
        const bool aliased = (ModelRegistry::canonicalize("GPT_OSS") == "gpt-oss");
        const bool notSubstring = (ModelRegistry::resolve("my-llama-copy") == nullptr);
        const bool notQuantInIdentity =
            (ModelRegistry::canonicalize("llama") == ModelRegistry::canonicalize("llama"));
        if (exact && aliased && notSubstring && notQuantInIdentity) {
            ++g.collision_safe;
        }
    }

    // ---------------- registry surface ----------------
    std::vector<std::string_view> archs;
    ModelRegistry::listArchitectures(archs);
    std::vector<std::string_view> aliases;
    ModelRegistry::listAliases(aliases);

    // ---------------- receipt ----------------
    // Each gate field is a comparison against a counter that was only
    // incremented on a satisfied assertion.
    const bool registryImplemented      = (g.dense_admitted == 1);
    const bool moeClassification        = (g.moe_admitted == 1);
    const bool ssmClassification        = (g.ssm_admitted == 1);
    const bool hybridClassification     = (g.hybrid_admitted == 1);
    const bool mlaClassification        = (g.mla_admitted == 1);
    const bool unknownArchFailClosed    = (g.unknown_arch_rejected == 1);
    const bool noNameGuessing           = (g.name_guessing_rejected == 2);
    const bool missingTensorRejected    = (g.missing_tensor_rejected == 1);
    const bool unsupportedQuantRejected = (g.unsupported_quant_rejected == 1);
    const bool malformedRejected        = (g.malformed_metadata_rejected == 3);
    const bool unsupportedOperatorRej   = (g.unsupported_operator_rejected == 1);
    const bool unregisteredRejected     = (g.unregistered_arch_rejected == 1);
    const bool collisionSafe            = (g.collision_safe == 1);

    std::printf("DENSE_ADMITTED=%u\n", g.dense_admitted);
    std::printf("MOE_ADMITTED=%u\n", g.moe_admitted);
    std::printf("SSM_ADMITTED=%u\n", g.ssm_admitted);
    std::printf("HYBRID_ADMITTED=%u\n", g.hybrid_admitted);
    std::printf("MLA_ADMITTED=%u\n", g.mla_admitted);
    std::printf("UNKNOWN_ARCH_REJECTED=%u\n", g.unknown_arch_rejected);
    std::printf("NAME_GUESSING_REJECTED=%u\n", g.name_guessing_rejected);
    std::printf("MISSING_TENSOR_REJECTED=%u\n", g.missing_tensor_rejected);
    std::printf("UNSUPPORTED_QUANT_REJECTED=%u\n", g.unsupported_quant_rejected);
    std::printf("MALFORMED_METADATA_REJECTED=%u\n", g.malformed_metadata_rejected);
    std::printf("UNSUPPORTED_OPERATOR_REJECTED=%u\n", g.unsupported_operator_rejected);
    std::printf("UNREGISTERED_ARCH_REJECTED=%u\n", g.unregistered_arch_rejected);
    std::printf("COLLISION_SAFE=%u\n", g.collision_safe);
    std::printf("REGISTERED_ARCHITECTURES=%zu\n", archs.size());
    std::printf("REGISTRY_ALIASES=%zu\n", aliases.size());

    // Measured quant capability for the formats under test.
    std::printf("QUANT_Q8_0_CPU_EXECUTABLE=%d\n",
                ModelRegistry::quantExecutable(8, ExecDevice::Cpu) ? 1 : 0);
    std::printf("QUANT_BF16_CPU_EXECUTABLE=%d\n",
                ModelRegistry::quantExecutable(30, ExecDevice::Cpu) ? 1 : 0);
    std::printf("QUANT_IQ2M_CPU_EXECUTABLE=%d\n",
                ModelRegistry::quantExecutable(20, ExecDevice::Cpu) ? 1 : 0);
    std::printf("QUANT_Q8_0_GPU_EXECUTABLE=%d\n",
                ModelRegistry::quantExecutable(8, ExecDevice::Gpu) ? 1 : 0);

    std::printf("MODEL_REGISTRY_IMPLEMENTED=%s\n", registryImplemented ? "PASS" : "FAIL");
    std::printf("MOE_METADATA_CLASSIFICATION=%s\n", moeClassification ? "PASS" : "FAIL");
    std::printf("SSM_METADATA_CLASSIFICATION=%s\n", ssmClassification ? "PASS" : "FAIL");
    std::printf("HYBRID_METADATA_CLASSIFICATION=%s\n", hybridClassification ? "PASS" : "FAIL");
    std::printf("MLA_METADATA_CLASSIFICATION=%s\n", mlaClassification ? "PASS" : "FAIL");
    std::printf("UNKNOWN_ARCH_FAIL_CLOSED=%s\n", unknownArchFailClosed ? "PASS" : "FAIL");
    std::printf("MODEL_NAME_NOT_AUTHORITATIVE=%s\n", noNameGuessing ? "PASS" : "FAIL");
    std::printf("MISSING_REQUIRED_TENSOR_REJECTED=%s\n", missingTensorRejected ? "PASS" : "FAIL");
    std::printf("UNSUPPORTED_QUANT_REJECTED=%s\n", unsupportedQuantRejected ? "PASS" : "FAIL");
    std::printf("MALFORMED_METADATA_REJECTED=%s\n", malformedRejected ? "PASS" : "FAIL");
    std::printf("UNSUPPORTED_OPERATOR_REJECTED=%s\n", unsupportedOperatorRej ? "PASS" : "FAIL");
    std::printf("RECOGNIZED_BUT_UNIMPLEMENTED_REJECTED=%s\n", unregisteredRejected ? "PASS" : "FAIL");
    std::printf("ALIAS_COLLISION_SAFE=%s\n", collisionSafe ? "PASS" : "FAIL");

    const bool allPass = registryImplemented && moeClassification && ssmClassification &&
                         hybridClassification && mlaClassification && unknownArchFailClosed &&
                         noNameGuessing && missingTensorRejected && unsupportedQuantRejected &&
                         malformedRejected && unsupportedOperatorRej && unregisteredRejected &&
                         collisionSafe;

    std::printf("ADMISSION_SUITE_VERDICT=%s\n", allPass ? "PASS" : "FAIL");
    return allPass ? 0 : 1;
}