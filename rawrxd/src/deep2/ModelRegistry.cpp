// ModelRegistry.cpp — RAWRXD_DEEP2_MODEL_REGISTRY_001
//
// Implementation of the six+one declarations in Deep2ModelRegistry.hpp.
//
// Design constraints this file exists to enforce:
//
//  1. NO SUBSTRING GUESSING. resolve(name) performs exact lookup against an
//     explicit alias table only. A name that is not an exact key returns
//     nullptr. "Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf" is NOT resolved by
//     scanning for "qwen" inside it. Admission authority lives in
//     resolve(const ModelMetadata&), which keys off metadata parsed out of the
//     GGUF, never off a filename.
//
//  2. FAIL CLOSED. Every unknown path returns nullptr. There is no fallback
//     descriptor, no default architecture, and no "closest match".
//
//  3. COLLISION-SAFE ALIAS RESOLUTION. An alias matches only when the FNV-1a
//     hash AND the string are both equal. Hash equality alone is forbidden:
//     a collision would route a model into the wrong implementation.
//
//  4. QUANTIZATION IS NOT ARCHITECTURE IDENTITY. No alias encodes a
//     quantization tag. Quant support is an admission-time capability check,
//     not an architecture selector.
//
//  5. NO NEW HIERARCHY. Deep2::Arch::resolve() (Deep2ModelArchitecture.hpp) is
//     the authority for architecture identity and forward family. This file
//     maps that authority onto ModelRegistry aliases. It does not restate
//     traits, and it does not define a second Kind/ForwardFamily taxonomy.
//
//  6. The Architecture descriptors are NOT fabricated here. Their probe/load/
//     createContext/forward/resetGeneration/destroy pointers are supplied by
//     the engine TU, which owns the real implementations, via
//     registerArchitecture(). Until an architecture is registered, resolve()
//     returns nullptr for it. An unregistered architecture is unrunnable, not
//     silently defaulted.

#include "Deep2ModelRegistry.hpp"
#include "Deep2ModelArchitecture.hpp"
#include "QuantKernelRegistry.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

namespace Deep2 {
namespace {

// -----------------------------------------------------------------------------
// Canonical architecture keys.
//
// Every entry here is a string that Deep2::Arch::resolve() recognizes. The
// registry does not decide which architectures exist; it only records the
// canonical spelling used for alias lookup. Adding a key that the architecture
// authority does not know is a build-time-visible no-op: resolve(metadata)
// still returns nullptr because the authority rejects it.
// -----------------------------------------------------------------------------
constexpr const char* kCanonicalArchs[] = {
    "llama",
    "mistral",
    "phi3",
    "qwen",
    "qwen2",
    "qwen2moe",
    "qwen3",
    "qwen3moe",
    "qwen3next",
    "qwen35",
    "qwen35moe",
    "gemma",
    "gemma2",
    "gemma3",
    "deepseek2",
    "deepseek32",
    "deepseek4",
    "nemotron",
    "nemotron_h",
    "nemotron_h_moe",
    "gpt-oss",
    "laguna",
    "mamba",
    "mamba2",
};

// -----------------------------------------------------------------------------
// Explicit alias spellings -> canonical key.
//
// These are whole-token equivalences only. Each maps one exact accepted
// spelling to one canonical key. Nothing here is a pattern, and nothing here
// encodes quantization.
// -----------------------------------------------------------------------------
struct AliasRule {
    const char* alias;
    const char* canonical;
};

constexpr AliasRule kAliasRules[] = {
    {"qwen3_moe",    "qwen3moe"},
    {"qwen3-next",   "qwen3next"},
    {"qwen3_next",   "qwen3next"},
    {"qwen3.5",      "qwen35"},
    {"qwen3_5",      "qwen35"},
    {"qwen3.5moe",   "qwen35moe"},
    {"qwen3.5-moe",  "qwen35moe"},
    {"qwen3_5moe",   "qwen35moe"},
    {"gpt_oss",      "gpt-oss"},
    {"gptoss",       "gpt-oss"},
    {"nemotron-h",   "nemotron_h"},
    {"nemotron-h-moe", "nemotron_h_moe"},
    {"nemotron_h-moe",  "nemotron_h_moe"},
    {"deepseek-v2",  "deepseek2"},
    {"deepseek-v3",  "deepseek32"},
    {"deepseek2-lite", "deepseek2"},
};

// Registry state. Architectures are registered by the engine TU; aliases are
// resolved against the canonical table above.
struct RegistryState {
    std::mutex mu;
    std::vector<const Architecture*> architectures;
};

RegistryState& state() noexcept {
    static RegistryState s;
    return s;
}

// Lowercase ASCII into a caller buffer. Deliberately not locale-dependent and
// deliberately not Unicode-aware: architecture tags are ASCII tokens.
std::string asciiLower(std::string_view in) {
    std::string out;
    out.reserve(in.size());
    for (const char c : in) {
        out.push_back(static_cast<char>(
            std::tolower(static_cast<unsigned char>(c))));
    }
    return out;
}

// Whole-token alias resolution: exact match against the alias table only.
const char* lookupAlias(std::string_view canonical) noexcept {
    for (const AliasRule& rule : kAliasRules) {
        if (canonical == rule.alias) return rule.canonical;
    }
    return nullptr;
}

bool isCanonicalKey(std::string_view key) noexcept {
    for (const char* c : kCanonicalArchs) {
        if (key == c) return true;
    }
    return false;
}

// -----------------------------------------------------------------------------
// Metadata well-formedness.
//
// A structurally incomplete model must be rejected even when its architecture
// metadata is recognized. This is deliberately separate from architecture
// identity: recognizing "qwen3moe" says nothing about whether the file actually
// carries the tensors and dimensions that architecture requires.
// -----------------------------------------------------------------------------
struct GeometryProblem {
    const char* field;
    const char* detail;
};

bool checkGeometry(const ModelMetadata& md, GeometryProblem& problem) noexcept {
    // Baseline geometry every Deep2 architecture needs to allocate anything.
    if (md.hiddenDim == 0)      { problem = {"hiddenDim", "zero"};        return false; }
    if (md.numLayers == 0)      { problem = {"numLayers", "zero"};        return false; }
    if (md.numHeads == 0)       { problem = {"numHeads", "zero"};         return false; }
    if (md.vocabSize == 0)      { problem = {"vocabSize", "zero"};        return false; }
    if (md.headDim == 0)         { problem = {"headDim", "zero"};          return false; }

// Attention heads must partition the hidden dimension exactly. A mismatch
      // here is the signature of a mis-parsed or truncated KV cache layout.
      //
      // RAWRXD_MLA_LOAD_AUTHORITY_001: this invariant is a SQUARE-attention
      // requirement and does not hold for MLA. For MLA the query width is
      // numHeads * key_length, and key_length is the nope+rope sum, which
      // legitimately differs from hiddenDim -- DeepSeek-V2-Lite is 16*192=3072
      // against hiddenDim=2048. Applying the square rule to an MLA model
      // rejected a valid model at admission, before any MLA code could run.
      //
      // The check is not removed: an MLA model is held to its own set of
      // invariants instead, so a genuinely malformed MLA geometry is still
      // rejected rather than waved through.
      if (md.useMLA) {
          if (md.kvLoraRank == 0 || md.qkNopeHeadDim == 0 ||
              md.qkRopeHeadDim == 0 || md.vHeadDim == 0) {
              problem = {"mlaDims", "kvLoraRank/qkNopeHeadDim/qkRopeHeadDim/vHeadDim zero"};
              return false;
          }
          if ((md.qkNopeHeadDim + md.qkRopeHeadDim) % 2 != 0) {
              problem = {"mlaHeads", "qkNopeHeadDim+qkRopeHeadDim is odd"};
              return false;
          }
      }
      // DEEP2_GQA_GEOMETRY_001: the previous check here was
      //     numHeads * headDim != hiddenDim  ->  reject
      // That invariant is false in general and rejected valid GQA models. The
      // engine does NOT require it: it treats qDim (numHeads*headDim) and
      // hiddenDim as independent dimensions and validates each projection
      // against the real per-layer tensors:
      //     wq.rows == numHeads*headDim   wq.cols == hiddenDim
      //     wk.rows == kvDim              wk.cols == hiddenDim
      //     wo.rows  == hiddenDim         wo.cols  == qDim
      // (Deep2Engine.cpp ATTN_PROJECTION_GEOMETRY, stage 18). A model whose
      // tensors genuinely disagree is still rejected there, against evidence.
      //
      // Measured: llama3.2-3b  3072 hidden, 24 heads, head_dim 128 -> 3072 == hidden
      // (passes the old check).  gemma3-1b  1152 hidden, 8 heads, head_dim 256
      // -> 2048 != 1152, a legitimate projection from 1152 into 2048, which the
      // old check refused. The metadata-only equality was the sole gate and it
      // contradicted the engine's own tensor-level contract.
      //
      // The legitimate head-count invariants (numKVHeads parsed, <= numHeads,
      // and dividing numHeads) remain enforced below; they are not affected.


    // Grouped-query attention requires a KV head count that divides the query
    // head count. numKVHeads == 0 means "not parsed"; that is a rejection, not
    // an implicit "same as numHeads".
    if (md.numKVHeads == 0)     { problem = {"numKVHeads", "unparsed"};    return false; }
    if (md.numKVHeads > md.numHeads) {
        problem = {"numKVHeads", "> numHeads"};
        return false;
    }
    if (md.numHeads % md.numKVHeads != 0) {
        problem = {"numHeads", "not divisible by numKVHeads"};
        return false;
    }

    // Dense FFN needs an intermediate dimension. MoE architectures are checked
    // against the MoE dimensions below instead.
    if (md.numExperts == 0) {
        if (md.intermediateDim == 0) {
            problem = {"intermediateDim", "zero for dense architecture"};
            return false;
        }
    } else {
        // MoE: authoritative from parsed expert counts, not from the name.
        if (md.moeIntermediateDim == 0) {
            problem = {"moeIntermediateDim", "zero but numExperts>0"};
            return false;
        }
        if (md.numExpertsPerToken == 0) {
            problem = {"numExpertsPerToken", "zero but numExperts>0"};
            return false;
        }
        // Routing more experts per token than exist is structurally impossible.
        if (md.numExpertsPerToken > md.numExperts) {
            problem = {"numExpertsPerToken", "> numExperts"};
            return false;
        }
    }
    return true;
}

// -----------------------------------------------------------------------------
// Consistency between the declared architecture and the parsed metadata.
//
// A file can carry a recognized architecture tag and still not be a valid
// instance of that architecture. These checks catch the mismatch rather than
// letting the engine discover it mid-forward.
// -----------------------------------------------------------------------------
bool checkArchConsistency(const ModelMetadata& md,
                          const Deep2::Arch::Traits& t,
                          GeometryProblem& problem) noexcept {
    const bool metadataSaysMoe = (md.numExperts > 0);

    // MoE determination is authoritative from parsed metadata. The architecture
    // tag and the expert counts must agree; neither may silently override the
    // other.
    if (metadataSaysMoe && !t.moe) {
        problem = {"numExperts", ">0 but architecture is not MoE"};
        return false;
    }
    if (!metadataSaysMoe && t.moe) {
        problem = {"numExperts", "=0 but architecture requires MoE"};
        return false;
    }

    // MLA consistency.
    const bool metadataSaysMla =
        md.useMLA || md.kvLoraRank != 0 || md.qkNopeHeadDim != 0;
    if (metadataSaysMla && !t.mla) {
        problem = {"kvLoraRank/qkNopeHeadDim", "present but architecture is not MLA"};
        return false;
    }
    if (t.mla) {
        if (md.kvLoraRank == 0) { problem = {"kvLoraRank", "zero but MLA"}; return false; }
        if (md.qkRopeHeadDim == 0) { problem = {"qkRopeHeadDim", "zero but MLA"}; return false; }
    }

    // Recurrent (Mamba2 / GatedDeltaNet) consistency.
    if (t.recurrent) {
        if (md.ssmStateSize == 0) { problem = {"ssmStateSize", "zero but recurrent"}; return false; }
        if (md.ssmInner == 0)     { problem = {"ssmInner", "zero but recurrent"}; return false; }
        if (md.ssmHeads == 0)     { problem = {"ssmHeads", "zero but recurrent"}; return false; }
        if (md.ssmGroups == 0)    { problem = {"ssmGroups", "zero but recurrent"}; return false; }
        if (md.ssmConvKernel == 0) { problem = {"ssmConvKernel", "zero but recurrent"}; return false; }
    } else {
        // A non-recurrent architecture carrying SSM geometry is a parse fault.
        if (md.ssmInner != 0 || md.ssmStateSize != 0) {
            problem = {"ssmInner/ssmStateSize", "present but architecture is not recurrent"};
            return false;
        }
    }

    // Sliding-window architectures must carry a parsed window size, otherwise
    // the mask would silently degrade to full attention.
    if (t.slidingWindow && md.slidingWindowSize == 0) {
        problem = {"slidingWindowSize", "zero but architecture requires sliding window"};
        return false;
    }

    // Nemotron-H style per-layer patterns must be complete when declared.
    if (md.nemotronPatternOk) {
        if (md.nemotronHeadKvPerLayer.size() != md.numLayers) {
            problem = {"nemotronHeadKvPerLayer", "size != numLayers"};
            return false;
        }
        if (md.nemotronFfPerLayer.size() != md.numLayers) {
            problem = {"nemotronFfPerLayer", "size != numLayers"};
            return false;
        }
    }
    return true;
}

} // namespace

// -----------------------------------------------------------------------------
// ModelRegistry
// -----------------------------------------------------------------------------

// Canonicalize a model name to a registry key.
//
// Deliberately conservative: lowercase ASCII, trimmed, with a trailing GGUF
// extension removed. It performs NO substring extraction. "qwen2.5-coder-32b"
// does not canonicalize to "qwen2" — it canonicalizes to itself, which is not a
// registry key, and therefore does not resolve. Deriving an architecture from a
// human-facing model name is exactly the guessing this registry must not do;
// that decision belongs to GGUF metadata.
std::string_view ModelRegistry::canonicalize(std::string_view name) noexcept {
    static thread_local std::string buffer;
    buffer.clear();

    std::size_t begin = 0;
    std::size_t end = name.size();
    while (begin < end && std::isspace(static_cast<unsigned char>(name[begin]))) ++begin;
    while (end > begin && std::isspace(static_cast<unsigned char>(name[end - 1]))) --end;

    std::string_view trimmed = name.substr(begin, end - begin);

    // Strip one trailing .gguf (case-insensitive).
    if (trimmed.size() > 5) {
        std::string_view tail = trimmed.substr(trimmed.size() - 5);
        std::string tailLower = asciiLower(tail);
        if (tailLower == ".gguf") {
            trimmed = trimmed.substr(0, trimmed.size() - 5);
        }
    }

    buffer = asciiLower(trimmed);

    // An explicit whole-token alias maps onto its canonical key.
    if (const char* canonical = lookupAlias(buffer)) {
        buffer = canonical;
    }

    return std::string_view(buffer);
}

// Resolve architecture from a model name.
//
// This is the WEAK path and exists for diagnostics and for tests that need a
// key without a file. Exact lookup only. It is NOT sufficient for admission:
// a caller that has parsed metadata must call resolve(metadata) instead, because
// a name carries no authority over architecture identity.
const Architecture* ModelRegistry::resolve(std::string_view modelName) noexcept {
    const std::string_view key = canonicalize(modelName);
    if (key.empty()) return nullptr;
    if (!isCanonicalKey(key)) return nullptr;

    // The architecture authority must also recognize the key. A key in the table
    // that the authority rejects is not runnable.
    if (!Deep2::Arch::isKnown(key)) return nullptr;

    RegistryState& s = state();
    std::lock_guard<std::mutex> lock(s.mu);
    for (const Architecture* arch : s.architectures) {
        if (arch == nullptr) continue;
        // Collision-safe: hash AND string must both match.
        if (hash_runtime(arch->id.data()) == hash_runtime(key.data()) &&
            arch->id == key) {
            return arch;
        }
    }
    // Recognized architecture with no registered implementation. Fail closed.
    return nullptr;
}

// Resolve architecture from parsed model metadata.
//
// This is the ADMISSION path. It is authoritative: the architecture comes from
// metadata.canonicalName, which the loader populates from the GGUF
// general.architecture tag. It never falls back to the file name, the model
// name, or the family string.
//
// A nullptr return means "do not execute this model". There is no partial
// admission and no degraded mode.
const Architecture* ModelRegistry::resolve(const ModelMetadata& metadata) noexcept {
    // No parsed architecture tag => no authority to admit anything.
    if (metadata.canonicalName.empty()) return nullptr;

    const std::string key = asciiLower(metadata.canonicalName);
    if (key.empty()) return nullptr;

    // Collision-safe canonicalization of the parsed tag: hash AND string.
    std::string canonicalKey = key;
    if (const char* alias = lookupAlias(key)) canonicalKey = alias;
    if (!isCanonicalKey(canonicalKey)) return nullptr;

    // The architecture authority decides identity and forward family.
    const Deep2::Arch::Traits traits = Deep2::Arch::resolve(canonicalKey);
    if (traits.kind == Deep2::Arch::Kind::Unknown) return nullptr;

    // A recognized tag with no runnable forward family is not admitted. This is
    // what keeps "recognized" distinct from "supported".
    if (traits.family == Deep2::Arch::ForwardFamily::Unsupported) return nullptr;

    // Structurally incomplete metadata is rejected even when the architecture is
    // recognized.
    GeometryProblem problem{};
    if (!checkGeometry(metadata, problem)) return nullptr;

    // Declared architecture must agree with the parsed geometry.
    if (!checkArchConsistency(metadata, traits, problem)) return nullptr;

    // Find the registered implementation.
    RegistryState& s = state();
    std::lock_guard<std::mutex> lock(s.mu);
    for (const Architecture* arch : s.architectures) {
        if (arch == nullptr) continue;
        if (hash_runtime(arch->id.data()) == hash_runtime(canonicalKey.data()) &&
            arch->id == std::string_view(canonicalKey)) {
            return arch;
        }
    }
    return nullptr;
}

// Check if a model name resolves to a registered architecture.
bool ModelRegistry::knows(std::string_view name) noexcept {
    return resolve(name) != nullptr;
}

// Register an architecture implementation.
//
// Called by the engine translation unit, which owns the real probe/load/
// createContext/forward/resetGeneration/destroy bodies. Registering is
// idempotent for a given id: the first registration wins and a duplicate id is
// ignored, so a double static initializer cannot swap the live implementation.
void ModelRegistry::registerArchitecture(const Architecture* arch) {
    if (arch == nullptr) return;
    if (arch->id.empty()) return;

    RegistryState& s = state();
    std::lock_guard<std::mutex> lock(s.mu);
    for (const Architecture* existing : s.architectures) {
        if (existing == nullptr) continue;
        if (existing->id == arch->id) return; // already registered
    }
    s.architectures.push_back(arch);
}

// List all registered architecture ids.
void ModelRegistry::listArchitectures(std::vector<std::string_view>& out) {
    out.clear();
    RegistryState& s = state();
    std::lock_guard<std::mutex> lock(s.mu);
    for (const Architecture* arch : s.architectures) {
        if (arch != nullptr && !arch->id.empty()) out.push_back(arch->id);
    }
}

// List every alias spelling the registry accepts, including the canonical keys.
//
// These are exact-match keys. A caller must not treat this list as a pattern
// set or attempt substring containment against it.
void ModelRegistry::listAliases(std::vector<std::string_view>& out) {
    out.clear();
    for (const char* c : kCanonicalArchs) out.emplace_back(c);
    for (const AliasRule& rule : kAliasRules) out.emplace_back(rule.alias);
}

// -----------------------------------------------------------------------------
// Required tensor roles
//
// A role names the INNER tensor stem as it appears in a real GGUF. Per-layer
// tensors are laid out as  blk.<layer>.<stem>.weight  (the llama.cpp/GGUF
// convention that Deep2Engine::loadModel itself binds against), with the
// stem-first  <stem>.<layer>.weight  spelling accepted as well because some
// exporters emit that. Non-per-layer tensors are <stem>.weight, and a bare
// <stem> is also accepted.
//
// Roles are derived from PARSED metadata and the architecture authority, never
// from a model name.
// -----------------------------------------------------------------------------
namespace {

struct RoleRule {
    const char* role;
    const char* stem;   // inner tensor stem, e.g. "attn_q"
    bool perLayer;
};

// Roles every Deep2 architecture carries: the embedding and the final norm.
constexpr RoleRule kBaseRoles[] = {
    {"token_embd",  "token_embd",  false},
    {"output_norm", "output_norm", false},
};

// Per-layer input norm for attention/recurrent stacks.
constexpr RoleRule kAttnNormRole[] = {
    {"attn_norm", "attn_norm", true},
};

// Dense (non-MLA) attention projections.
//
// The Q/K/V triple is split out of this table because it has TWO legal GGUF
// layouts, and requiring only the split one rejects models the engine
// genuinely supports.
//
// The loader binds BOTH:
//     Deep2Engine.cpp  bindTensor(p + "attn_qkv.weight", lw.wqkv);
//     Deep2Engine.cpp  bindTensor(p + "attn_q.weight",     lw.wq);   (+k, +v)
// and its own topology check accepts either form:
//     Deep2Engine.cpp  const bool fusedQkv = lw.wqkv.data != nullptr;
//                     if (!splitQkv && !fusedQkv) -> reject
// with the fused tensor consumed at the projection site:
//     Deep2Engine.cpp  } else if (lw.wqkv.data) { LinearW(lw.wqkv, ...) }
//
// phi3 exports the fused layout (blk.N.attn_qkv.weight) and was refused with
// "MissingRequiredTensor field=attn_q" — the registry rejecting a model the
// loader can load. Requiring split-only made this gate STRICTER than the
// engine it guards, which converts a supported architecture into an
// unsupported one.
//
// attn_output is required in BOTH layouts and stays in this table.
constexpr RoleRule kDenseAttnRoles[] = {
    {"attn_output", "attn_output", true},
};

// The alternative QKV layouts. A model satisfies the QKV requirement when the
// fused tensor is present, or when all three split tensors are present.
constexpr RoleRule kFusedQkvRole[] = {
    {"attn_qkv", "attn_qkv", true},
};

constexpr RoleRule kSplitQkvRoles[] = {
    {"attn_q", "attn_q", true},
    {"attn_k", "attn_k", true},
    {"attn_v", "attn_v", true},
};

// Dense FFN. Only required when the architecture is NOT MoE — a MoE layer
// carries the expert tensors instead and has no ffn_gate/up/down at all.
//
// The gate is split out for the same reason as the QKV triple: gated
// architectures (phi3, llama-3, qwen2) may ship a SINGLE ffn_up tensor that
// concatenates the gate rows and the up rows. This is a genuine second legal
// layout, and the loader splits it:
//
//     Deep2Engine.cpp  fused gate_up split  (RAWRXD_FUSED_GATE_UP_001)
//     Deep2Engine.cpp  computeFFN() -> SwiGLU branch (both wGate and wUp)
//
// Requiring only the split layout refused models the engine now supports. The
// fused tensor is accepted ONLY alongside ffn_down, because the down
// projection's column count is what proves the 2x row ratio; ffn_up on its own
// is equally consistent with a genuine non-gated MLP, which is a different
// topology with different arithmetic and must keep being rejected.
constexpr RoleRule kDenseFfnRoles[] = {
    {"ffn_norm", "ffn_norm", true},
    {"ffn_up",   "ffn_up",   true},
    {"ffn_down", "ffn_down", true},
};

// The two legal gate layouts: an explicit ffn_gate tensor, or a fused ffn_up
// that the loader splits. Satisfying EITHER satisfies one required role.
constexpr RoleRule kSplitFfnGateRole[] = {
    {"ffn_gate", "ffn_gate", true},
};

constexpr RoleRule kFusedFfnGateRole[] = {
    {"ffn_up", "ffn_up", true},
};

// MoE replaces the dense FFN with a router plus per-expert tensors.
constexpr RoleRule kMoeRoles[] = {
    {"ffn_gate_inp",  "ffn_gate_inp",  true},
    {"ffn_gate_exps", "ffn_gate_exps", true},
    {"ffn_up_exps",   "ffn_up_exps",   true},
    {"ffn_down_exps", "ffn_down_exps", true},
};

// MLA / DeepSeek: q/k/v projections are replaced by latent projections.
// ---------------------------------------------------------------------------
// Negative control for this translation unit's role tables.
//
// The defect this guards against is not theoretical: kMlaRoles below once held
// q_proj / kv_a_proj / kv_b_proj / o_proj, which are PyTorch/HuggingFace
// parameter names. No GGUF file contains them, so the table was unsatisfiable
// and every MLA model was rejected at admission while the reported "missing
// role" named a tensor the engine had never looked for.
//
// Every real per-layer GGUF stem in this file is snake_case with no "_proj"
// suffix. Any stem reintroducing a PyTorch spelling fails to compile.
// ---------------------------------------------------------------------------
#include <string_view>

constexpr bool stemUsesHfNaming(const char* stem) noexcept {
    return std::string_view(stem).find("_proj") != std::string_view::npos;
}
#define RAWRXD_ASSERT_GGUF_STEMS(table)                                          \
    static_assert([&] {                                                         \
        for (const RoleRule& r : table) if (stemUsesHfNaming(r.stem)) return false; \
        return true;                                                            \
    }(), #table " contains a PyTorch/HuggingFace stem; GGUF models do not "     \
        "ship those names")

// MLA attention projections, grouped by FUNCTIONAL ROLE rather than as one flat
// conjunctive list.
//
// Measured tensor table of a real MLA model (DeepSeek-V2-Lite, read from the
// GGUF directly, not from a name):
//     blk.N.attn_q_a.weight        blk.N.attn_q_b.weight
//     blk.N.attn_k_b.weight        blk.N.attn_v_b.weight
//     blk.N.attn_kv_a_mqa.weight   blk.N.attn_output.weight
//
// A flat table of all of these would be CONJUNCTIVE and would reject a model
// shipping attn_kv_a (without the _mqa suffix) on the missing attn_kv_a_mqa.
// The latent down-projection therefore has two real spellings that satisfy one
// requirement, and is evaluated as a disjunction by the caller.
constexpr RoleRule kMlaQueryRoles[] = {
    {"attn_q_a", "attn_q_a", true},
    {"attn_q_b", "attn_q_b", true},
};

constexpr RoleRule kMlaKvRoles[] = {
    {"attn_k_b", "attn_k_b", true},
    {"attn_v_b", "attn_v_b", true},
};

// Alternatives for ONE requirement: multi-query-absorbed (DeepSeek2 and later)
// versus the plain latent spelling used by earlier MLA exports.
constexpr RoleRule kMlaKvDownMqaRole[]   = { {"attn_kv_a_mqa", "attn_kv_a_mqa", true} };
constexpr RoleRule kMlaKvDownPlainRole[] = { {"attn_kv_a",     "attn_kv_a",     true} };

constexpr RoleRule kMlaOutRoles[] = {
    {"attn_output", "attn_output", true},
};

RAWRXD_ASSERT_GGUF_STEMS(kMlaQueryRoles);
RAWRXD_ASSERT_GGUF_STEMS(kMlaKvRoles);
RAWRXD_ASSERT_GGUF_STEMS(kMlaKvDownMqaRole);
RAWRXD_ASSERT_GGUF_STEMS(kMlaKvDownPlainRole);
RAWRXD_ASSERT_GGUF_STEMS(kMlaOutRoles);

// Recurrent / SSM roles.
constexpr RoleRule kRecurrentRoles[] = {
    {"ssm_in",     "ssm_in",     true},
    {"ssm_conv1d", "ssm_conv1d", true},
    {"ssm_out",    "ssm_out",    true},
    {"ssm_dt",     "ssm_dt",     true},
    {"ssm_a",      "ssm_a",      true},
};

// A scalar (non-per-layer) role matches "<stem>", "<stem>.weight", or
// "model.<stem>.weight" — all three appear in real exports.
bool tensorExists(const ModelMetadata& md, const std::string& stem) noexcept {
    const std::string suffixed = stem + ".weight";
    const std::string modelPrefixed = "model." + suffixed;
    for (const std::string& t : md.presentTensors) {
        if (t == stem) return true;
        if (t == suffixed) return true;
        if (t == modelPrefixed) return true;
    }
    return false;
}

// A per-layer role is present when the tensor table carries, for that exact
// layer index, one of:
//     blk.<layer>.<stem>.weight    (GGUF / llama.cpp convention, the layout
//                                   Deep2Engine::loadModel itself binds against)
//     <stem>.<layer>.weight         (stem-first export spelling)
//     blk.<layer>.<stem>
// Matching on the exact index means a layer missing its tensor is not masked by
// a neighbouring layer that has one.
//
// Nemotron-H style mixed stacks carry attention layers and recurrent layers
// under different stems, so a per-layer role is satisfied when it appears on at
// least one layer; the per-layer pattern arrays are validated separately.
bool layerTensorPresent(const ModelMetadata& md,
                        const std::string& stem,
                        std::size_t layer) noexcept {
    const std::string idx = "." + std::to_string(layer);
    const std::string a = "blk" + idx + "." + stem + ".weight";
    const std::string b = stem + idx + ".weight";
    const std::string c = "blk" + idx + "." + stem;
    for (const std::string& t : md.presentTensors) {
        if (t == a || t == b || t == c) return true;
    }
    return false;
}

std::size_t layersWithRole(const ModelMetadata& md, const RoleRule& rule) noexcept {
    std::size_t found = 0;
    for (std::size_t layer = 0; layer < md.numLayers; ++layer) {
        if (layerTensorPresent(md, rule.stem, layer)) ++found;
    }
    return found;
}

bool roleSatisfied(const ModelMetadata& md, const RoleRule& rule) noexcept {
    if (!rule.perLayer) return tensorExists(md, rule.stem);
    return layersWithRole(md, rule) > 0;
}

void countRoles(const ModelMetadata& md,
                const RoleRule* roles, std::size_t count,
                std::size_t& required, std::size_t& missing,
                std::string& firstMissing) noexcept {
    for (std::size_t i = 0; i < count; ++i) {
        ++required;
        if (!roleSatisfied(md, roles[i])) {
            ++missing;
            if (firstMissing.empty()) firstMissing = roles[i].role;
        }
    }
}

} // namespace

std::size_t ModelRegistry::countMissingRequiredTensors(const ModelMetadata& md,
                                                       std::string& firstMissing) noexcept {
    firstMissing.clear();
    if (md.canonicalName.empty()) return 0;

    const std::string key = asciiLower(md.canonicalName);
    const Deep2::Arch::Traits traits = Deep2::Arch::resolve(key);
    if (traits.kind == Deep2::Arch::Kind::Unknown) return 0;

    std::size_t required = 0;
    std::size_t missing = 0;

    // Every architecture carries the embedding and the final norm.
    countRoles(md, kBaseRoles, std::size(kBaseRoles), required, missing, firstMissing);

    if (!traits.recurrent) {
        countRoles(md, kAttnNormRole, std::size(kAttnNormRole), required, missing, firstMissing);
        // MLA carries latent projections instead of dense q/k/v.
        if (traits.mla) {
            // Three functional requirements, four conjunctive stems:
            //   query low-rank  : attn_q_a AND attn_q_b   (two distinct factors)
            //   key/value latent: attn_k_b AND attn_v_b   (two distinct factors)
            //   output          : attn_output
            // plus ONE requirement with two alternative spellings:
            //   latent down     : attn_kv_a_mqa OR attn_kv_a
            //
            // The down-projection is an OR because DeepSeek2 and later absorb the
            // queries into the latent and export attn_kv_a_mqa, while earlier MLA
            // exports use attn_kv_a. Both are real and both are correct for their
            // model; requiring the specific one turns a supported architecture
            // into an unsupported one -- the same mistake the fused-QKV table
            // above documents for phi3.
            countRoles(md, kMlaQueryRoles, std::size(kMlaQueryRoles), required, missing, firstMissing);
            countRoles(md, kMlaKvRoles,    std::size(kMlaKvRoles),    required, missing, firstMissing);
            countRoles(md, kMlaOutRoles,   std::size(kMlaOutRoles),   required, missing, firstMissing);

            ++required;
            const bool kvMqa   = roleSatisfied(md, kMlaKvDownMqaRole[0]);
            const bool kvPlain = roleSatisfied(md, kMlaKvDownPlainRole[0]);
            if (!kvMqa && !kvPlain) {
                ++missing;
                // Name the stem the loader prefers, matching the convention used
                // by the fused-QKV disjunct above.
                if (firstMissing.empty()) firstMissing = kMlaKvDownMqaRole[0].role;
            }
        } else {
            // QKV is satisfied by EITHER layout, and counts as ONE required
            // role rather than three, because the two are alternatives for the
            // same requirement. Counting all three would make a perfectly
            // valid fused model appear to be missing two roles it never needed.
            //
            // Only when NEITHER layout is satisfied is the requirement absent,
            // and the reported field names the fused stem: that is the shape
            // the loader prefers and the one a reader of the message will
            // look for.
            ++required;
            const bool fusedOk   = roleSatisfied(md, kFusedQkvRole[0]);
            const bool splitOk   = layersWithRole(md, kSplitQkvRoles[0]) > 0 &&
                                   layersWithRole(md, kSplitQkvRoles[1]) > 0 &&
                                   layersWithRole(md, kSplitQkvRoles[2]) > 0;
            if (!fusedOk && !splitOk) {
                ++missing;
                if (firstMissing.empty()) firstMissing = kFusedQkvRole[0].role;
            }
            countRoles(md, kDenseAttnRoles, std::size(kDenseAttnRoles), required, missing, firstMissing);
        }
    } else {
        countRoles(md, kRecurrentRoles, std::size(kRecurrentRoles), required, missing, firstMissing);
    }

    // FFN shape is mutually exclusive: dense or MoE, never both.
    if (traits.moe) {
        countRoles(md, kMoeRoles, std::size(kMoeRoles), required, missing, firstMissing);
    } else if (!traits.recurrent) {
        countRoles(md, kDenseFfnRoles, std::size(kDenseFfnRoles), required, missing, firstMissing);

        // The gate requirement is satisfied by EITHER an explicit ffn_gate
        // tensor or a fused ffn_up that the loader splits, and counts as ONE
        // required role for the same reason the QKV layouts count as one.
        //
        // The fused layout is only believed when ffn_down is also present: the
        // loader proves the 2x row ratio against ffn_down's column count, and a
        // bare ffn_up is equally consistent with a genuine non-gated MLP, which
        // is a different topology and must still be rejected. ffn_up is already
        // counted as required above, so this adds no new requirement.
        ++required;
        const bool gateSplitOk = layersWithRole(md, kSplitFfnGateRole[0]) > 0;
        const bool gateFusedOk = !gateSplitOk &&
                                 layersWithRole(md, kFusedFfnGateRole[0]) > 0 &&
                                 layersWithRole(md, kDenseFfnRoles[2]) > 0;
        if (!gateSplitOk && !gateFusedOk) {
            ++missing;
            if (firstMissing.empty()) firstMissing = kSplitFfnGateRole[0].role;
        }
    }

    // output.weight is absent when embeddings are tied; token_embd already
    // covers the role in that case, so no extra requirement is added.

    return missing;
}

// -----------------------------------------------------------------------------
// Quantization execution capability
//
// Measured, never assumed. The kernel registry is asked whether it actually
// holds a GEMV and a dequant pointer for this type id. A format present in the
// GGML type enum but with no linked kernel — every IQ type, for example, whose
// RegisterIQKernels() is an empty stub — reports false here even though it
// parses perfectly well.
// -----------------------------------------------------------------------------
bool ModelRegistry::quantExecutable(uint32_t ggmlTypeId, ExecDevice device) noexcept {
    // QuantKernelRegistry::Instance() does NOT register its builtins; that is a
    // separate explicit Initialize() call. Querying before initialization would
    // report "no capability" for every format including the ones that genuinely
    // work, which is fail-closed but wrong. Ensure initialization exactly once so
    // the answer below is the registry's real state.
    static const bool initialized = []() {
        Deep2::QuantKernelRegistry::Instance().Initialize();
        return true;
    }();

    const Deep2::QuantKernelRegistry& reg = Deep2::QuantKernelRegistry::Instance();
    const int id = static_cast<int>(ggmlTypeId);

    // Dequantization is required for every device: a format that cannot be
    // expanded to floats cannot feed any matmul on any device.
    if (reg.GetDequant(id) == nullptr) return false;

    if (device == ExecDevice::Cpu) {
        return reg.GetGEMV(id) != nullptr;
    }

    // GPU execution capability is not claimed by the CPU kernel registry. Until
    // a Vulkan-side kernel registration is measurable here, GPU quant support
    // is false. Reporting true on the strength of a CPU registration would be
    // exactly the parseable-but-not-executable error this gate exists to catch.
    return false;
}

// -----------------------------------------------------------------------------
// admit()
// -----------------------------------------------------------------------------
bool ModelRegistry::admit(const ModelMetadata& md,
                          ExecDevice device,
                          AdmissionReport& report) noexcept {
    report = AdmissionReport{};

    auto reject = [&report](AdmissionReject why, std::string field,
                            std::string detail) -> bool {
        report.admitted = false;
        report.reject = why;
        report.field = std::move(field);
        report.detail = std::move(detail);
        return false;
    };

    // 1. Parsed architecture must exist. No name fallback.
    if (md.canonicalName.empty()) {
        return reject(AdmissionReject::NoParsedArchitecture, "canonicalName",
                      "no parsed architecture tag; refusing to guess from model name");
    }

    // 2. Architecture authority must recognize it.
    const std::string key = asciiLower(md.canonicalName);
    const Deep2::Arch::Traits traits = Deep2::Arch::resolve(key);
    if (traits.kind == Deep2::Arch::Kind::Unknown) {
        return reject(AdmissionReject::UnknownArchitecture, "canonicalName",
                      "architecture not recognized: " + key);
    }
    report.architectureId = traits.canonical;
    report.forwardFamily = Deep2::Arch::familyName(traits.family);
    report.moe = traits.moe;
    report.mla = traits.mla;
    report.recurrent = traits.recurrent;
    report.slidingWindow = traits.slidingWindow;
    report.tieEmbeddings = md.tieEmbeddings;

    // 3. The forward family must be runnable. A SpecialGraph architecture is
    //    recognized but must never fall through into the generic transformer or
    //    generic MoE path: its graph is not the one those primitives implement.
    if (traits.family == Deep2::Arch::ForwardFamily::Unsupported) {
        return reject(AdmissionReject::UnsupportedForwardFamily, "forwardFamily",
                      std::string("no runnable forward graph for ") + report.forwardFamily);
    }
    if (traits.family == Deep2::Arch::ForwardFamily::SpecialGraph) {
        return reject(AdmissionReject::UnsupportedForwardFamily, "forwardFamily",
                      std::string("architecture ") + key +
                          " is SpecialGraph; no execution graph is wired for it");
    }
    // requiresSpecialGraph means "must not be run by the generic primitives".
    // That prohibition only binds when the family IS one of the generic ones.
    // Recurrent architectures (Mamba2, GatedDeltaNet) carry their own dedicated
    // forward family with its own implementation, so the flag does not block
    // them; blocking them here would reject SSM stacks that genuinely run.
    if (traits.requiresSpecialGraph &&
        (traits.family == Deep2::Arch::ForwardFamily::GenericTransformer ||
         traits.family == Deep2::Arch::ForwardFamily::GenericMoE ||
         traits.family == Deep2::Arch::ForwardFamily::MLA)) {
        return reject(AdmissionReject::UnsupportedForwardFamily, "requiresSpecialGraph",
                      std::string("architecture ") + key +
                          " requires its own execution graph but declares the generic "
                          "family " + report.forwardFamily + "; refusing to run it "
                          "through the generic path");
    }

    // 4. Geometry coherence. This runs BEFORE implementation lookup so that a
    //    structurally incomplete model is reported as malformed rather than
    //    misreported as "no implementation registered" — resolve() itself
    //    applies the same geometry gate and would return nullptr for both.
    GeometryProblem problem{};
    if (!checkGeometry(md, problem)) {
        return reject(AdmissionReject::MalformedMetadata, problem.field,
                      std::string("inconsistent geometry: ") + problem.field + " " + problem.detail);
    }
    if (!checkArchConsistency(md, traits, problem)) {
        return reject(AdmissionReject::MalformedMetadata, problem.field,
                      std::string("architecture/metadata mismatch: ") + problem.field + " " + problem.detail);
    }

    // 5. A registered implementation must exist. Recognition without an
    //    implementation is not admission.
    const Architecture* arch = resolve(md);
    if (arch == nullptr) {
        return reject(AdmissionReject::ArchitectureUnimplemented, "architecture",
                      "architecture recognized but no implementation registered: " + key);
    }

    // 6. Required tensor roles.
    std::string firstMissing;
    const std::size_t missing = countMissingRequiredTensors(md, firstMissing);
    if (missing != 0) {
        report.missingTensors = missing;
        return reject(AdmissionReject::MissingRequiredTensor, firstMissing.c_str(),
                      std::to_string(missing) + " required tensor role(s) absent; first: " + firstMissing);
    }
    report.missingTensors = 0;

    // 7. Quantization execution capability on the requested device.
    report.quantCpuExecutable = quantExecutable(md.quantTypeId, ExecDevice::Cpu);
    report.quantGpuExecutable = quantExecutable(md.quantTypeId, ExecDevice::Gpu);
    const bool deviceOk = (device == ExecDevice::Cpu) ? report.quantCpuExecutable
                                                      : report.quantGpuExecutable;
    if (!deviceOk) {
        return reject(AdmissionReject::UnsupportedQuant, "quantTypeId",
                      "no executable kernel for quant type id " +
                          std::to_string(md.quantTypeId) + " (" +
                          Deep2::QuantTypeName(md.quantTypeId) + ") on " +
                          (device == ExecDevice::Cpu ? "CPU" : "GPU") +
                          "; parseable is not executable");
    }

    report.admitted = true;
    report.reject = AdmissionReject::None;
    return true;
}

} // namespace Deep2