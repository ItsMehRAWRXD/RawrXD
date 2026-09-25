#pragma once
// RAWRXD_MODEL_ARCH_PACK_001
// Pure C++20, no third-party dependencies.
//
// Central model-architecture authority for Deep2.  The point of this file is
// to stop treating every GGUF that is "close to llama" as llama.  Architectures
// are explicitly classified and either routed to an existing production path,
// a recurrent reference path, or rejected fail-closed.

#include <array>
#include <string>
#include <string_view>

namespace Deep2::Arch {

enum class Kind : unsigned char {
    Unknown = 0,
    Llama,
    Mistral,
    Phi3,
    Qwen,
    Qwen2,
    Qwen2Moe,
    Qwen3,
    Qwen3Moe,
    Qwen3Next,
    Qwen35,
    Qwen35Moe,
    Gemma,
    Gemma2,
    Gemma3,
    DeepSeek2,
    DeepSeek32,
    DeepSeek4,
    Nemotron,
    NemotronH,
    NemotronHMoe,
    GptOss,
    Laguna,
    Mamba,
    Mamba2,
};

enum class ForwardFamily : unsigned char {
    Unsupported = 0,
    GenericTransformer, // MHA/GQA + dense FFN
    GenericMoE,         // MHA/GQA + current Deep2 MoE
    MLA,                // DeepSeek/K2 Multi-Latent Attention
    GatedDeltaNet,      // Qwen3-Next / Qwen3.5 recurrent layers
    Mamba2,             // Nemotron-H recurrent layers
    SpecialGraph,       // recognized, but requires its own graph
};

enum class FfnActivation : unsigned char {
    SwiGLU = 0,
    GeGLU,
    GELU,
};

struct Traits {
    Kind kind = Kind::Unknown;
    ForwardFamily family = ForwardFamily::Unsupported;
    FfnActivation ffn = FfnActivation::SwiGLU;
    const char* canonical = "unknown";

    bool qkNorm = false;
    bool qkvBias = false;
    bool embedSqrtScale = false;
    bool postAttentionNorm = false;
    bool postFfnNorm = false;
    bool moe = false;
    bool mla = false;
    bool recurrent = false;
    bool slidingWindow = false;

    // "safeGeneric" means current Deep2 generic transformer/MoE/MLA primitives
    // are a valid architectural base.  It is not a parity certificate.
    bool safeGeneric = false;

    // These must not silently enter GenericTransformer.
    bool requiresSpecialGraph = false;
};

inline bool eq(std::string_view a, std::string_view b) noexcept {
    return a == b;
}

inline Traits resolve(std::string_view a) noexcept {
    // llama-compatible dense families
    if (eq(a,"llama"))      return {Kind::Llama,   ForwardFamily::GenericTransformer,FfnActivation::SwiGLU,"llama",false,false,false,false,false,false,false,false,false,true,false};
    if (eq(a,"mistral"))    return {Kind::Mistral, ForwardFamily::GenericTransformer,FfnActivation::SwiGLU,"mistral",false,false,false,false,false,false,false,false,true,true,false};
    if (eq(a,"phi3"))       return {Kind::Phi3,    ForwardFamily::GenericTransformer,FfnActivation::SwiGLU,"phi3",false,true,false,false,false,false,false,false,false,true,false};

    // Qwen
    if (eq(a,"qwen"))       return {Kind::Qwen,    ForwardFamily::GenericTransformer,FfnActivation::SwiGLU,"qwen",false,true,false,false,false,false,false,false,false,true,false};
    if (eq(a,"qwen2"))      return {Kind::Qwen2,   ForwardFamily::GenericTransformer,FfnActivation::SwiGLU,"qwen2",false,true,false,false,false,false,false,false,false,true,false};
    if (eq(a,"qwen2moe"))   return {Kind::Qwen2Moe,ForwardFamily::GenericMoE,FfnActivation::SwiGLU,"qwen2moe",false,true,false,false,false,true,false,false,false,true,false};
    if (eq(a,"qwen3"))      return {Kind::Qwen3,   ForwardFamily::GenericTransformer,FfnActivation::SwiGLU,"qwen3",true,false,false,false,false,false,false,false,false,true,false};
    if (eq(a,"qwen3moe") || eq(a,"qwen3_moe"))
                               return {Kind::Qwen3Moe,ForwardFamily::GenericMoE,FfnActivation::SwiGLU,"qwen3moe",true,false,false,false,false,true,false,false,false,true,false};
    if (eq(a,"qwen3next") || eq(a,"qwen3_next"))
                               return {Kind::Qwen3Next,ForwardFamily::GatedDeltaNet,FfnActivation::SwiGLU,"qwen3next",true,false,false,true,false,true,false,true,false,false,true};
    if (eq(a,"qwen35") || eq(a,"qwen3.5") || eq(a,"qwen3_5"))
                               return {Kind::Qwen35,ForwardFamily::GatedDeltaNet,FfnActivation::SwiGLU,"qwen35",true,false,false,true,false,false,false,true,false,false,true};
    if (eq(a,"qwen35moe") || eq(a,"qwen3.5moe") || eq(a,"qwen3_5moe"))
                               return {Kind::Qwen35Moe,ForwardFamily::GatedDeltaNet,FfnActivation::SwiGLU,"qwen35moe",true,false,false,true,false,true,false,true,false,false,true};

    // Gemma.  Gemma3 already has dedicated handling in current Deep2.
    if (eq(a,"gemma"))      return {Kind::Gemma, ForwardFamily::GenericTransformer,FfnActivation::GeGLU,"gemma",false,false,true,false,false,false,false,false,false,true,false};
    if (eq(a,"gemma2"))     return {Kind::Gemma2,ForwardFamily::GenericTransformer,FfnActivation::GeGLU,"gemma2",false,false,true,true,true,false,false,false,true,true,false};
    if (eq(a,"gemma3"))     return {Kind::Gemma3,ForwardFamily::GenericTransformer,FfnActivation::GeGLU,"gemma3",false,false,true,true,true,false,false,false,true,true,false};

    // DeepSeek MLA family. DeepSeek4 is recognized but not aliased to V2/V3:
    // it has architecture changes and must earn its own path.
    if (eq(a,"deepseek2"))  return {Kind::DeepSeek2,ForwardFamily::MLA,FfnActivation::SwiGLU,"deepseek2",false,false,false,false,false,true,true,false,false,true,false};
    if (eq(a,"deepseek32")) return {Kind::DeepSeek32,ForwardFamily::MLA,FfnActivation::SwiGLU,"deepseek32",false,false,false,false,false,true,true,false,false,true,false};
    if (eq(a,"deepseek4"))  return {Kind::DeepSeek4,ForwardFamily::SpecialGraph,FfnActivation::SwiGLU,"deepseek4",false,false,false,false,false,true,true,false,false,false,true};

    // NVIDIA Nemotron.
    if (eq(a,"nemotron"))   return {Kind::Nemotron,ForwardFamily::GenericTransformer,FfnActivation::SwiGLU,"nemotron",false,false,false,false,false,false,false,false,false,true,false};
    if (eq(a,"nemotron_h")) return {Kind::NemotronH,ForwardFamily::Mamba2,FfnActivation::SwiGLU,"nemotron_h",false,false,false,false,false,false,false,true,false,false,true};
    if (eq(a,"nemotron_h_moe"))
                               return {Kind::NemotronHMoe,ForwardFamily::Mamba2,FfnActivation::SwiGLU,"nemotron_h_moe",false,false,false,false,false,true,false,true,false,false,true};

    // Known special graphs.  Recognition is intentional: do not silently run
    // them through Llama math just because their tensor names look familiar.
    if (eq(a,"gpt-oss") || eq(a,"gpt_oss"))
                               return {Kind::GptOss,ForwardFamily::SpecialGraph,FfnActivation::SwiGLU,"gpt-oss",false,false,false,false,false,true,false,false,true,false,true};
    if (eq(a,"laguna"))     return {Kind::Laguna,ForwardFamily::SpecialGraph,FfnActivation::SwiGLU,"laguna",true,false,false,false,false,true,false,false,true,false,true};

    if (eq(a,"mamba"))      return {Kind::Mamba,ForwardFamily::Mamba2,FfnActivation::SwiGLU,"mamba",false,false,false,false,false,false,false,true,false,false,true};
    if (eq(a,"mamba2"))     return {Kind::Mamba2,ForwardFamily::Mamba2,FfnActivation::SwiGLU,"mamba2",false,false,false,false,false,false,false,true,false,false,true};

    return {};
}

inline const char* familyName(ForwardFamily f) noexcept {
    switch (f) {
        case ForwardFamily::GenericTransformer: return "GENERIC_TRANSFORMER";
        case ForwardFamily::GenericMoE:         return "GENERIC_MOE";
        case ForwardFamily::MLA:                return "MLA";
        case ForwardFamily::GatedDeltaNet:      return "GATED_DELTA_NET";
        case ForwardFamily::Mamba2:             return "MAMBA2";
        case ForwardFamily::SpecialGraph:       return "SPECIAL_GRAPH";
        default:                                return "UNSUPPORTED";
    }
}

inline bool isKnown(std::string_view a) noexcept {
    return resolve(a).kind != Kind::Unknown;
}

} // namespace Deep2::Arch
