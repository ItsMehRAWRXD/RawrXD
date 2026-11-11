#pragma once
// RawrXD Bolt capability admission gate. C++20, STL only.
// No inference is performed here. Unknown capabilities fail closed.
#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace rawrxd::bolt {
enum class Capability : std::uint8_t {
    GgufNemotronHMoe, Mamba2Scan, Mamba2StateCache,
    TransformerAttention, TransformerKVCache,
    LatentDownProjection, LatentRouter, RoutedExperts, SharedExperts,
    IQ2XXS, NVFP4, Q8_0, Tokenizer, ChatTemplate,
    Count
};
inline constexpr std::array<std::string_view, static_cast<size_t>(Capability::Count)> names = {
    "gguf.nemotron_h_moe", "mamba2.scan", "mamba2.state_cache",
    "transformer.attention", "transformer.kv_cache",
    "latent_moe.down_projection", "latent_moe.router",
    "latent_moe.routed_experts", "latent_moe.shared_experts",
    "quant.iq2_xxs", "quant.nvfp4", "quant.q8_0",
    "tokenizer", "chat_template"
};
struct Certification {
    Capability capability;
    bool implemented = false;
    bool tested = false;
    bool parity_pass = false;
    std::string source_commit;
    std::string test_receipt;
};
struct Admission {
    bool accepted = false;
    std::vector<std::string> failures;
};
inline Admission evaluate(std::string_view gguf_arch,
                          const std::vector<Certification>& records,
                          std::string_view running_commit) {
    Admission out;
    if (gguf_arch != "nemotron_h_moe")
        out.failures.emplace_back("Unexpected GGUF architecture");
    std::array<bool, names.size()> satisfied{};
    for (const auto& record : records) {
        const auto i = static_cast<size_t>(record.capability);
        if (i >= satisfied.size()) {
            out.failures.emplace_back("Unknown capability ID");
            continue;
        }
        const bool valid = record.implemented && record.tested &&
            record.parity_pass && !record.test_receipt.empty() &&
            !running_commit.empty() && record.source_commit == running_commit;
        if (valid) satisfied[i] = true;
    }
    for (size_t i = 0; i < satisfied.size(); ++i)
        if (!satisfied[i])
            out.failures.emplace_back("Uncertified capability: " + std::string(names[i]));
    out.accepted = out.failures.empty();
    return out;
}
} // namespace rawrxd::bolt
