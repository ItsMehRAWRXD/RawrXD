#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace Deep2::SpecialGraph {

enum class Family : std::uint8_t {
    GptOss120B,
    LagunaS21,
    DeepSeekV4Flash
};

enum class Op : std::uint8_t {
    TokenEmbedding,
    PreAttentionNorm,
    AttentionQKV,
    AttentionRoPE,
    MLALatentProjection,
    MLAAttention,
    AttentionScores,
    AttentionSoftmax,
    AttentionValue,
    AttentionOutput,
    AttentionResidual,
    PreFfnNorm,
    MoERouter,
    ExpertDispatch,
    RoutedExperts,
    SharedExpert,
    ExpertReduce,
    FfnResidual,
    FinalNorm,
    LMHead,
    Logits
};

struct RuntimeMeta final {
    std::uint32_t layerCount{};
    std::uint32_t expertCount{};
    std::uint32_t expertsPerToken{};
    std::uint32_t sharedExperts{};
    std::uint32_t kvHeads{};
    std::uint32_t headDim{};
    std::uint64_t contextLength{};
    bool usesMla{};
};

struct Node final {
    std::uint32_t id{};
    Op op{Op::TokenEmbedding};
    std::int32_t layer{-1};
    std::string name{};
};

struct Edge final {
    std::uint32_t from{};
    std::uint32_t to{};
};

struct Graph final {
    Family family{Family::GptOss120B};
    RuntimeMeta meta{};
    std::vector<Node> nodes{};
    std::vector<Edge> edges{};
};

struct Validation final {
    bool ok{};
    std::string reason{};
};

[[nodiscard]] RuntimeMeta contractDefaults(Family family) noexcept;
[[nodiscard]] Graph build(Family family, RuntimeMeta runtimeMeta = {});
[[nodiscard]] Validation validate(const Graph& graph) noexcept;
[[nodiscard]] const char* toString(Family family) noexcept;
[[nodiscard]] const char* toString(Op op) noexcept;

} // namespace Deep2::SpecialGraph
