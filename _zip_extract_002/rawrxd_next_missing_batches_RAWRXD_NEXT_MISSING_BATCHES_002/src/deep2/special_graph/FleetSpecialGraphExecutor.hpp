#pragma once

#include "FleetSpecialGraph.hpp"

#include <cstdint>
#include <string>

namespace Deep2::SpecialGraph {

struct ExecuteCallbacks final {
    void* user{};
    bool (*executeNode)(void* user, const Node& node){};
};

struct ExecuteReceipt final {
    Family family{Family::GptOss120B};
    std::uint64_t nodesPlanned{};
    std::uint64_t nodesExecuted{};
    std::uint64_t layersCompleted{};
    std::uint64_t failures{};
    bool graphValid{};
    bool finalLogitsReached{};

    [[nodiscard]] bool pass() const noexcept;
    [[nodiscard]] std::string text() const;
};

[[nodiscard]] ExecuteReceipt execute(
    const Graph& graph,
    const ExecuteCallbacks& callbacks);

} // namespace Deep2::SpecialGraph
