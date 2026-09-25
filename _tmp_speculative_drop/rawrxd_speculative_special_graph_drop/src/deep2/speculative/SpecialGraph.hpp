#pragma once
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace rawrxd::deep2::spec {

enum class GraphOp : std::uint8_t {
    Draft,
    Verify,
    Accept,
    Rollback,
    Commit,
    Stop
};

enum class EdgeCond : std::uint8_t {
    Always,
    DraftProduced,
    DraftEmpty,
    AllAccepted,
    Rejected,
    BudgetExhausted,
    BudgetRemaining
};

struct GraphNode final {
    std::uint32_t id{};
    GraphOp op{GraphOp::Stop};
    std::string name{};
};

struct GraphEdge final {
    std::uint32_t from{};
    std::uint32_t to{};
    EdgeCond cond{EdgeCond::Always};
};

class SpecialGraph final {
public:
    std::uint32_t addNode(GraphOp op, std::string name);
    bool addEdge(std::uint32_t from, std::uint32_t to, EdgeCond cond);

    [[nodiscard]] const GraphNode* node(std::uint32_t id) const noexcept;
    [[nodiscard]] const std::vector<GraphNode>& nodes() const noexcept { return nodes_; }
    [[nodiscard]] const std::vector<GraphEdge>& edges() const noexcept { return edges_; }

    [[nodiscard]] bool validate(std::string* why = nullptr) const;
    [[nodiscard]] std::uint32_t next(std::uint32_t from, EdgeCond cond) const noexcept;

    static SpecialGraph makeSpeculativeDecodeGraph();

private:
    std::vector<GraphNode> nodes_{};
    std::vector<GraphEdge> edges_{};
};

[[nodiscard]] const char* toString(GraphOp op) noexcept;
[[nodiscard]] const char* toString(EdgeCond cond) noexcept;

} // namespace rawrxd::deep2::spec
