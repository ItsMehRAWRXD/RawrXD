// ============================================================================
// TrailForge.h — Execution-graph kernel for Deep2 inference scheduling
// RAWRXD_TRAILFORGE_001
//
// Models the inference pipeline as a DAG of execution nodes.
// Supports multiple scheduling strategies: STATIC, FORWARD_READY,
// REVERSE_DEMAND, RANDOM_READY.
//
// All production inference paths route through generateUnified(), which
// internally may use TrailForge to schedule layer execution.
// ============================================================================
#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <functional>
#include <random>

namespace Deep2::TrailForge {

// ---------------------------------------------------------------------------
// ExecOp — every primitive operation in the inference pipeline
// ---------------------------------------------------------------------------
enum class ExecOp : uint8_t {
    None          = 0,
    Embed         = 1,   // embedToken(int, float*)
    ForwardLayer  = 2,   // forward one transformer layer
    ComputeLogits = 3,   // computeLogits(float*, float*)
    Sample        = 4,   // sample from logits → token
    AdvanceKV     = 5,   // advancePersistentKv()
    YieldToken    = 6,   // emit generated token to callback
    ResetState    = 7,   // reset() / clear caches
    LoopCondition = 8,   // check max tokens / EOS / cancel
    PrefillPhase  = 9,   // marker: prefill vs decode phase boundary
};

const char* execOpName(ExecOp op);

// ---------------------------------------------------------------------------
// ExecutionNode — single node in the recipe DAG
// ---------------------------------------------------------------------------
struct ExecutionNode {
    size_t id = 0;                  // stable index into recipe.nodes
    ExecOp op = ExecOp::None;
    size_t layerIndex = 0;          // for ForwardLayer: which layer
    std::vector<size_t> deps;       // nodes this node depends on (must complete first)
    std::vector<size_t> consumers;  // nodes that depend on this one

    // Scheduling metadata (populated by DependencyGraph)
    int inDegree = 0;               // unresolved dependency count
    int outDegree = 0;              // consumer count
    bool scheduled = false;         // visited during scheduling
};

// ---------------------------------------------------------------------------
// ExecutionRecipe — a complete DAG describing one inference step
// ---------------------------------------------------------------------------
struct ExecutionRecipe {
    std::string name;
    std::vector<ExecutionNode> nodes;

    // Builder helpers
    size_t addNode(ExecOp op, size_t layerIdx = 0);
    void addDependency(size_t from, size_t to); // from must complete before to

    // Validate structural integrity
    bool validate(std::string* error = nullptr) const;
};

// ---------------------------------------------------------------------------
// DependencyGraph — built from a recipe; provides adjacency + cycle detection
// ---------------------------------------------------------------------------
class DependencyGraph {
public:
    DependencyGraph() = default;
    explicit DependencyGraph(const ExecutionRecipe& recipe);

    bool build(const ExecutionRecipe& recipe);
    bool hasCycle() const;
    size_t nodeCount() const { return nodes_.size(); }

    const std::vector<size_t>& dependencies(size_t nodeId) const;
    const std::vector<size_t>& consumers(size_t nodeId) const;
    int inDegree(size_t nodeId) const;

    // All nodes with in-degree == 0 (entry points)
    std::vector<size_t> entryNodes() const;

    // All nodes with out-degree == 0 (terminal points)
    std::vector<size_t> terminalNodes() const;

private:
    struct GraphNode {
        std::vector<size_t> deps;
        std::vector<size_t> consumers;
        int inDegree = 0;
    };
    std::vector<GraphNode> nodes_;
    bool cycleDetected_ = false;

    bool detectCycleDFS(size_t start, std::vector<uint8_t>& color) const;
};

// ---------------------------------------------------------------------------
// ExecutionStrategy — scheduling policy
// ---------------------------------------------------------------------------
enum class ExecutionStrategy : uint8_t {
    Static        = 0,  // Pre-computed topological order (deterministic)
    ForwardReady  = 1,  // BFS from entry nodes (natural forward order)
    ReverseDemand = 2,  // Backwards from terminals (demand-driven)
    RandomReady   = 3,  // Randomized ready-set (stress / coverage testing)
};

const char* strategyName(ExecutionStrategy s);

// ---------------------------------------------------------------------------
// ReadySet — ordered queue of nodes ready to execute
// ---------------------------------------------------------------------------
class ReadySet {
public:
    ReadySet() = default;
    explicit ReadySet(ExecutionStrategy strategy);

    void setStrategy(ExecutionStrategy s) { strategy_ = s; }
    ExecutionStrategy strategy() const { return strategy_; }

    void clear();
    bool empty() const;
    void insert(size_t nodeId);

    // Pop the next node according to the active strategy.
    // Returns std::nullopt when empty.
    std::optional<size_t> popNext(std::mt19937_64& rng);

    // Peek at what would be popped next (non-destructive)
    std::optional<size_t> peekNext(std::mt19937_64& rng) const;

    size_t size() const { return data_.size(); }

private:
    ExecutionStrategy strategy_ = ExecutionStrategy::Static;
    std::vector<size_t> data_;

    size_t selectIndex(std::mt19937_64& rng) const;
};

// ---------------------------------------------------------------------------
// RecipeScheduler — produces an execution order from a recipe + strategy
// ---------------------------------------------------------------------------
class RecipeScheduler {
public:
    // Returns ordered node IDs. Empty if cycle detected.
    std::vector<size_t> schedule(const ExecutionRecipe& recipe,
                                   ExecutionStrategy strategy,
                                   std::string* error = nullptr);

    // Verify that an ordering respects all dependencies (certification gate)
    static bool verifyOrdering(const ExecutionRecipe& recipe,
                                const std::vector<size_t>& ordering,
                                std::string* error = nullptr);

    // Build a standard transformer-layer recipe for N layers
    static ExecutionRecipe buildTransformerRecipe(size_t numLayers,
                                                    const std::string& name = "transformer");

    // Build a single-token decode recipe (1 embed + N layers + logits + sample + advance)
    static ExecutionRecipe buildDecodeStepRecipe(size_t numLayers,
                                                   const std::string& name = "decode_step");

private:
    std::vector<size_t> scheduleStatic(const DependencyGraph& graph);
    std::vector<size_t> scheduleForwardReady(const DependencyGraph& graph);
    std::vector<size_t> scheduleReverseDemand(const DependencyGraph& graph);
    std::vector<size_t> scheduleRandomReady(const DependencyGraph& graph, std::mt19937_64& rng);
};

} // namespace Deep2::TrailForge
