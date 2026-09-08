#pragma once
#include "ProductRuntime.hpp"
namespace rawr::product_run {

class ExecutionGraph {
public:
    uint32_t nodeCount = 0;
    void reset() { nodeCount = 0; }
    uint32_t size() const { return nodeCount; }
};

inline bool BuildExecutionGraph(ProductRuntime& rt, ExecutionGraph& g) {
    if (!rt.BuildExecutionGraph()) {
        g.reset();
        return false;
    }
    g.nodeCount = rt.graphNodes;
    return g.nodeCount > 0;
}

} // namespace rawr::product_run
