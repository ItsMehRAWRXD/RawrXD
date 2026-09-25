#include "FleetSpecialGraphExecutor.hpp"

#include <sstream>

namespace Deep2::SpecialGraph {

bool ExecuteReceipt::pass() const noexcept {
    return graphValid && failures == 0 && nodesPlanned > 0 &&
           nodesExecuted == nodesPlanned && finalLogitsReached;
}

std::string ExecuteReceipt::text() const {
    const char* gate = "RAWRXD_SPECIAL_GRAPH_UNKNOWN_001";
    switch (family) {
        case Family::GptOss120B: gate = "RAWRXD_GPT_OSS_SPECIAL_GRAPH_001"; break;
        case Family::LagunaS21: gate = "RAWRXD_LAGUNA_SPECIAL_GRAPH_001"; break;
        case Family::DeepSeekV4Flash: gate = "RAWRXD_DEEPSEEK4_SPECIAL_GRAPH_001"; break;
    }
    std::ostringstream o;
    o << "=== " << gate << " ===\n";
    o << "GRAPH_VALID=" << (graphValid ? "PASS" : "FAIL") << "\n";
    o << "NODES_PLANNED=" << nodesPlanned << "\n";
    o << "NODES_EXECUTED=" << nodesExecuted << "\n";
    o << "LAYERS_COMPLETED=" << layersCompleted << "\n";
    o << "FINAL_LOGITS_REACHED=" << (finalLogitsReached ? "PASS" : "FAIL") << "\n";
    o << "FAILURES=" << failures << "\n";
    o << "VERDICT=" << (pass() ? "PASS" : "FAIL") << "\n";
    return o.str();
}

ExecuteReceipt execute(const Graph& graph, const ExecuteCallbacks& callbacks) {
    ExecuteReceipt r;
    r.family = graph.family;
    r.nodesPlanned = graph.nodes.size();
    const auto v = validate(graph);
    r.graphValid = v.ok;
    if (!v.ok || !callbacks.executeNode) {
        ++r.failures;
        return r;
    }

    std::int32_t lastCompletedLayer = -1;
    for (const auto& node : graph.nodes) {
        if (!callbacks.executeNode(callbacks.user, node)) {
            ++r.failures;
            return r; // fail closed at the first unexecuted graph operation.
        }
        ++r.nodesExecuted;
        if (node.op == Op::FfnResidual && node.layer >= 0) {
            lastCompletedLayer = node.layer;
            ++r.layersCompleted;
        }
        if (node.op == Op::Logits) r.finalLogitsReached = true;
    }
    (void)lastCompletedLayer;
    return r;
}

} // namespace Deep2::SpecialGraph
