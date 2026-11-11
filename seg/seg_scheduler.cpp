#include "seg_scheduler.hpp"
#include <thread>

namespace seg {

void Scheduler::Execute(const Graph& graph, const NodeFn& fn) {
    auto order = graph.TopologicalSort();
    if (m_mode == ScheduleMode::kSequential) {
        for (auto id : order) {
            const Node* n = graph.GetNode(id);
            if (n) fn(*n);
        }
    } else {
        // Placeholder parallel mode: still sequential, ready for C7 integration
        for (auto id : order) {
            const Node* n = graph.GetNode(id);
            if (n) fn(*n);
        }
    }
}

} // namespace seg
