#pragma once
#include "seg_graph.hpp"
#include <functional>

namespace seg {

enum class ScheduleMode : uint8_t {
    kSequential,
    kParallel
};

using NodeFn = std::function<void(const Node&)>;

class Scheduler {
public:
    void SetMode(ScheduleMode mode) { m_mode = mode; }
    void Execute(const Graph& graph, const NodeFn& fn);

private:
    ScheduleMode m_mode = ScheduleMode::kSequential;
};

} // namespace seg
