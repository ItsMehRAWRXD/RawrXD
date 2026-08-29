#include "BuildStateGraph.hpp"

namespace Sovereign {

BuildStateGraph& BuildStateGraph::Instance() {
    static BuildStateGraph instance;
    return instance;
}

void BuildStateGraph::TransitionTo(BuildState newState) {
    std::lock_guard<std::mutex> lock(mutex_);
    current_.state = newState;
}

bool BuildStateGraph::StartBuild(const std::string& target, const BuildConfiguration& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    current_.target = target;
    current_.config = config;
    current_.percent = 0;
    current_.lastError.clear();
    current_.state = BuildState::BUILDING;
    return !target.empty();
}

bool BuildStateGraph::CancelBuild() {
    std::lock_guard<std::mutex> lock(mutex_);
    current_.state = BuildState::CANCELLED;
    return true;
}

BuildStateGraph::CurrentBuild BuildStateGraph::GetCurrent() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return current_;
}

BuildState BuildStateGraph::GetState() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return current_.state;
}

} // namespace Sovereign
