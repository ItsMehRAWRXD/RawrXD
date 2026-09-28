#include "BoundedAgentLoop.h"

namespace RawrXD {
namespace Agent {

std::string BoundedAgentLoop::Execute(const std::string& task) {
    running_ = true;
    currentStep_ = 0;
    std::string result;
    while (currentStep_ < config_.maxSteps) {
        ++currentStep_;
        // Stub: no real model invocation yet
        break;
    }
    running_ = false;
    return result;
}

} // namespace Agent
} // namespace RawrXD
