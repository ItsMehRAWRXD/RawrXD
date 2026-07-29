#pragma once
#include "AgenticSupervisor.hpp"
#include "Deep2Engine.hpp"

namespace RawrXD {
namespace Agentic {

struct InferenceRequest {
    std::string prompt;
    size_t maxTokens = 256;
    float temperature = 0.7f;
    std::function<void(const std::string&)> onToken;
    std::function<void(const std::string&)> onComplete;
};

class InferenceTaskFactory {
public:
    static AgenticTask Create(const InferenceRequest& req, Deep2Engine* engine);
};

} // namespace Agentic
} // namespace RawrXD
