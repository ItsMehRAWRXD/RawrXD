// ============================================================================
// streaming_command_handler.cpp — Parsed request → Tool Authority → result
// ============================================================================
#include "streaming_command_handler.h"
#include "StreamingResultChannel.h"
#include "deep2/AgentToolRegistry.hpp"

#include <atomic>
#include <filesystem>
#include <string>

namespace RawrXD::Agentic {

using namespace std::chrono_literals;

// ============================================================================
// Implementation
// ============================================================================
class StreamingCommandHandler::Impl {
public:
    StreamingResultChannel* channel_ = nullptr;
    AgentToolRegistry* registry_ = nullptr;

    // Counters
    std::atomic<uint64_t> requestsBuilt_{0};
    std::atomic<uint64_t> invocationsSent_{0};
    std::atomic<uint64_t> resultsReceived_{0};
    std::atomic<uint64_t> resultsPushed_{0};
    std::atomic<uint64_t> errors_{0};
};

StreamingCommandHandler::StreamingCommandHandler()
    : impl_(std::make_unique<Impl>()) {}

StreamingCommandHandler::~StreamingCommandHandler() = default;

void StreamingCommandHandler::setChannel(StreamingResultChannel* channel) {
    impl_->channel_ = channel;
}

void StreamingCommandHandler::setToolRegistry(AgentToolRegistry* registry) {
    impl_->registry_ = registry;
}

bool StreamingCommandHandler::handleCommand(const std::string& jsonPayload) {
    if (!impl_->registry_ || !impl_->channel_) return false;

    // Build ToolRequest from JSON payload (naïve: whole payload is tool_id for now)
    ToolRequest req;
    req.run_id    = 0;
    req.action_id = impl_->requestsBuilt_.fetch_add(1, std::memory_order_acq_rel);
    req.surface   = AgentToolSurface::AgentCore;
    req.tool_id   = jsonPayload;
    req.working_directory = std::filesystem::current_path();

    ToolContext ctx;
    ctx.cancelled = [&]() {
        return impl_->channel_->isCancelRequested();
    };

    impl_->invocationsSent_.fetch_add(1, std::memory_order_acq_rel);
    ToolResult result = impl_->registry_->invoke(std::move(req), ctx);
    impl_->resultsReceived_.fetch_add(1, std::memory_order_acq_rel);

    if (!result.ok()) {
        impl_->errors_.fetch_add(1, std::memory_order_acq_rel);
        impl_->channel_->publishError(result.stderr_text);
        return false;
    }

    impl_->channel_->publishToolResult(result.stdout_text);
    impl_->resultsPushed_.fetch_add(1, std::memory_order_acq_rel);
    return true;
}

HandlerCounters StreamingCommandHandler::counters() const {
    HandlerCounters c;
    c.requestsBuilt   = impl_->requestsBuilt_.load(std::memory_order_acquire);
    c.invocationsSent = impl_->invocationsSent_.load(std::memory_order_acquire);
    c.resultsReceived = impl_->resultsReceived_.load(std::memory_order_acquire);
    c.resultsPushed   = impl_->resultsPushed_.load(std::memory_order_acquire);
    c.errors          = impl_->errors_.load(std::memory_order_acquire);
    return c;
}

void StreamingCommandHandler::resetCounters() {
    impl_->requestsBuilt_.store(0, std::memory_order_release);
    impl_->invocationsSent_.store(0, std::memory_order_release);
    impl_->resultsReceived_.store(0, std::memory_order_release);
    impl_->resultsPushed_.store(0, std::memory_order_release);
    impl_->errors_.store(0, std::memory_order_release);
}

} // namespace RawrXD::Agentic
