// ============================================================================
// agentic_model_streamer_bridge.cpp — Model↔Agent boundary
// ============================================================================
#include "agentic_model_streamer_bridge.h"
#include "StreamingResultChannel.h"
#include "deep2/AgentToolRegistry.hpp"

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <optional>
#include <chrono>
#include <fstream>

namespace RawrXD::Agentic {

static void bridgeLog(const std::string& msg) {
    static std::mutex m;
    std::lock_guard<std::mutex> lk(m);
    std::ofstream ofs("F:\\~dev\\agentic_bridge_log.txt", std::ios::app);
    if (ofs) ofs << msg << "\n";
}

using namespace std::chrono_literals;

// ============================================================================
// Implementation
// ============================================================================
class AgenticModelStreamerBridge::Impl {
public:
    StreamingResultChannel* channel_ = nullptr;
    AgentToolRegistry* registry_ = nullptr;
    std::thread pumpThread_;
    std::atomic<bool> running_{false};
    std::atomic<bool> stopRequested_{false};
    std::string textAccumulator_;
    std::string lastToolRequestRaw_;
    std::string lastToolName_;
    std::string lastToolResultText_;
    std::mutex diagMu_;

    // Counters
    std::atomic<uint64_t> deltasConsumed_{0};
    std::atomic<uint64_t> toolRequestsSeen_{0};
    std::atomic<uint64_t> toolRequestsParsed_{0};
    std::atomic<uint64_t> authorityCalls_{0};
    std::atomic<uint64_t> toolExecutions_{0};
    std::atomic<uint64_t> toolResultsProduced_{0};
    std::atomic<uint64_t> toolResultsSent_{0};
    std::atomic<uint64_t> toolResultsInjected_{0};
    std::atomic<uint64_t> continuationsStarted_{0};
    std::atomic<uint64_t> postToolTokens_{0};
    std::atomic<uint64_t> errors_{0};
    std::atomic<uint64_t> parseFailures_{0};

    void tryExtractToolCall() {
        if (!registry_ || !channel_) return;
        bridgeLog("[tryExtract] acc_len=" + std::to_string(textAccumulator_.size()));
        auto ts = textAccumulator_.find("<tool>"), te = textAccumulator_.find("</tool>");
        auto as = textAccumulator_.find("<args>"),  ae = textAccumulator_.find("</args>");
        bridgeLog("[tryExtract] ts=" + std::to_string(ts) + " te=" + std::to_string(te) +
                    " as=" + std::to_string(as) + " ae=" + std::to_string(ae));
        if (ts != std::string::npos && te != std::string::npos &&
            as != std::string::npos && ae != std::string::npos &&
            ts < te && as < ae && ts < as && te < ae) {
            std::string toolName = textAccumulator_.substr(ts + 6, te - ts - 6);
            std::string args     = textAccumulator_.substr(as + 6, ae - as - 6);
            bridgeLog("[tryExtract] toolName=" + toolName + " args=" + args);
            if (!toolName.empty()) {
                {
                    std::lock_guard<std::mutex> lk(diagMu_);
                    lastToolRequestRaw_ = textAccumulator_.substr(ts, ae + 7 - ts);
                    lastToolName_       = toolName;
                }
                toolRequestsParsed_.fetch_add(1, std::memory_order_acq_rel);
                ToolRequest req;
                req.run_id    = 0;
                req.action_id = 0;
                req.surface   = AgentToolSurface::AgentCore;
                req.tool_id   = std::move(toolName);
                req.stdin_text = std::move(args);
                req.working_directory = std::filesystem::current_path();
                ToolContext ctx;
                ctx.cancelled = [&]() { return channel_->isCancelRequested(); };
                authorityCalls_.fetch_add(1, std::memory_order_acq_rel);
                ToolResult res = registry_->invoke(std::move(req), ctx);
                toolExecutions_.fetch_add(1, std::memory_order_acq_rel);
                if (res.ok()) {
                    {
                        std::lock_guard<std::mutex> lk(diagMu_);
                        lastToolResultText_ = res.stdout_text;
                    }
                    toolResultsProduced_.fetch_add(1, std::memory_order_acq_rel);
                    channel_->publishToolResult(res.stdout_text);
                    toolResultsSent_.fetch_add(1, std::memory_order_acq_rel);
                    toolResultsInjected_.fetch_add(1, std::memory_order_acq_rel);
                    bridgeLog("[tryExtract] tool OK stdout_len=" + std::to_string(res.stdout_text.size()));
                } else {
                    channel_->publishError(res.stderr_text);
                    errors_.fetch_add(1, std::memory_order_acq_rel);
                    bridgeLog("[tryExtract] tool ERROR stderr=" + res.stderr_text);
                }
                toolRequestsSeen_.fetch_add(1, std::memory_order_acq_rel);
                size_t consumed = ae + 7;
                if (consumed <= textAccumulator_.size())
                    textAccumulator_.erase(0, consumed);
            }
        }
    }
};

AgenticModelStreamerBridge::AgenticModelStreamerBridge()
    : impl_(std::make_unique<Impl>()) {}

AgenticModelStreamerBridge::~AgenticModelStreamerBridge() {
    stop();
}

void AgenticModelStreamerBridge::setChannel(StreamingResultChannel* channel) {
    impl_->channel_ = channel;
}

void AgenticModelStreamerBridge::setToolRegistry(AgentToolRegistry* registry) {
    impl_->registry_ = registry;
}

void AgenticModelStreamerBridge::start() {
    if (impl_->running_.load(std::memory_order_acquire)) return;
    impl_->stopRequested_.store(false, std::memory_order_release);
    impl_->running_.store(true, std::memory_order_release);
    impl_->pumpThread_ = std::thread([this]() {
        while (!impl_->stopRequested_.load(std::memory_order_acquire)) {
            if (!impl_->channel_) { std::this_thread::sleep_for(10ms); continue; }

            auto ev = impl_->channel_->pop(std::chrono::milliseconds(100));
            if (!ev) continue;

            impl_->deltasConsumed_.fetch_add(1, std::memory_order_acq_rel);

            switch (ev->type) {
                case StreamEventType::TextDelta: {
                    if (!ev->text.empty()) {
                        impl_->textAccumulator_ += ev->text;
                        impl_->tryExtractToolCall();
                    }
                    break;
                }
                case StreamEventType::Token: {
                    if (!ev->text.empty()) {
                        bridgeLog("[Token] text_len=" + std::to_string(ev->text.size()) + " text=[" + ev->text + "]");
                        impl_->textAccumulator_ += ev->text;
                        impl_->tryExtractToolCall();
                    }
                    break;
                }
                case StreamEventType::ToolRequest: {
                    impl_->toolRequestsSeen_.fetch_add(1, std::memory_order_acq_rel);
                    if (impl_->registry_ && impl_->channel_) {
                        ToolRequest req;
                        req.run_id    = 0;
                        req.action_id = 0;
                        req.surface   = AgentToolSurface::AgentCore;
                        req.tool_id   = std::string(ev->text);
                        req.working_directory = std::filesystem::current_path();
                        ToolContext ctx;
                        ctx.cancelled = [&]() {
                            return impl_->channel_->isCancelRequested();
                        };
                        ToolResult res = impl_->registry_->invoke(std::move(req), ctx);
                        if (res.ok()) {
                            impl_->channel_->publishToolResult(res.stdout_text);
                            impl_->toolResultsSent_.fetch_add(1, std::memory_order_acq_rel);
                        } else {
                            impl_->channel_->publishError(res.stderr_text);
                            impl_->errors_.fetch_add(1, std::memory_order_acq_rel);
                        }
                    }
                    break;
                }
                case StreamEventType::ToolResult: {
                    // Already handled downstream; no-op
                    break;
                }
                case StreamEventType::Error: {
                    impl_->errors_.fetch_add(1, std::memory_order_acq_rel);
                    break;
                }
                case StreamEventType::Completed:
                case StreamEventType::Cancelled: {
                    // Session end; stop pump on next cycle
                    impl_->stopRequested_.store(true, std::memory_order_release);
                    break;
                }
            }
        }
        impl_->running_.store(false, std::memory_order_release);
    });
}

void AgenticModelStreamerBridge::stop() {
    if (!impl_->running_.load(std::memory_order_acquire)) return;
    impl_->stopRequested_.store(true, std::memory_order_release);
    if (impl_->channel_) impl_->channel_->requestCancel();
    if (impl_->pumpThread_.joinable()) impl_->pumpThread_.join();
    impl_->running_.store(false, std::memory_order_release);
}

BridgeCounters AgenticModelStreamerBridge::counters() const {
    BridgeCounters c;
    c.deltasConsumed       = impl_->deltasConsumed_.load(std::memory_order_acquire);
    c.toolRequestsSeen     = impl_->toolRequestsSeen_.load(std::memory_order_acquire);
    c.toolRequestsParsed   = impl_->toolRequestsParsed_.load(std::memory_order_acquire);
    c.authorityCalls       = impl_->authorityCalls_.load(std::memory_order_acquire);
    c.toolExecutions       = impl_->toolExecutions_.load(std::memory_order_acquire);
    c.toolResultsProduced  = impl_->toolResultsProduced_.load(std::memory_order_acquire);
    c.toolResultsSent      = impl_->toolResultsSent_.load(std::memory_order_acquire);
    c.toolResultsInjected  = impl_->toolResultsInjected_.load(std::memory_order_acquire);
    c.continuationsStarted = impl_->continuationsStarted_.load(std::memory_order_acquire);
    c.postToolTokens       = impl_->postToolTokens_.load(std::memory_order_acquire);
    c.errors               = impl_->errors_.load(std::memory_order_acquire);
    c.parseFailures        = impl_->parseFailures_.load(std::memory_order_acquire);
    return c;
}

void AgenticModelStreamerBridge::resetCounters() {
    impl_->deltasConsumed_.store(0, std::memory_order_release);
    impl_->toolRequestsSeen_.store(0, std::memory_order_release);
    impl_->toolRequestsParsed_.store(0, std::memory_order_release);
    impl_->authorityCalls_.store(0, std::memory_order_release);
    impl_->toolExecutions_.store(0, std::memory_order_release);
    impl_->toolResultsProduced_.store(0, std::memory_order_release);
    impl_->toolResultsSent_.store(0, std::memory_order_release);
    impl_->toolResultsInjected_.store(0, std::memory_order_release);
    impl_->continuationsStarted_.store(0, std::memory_order_release);
    impl_->postToolTokens_.store(0, std::memory_order_release);
    impl_->errors_.store(0, std::memory_order_release);
    impl_->parseFailures_.store(0, std::memory_order_release);
}

bool AgenticModelStreamerBridge::isRunning() const noexcept {
    return impl_->running_.load(std::memory_order_acquire);
}

std::string AgenticModelStreamerBridge::accumulatedText() const noexcept {
    std::lock_guard<std::mutex> lk(impl_->diagMu_);
    return impl_->textAccumulator_;
}

std::string AgenticModelStreamerBridge::lastToolRequestRaw() const noexcept {
    std::lock_guard<std::mutex> lk(impl_->diagMu_);
    return impl_->lastToolRequestRaw_;
}

std::string AgenticModelStreamerBridge::lastToolName() const noexcept {
    std::lock_guard<std::mutex> lk(impl_->diagMu_);
    return impl_->lastToolName_;
}

std::string AgenticModelStreamerBridge::lastToolResultText() const noexcept {
    std::lock_guard<std::mutex> lk(impl_->diagMu_);
    return impl_->lastToolResultText_;
}

void AgenticModelStreamerBridge::clearAccumulatedText() {
    std::lock_guard<std::mutex> lk(impl_->diagMu_);
    impl_->textAccumulator_.clear();
    impl_->lastToolRequestRaw_.clear();
    impl_->lastToolName_.clear();
    impl_->lastToolResultText_.clear();
}

} // namespace RawrXD::Agentic
