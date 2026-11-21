// strata_chat.hpp -- RAWRXD_STRATA_CHAT_001
//
// Reusable, request-scoped Strata chat execution extracted from
// tools/deep2_strata_chat.cpp so the IDE and CLI can share one implementation.
//
// Strata is a RuntimeGraphExecutor execution mode (expert residency + optional
// int8 KV), NOT a Deep2Engine feature. Each session owns its token positions,
// cancellation and completion state so a GUI adapter can call it per request.

#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "StrataExpertResidency.hpp"
#include "quant_dot_dispatch.hpp"
#include "runtime_graph_executor.hpp"
#include "universal_gguf.hpp"

namespace rawrxd::deep2 {

struct StrataChatOptions {
    bool gpu = true;
    int device = 0;
    bool expertTracking = true;   // SetStrataExpertTracking
    int cachePolicy = 0;          // 0 = LRU
    int64_t weightCacheBudget = -1;  // bytes; <0 = runtime default
};

struct StrataChatStats {
    bool ok = false;
    size_t promptTokens = 0;
    size_t generatedTokens = 0;
    uint64_t gpuCalls = 0;
    uint64_t cpuCalls = 0;
    size_t nonFiniteLogits = 0;
    uint64_t expertObservations = 0;
    uint64_t expertHits = 0;
    uint64_t expertEvictions = 0;
    double bindMs = 0;
    double prefillMs = 0;
    double decodeMs = 0;
    std::string error;
};

class StrataChatSession {
public:
    bool Open(const std::string& gguf, const StrataChatOptions& opts)
    {
        opts_ = opts;
        const auto rep = RawrXD::Deep2::Universal::Ingest(gguf, false);
        if (!rep.ok) { stats_.error = "ingest: " + rep.error; return false; }
        executor_ = std::make_unique<::RawrXD::Deep2::RuntimeGraph::Executor>();
        executor_->SetForceCpu(!opts_.gpu);
        if (opts_.device >= 0) ::RawrXD::Deep2::QuantDot::SetPreferredDevice(opts_.device);
        if (opts_.expertTracking) {
            executor_->SetStrataExpertTracking(true);
            executor_->SetStrataCachePolicy(opts_.cachePolicy);
        }
        if (opts_.weightCacheBudget >= 0)
            ::RawrXD::Deep2::QuantDot::SetWeightCacheBudget(opts_.weightCacheBudget);
        if (!executor_->Bind(rep)) { stats_.error = "bind failed"; return false; }
        return true;
    }

    bool Prefill(const std::vector<uint32_t>& tokens)
    {
        if (!executor_) return false;
        const auto t0 = std::chrono::steady_clock::now();
        for (size_t i = 0; i < tokens.size(); ++i) {
            if (!executor_->ExecuteToken(tokens[i], i)) return false;
        }
        stats_.prefillMs = ElapsedMs(t0);
        stats_.promptTokens = tokens.size();
        return true;
    }

    // One decode step: sample greedily from the current logits, then advance.
    bool Step(uint32_t& nextToken, std::string* tokenText = nullptr)
    {
        if (!executor_) return false;
        const auto& logits = executor_->Logits();
        if (logits.empty()) return false;
        uint64_t best = 0;
        for (size_t i = 1; i < logits.size(); ++i)
            if (logits[i] > logits[best]) best = i;
        nextToken = (uint32_t)best;
        if (!executor_->ExecuteToken(nextToken, stats_.promptTokens + stats_.generatedTokens))
            return false;
        ++stats_.generatedTokens;
        return true;
    }

    const StrataChatStats& Stats() const { return stats_; }
    void Finalise()
    {
        if (!executor_) return;
        const auto& s = executor_->Stats();
        stats_.gpuCalls = s.gpu_calls;
        stats_.cpuCalls = s.cpu_calls;
        stats_.nonFiniteLogits = executor_->NonFiniteLogits();
        const auto l = executor_->StrataExpertSummary();
        stats_.expertObservations = l.observations;
        stats_.expertHits = l.hits;
        stats_.expertEvictions = l.evictions;
        stats_.ok = stats_.error.empty();
    }

private:
    static double ElapsedMs(std::chrono::steady_clock::time_point t0)
    {
        return std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - t0).count();
    }

    StrataChatOptions opts_{};
    std::unique_ptr<::RawrXD::Deep2::RuntimeGraph::Executor> executor_;
    StrataChatStats stats_{};
};

}  // namespace rawrxd::deep2