#pragma once
// RawrXD Deep2 — dependency-free, header-only, C++17 session steering.
// Apply only to a COPY of raw logits. Never use steered logits for parity evidence.
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace rawrxd::deep2 {
struct SteeringConfig {
    bool enabled = false;
    bool certification_mode = false;
    float temperature = 1.0f; // 0 => deterministic argmax (not applied as a logit transform)
    float repetition_penalty = 1.0f; // >= 1
    std::unordered_map<uint32_t, float> logit_bias;
    std::unordered_set<uint32_t> blocked_tokens;
    std::unordered_set<uint32_t> allowed_tokens; // empty => no allowlist
    size_t history_window = 128;
};

class SteeringController final {
    SteeringConfig cfg_;
    std::vector<uint32_t> history_;
public:
    void Configure(const SteeringConfig& cfg) {
        if (!std::isfinite(cfg.temperature) || cfg.temperature < 0.0f ||
            !std::isfinite(cfg.repetition_penalty) || cfg.repetition_penalty < 1.0f)
            throw std::invalid_argument("invalid steering temperature or repetition penalty");
        for (const auto& p : cfg.logit_bias)
            if (!std::isfinite(p.second)) throw std::invalid_argument("nonfinite logit bias");
        cfg_ = cfg;
    }
    const SteeringConfig& Config() const noexcept { return cfg_; }
    void Reset() noexcept { history_.clear(); }
    void Observe(uint32_t token) {
        if (!cfg_.history_window) return;
        history_.push_back(token);
        if (history_.size() > cfg_.history_window)
            history_.erase(history_.begin(), history_.begin() + (history_.size() - cfg_.history_window));
    }
    bool Active() const noexcept { return cfg_.enabled && !cfg_.certification_mode; }

    // Mutates caller-owned working logits only; caller must retain original raw logits.
    // Returns false if no selectable token remains. Does not sample or execute tools.
    bool Apply(std::vector<float>& logits) const {
        if (!Active()) return !logits.empty();
        if (logits.empty()) return false;
        const float neg_inf = -std::numeric_limits<float>::infinity();
        for (size_t i = 0; i < logits.size(); ++i) {
            if (!std::isfinite(logits[i])) return false;
            if ((!cfg_.allowed_tokens.empty() && !cfg_.allowed_tokens.count(static_cast<uint32_t>(i))) ||
                cfg_.blocked_tokens.count(static_cast<uint32_t>(i))) {
                logits[i] = neg_inf;
                continue;
            }
            auto bias = cfg_.logit_bias.find(static_cast<uint32_t>(i));
            if (bias != cfg_.logit_bias.end()) logits[i] += bias->second;
        }
        if (cfg_.repetition_penalty != 1.0f) {
            std::unordered_set<uint32_t> unique(history_.begin(), history_.end());
            for (uint32_t token : unique) {
                if (token >= logits.size() || !std::isfinite(logits[token])) continue;
                logits[token] = logits[token] < 0.0f
                    ? logits[token] * cfg_.repetition_penalty
                    : logits[token] / cfg_.repetition_penalty;
            }
        }
        // Temperature zero selects greedy decoding; for >0 scale logits.
        if (cfg_.temperature > 0.0f && cfg_.temperature != 1.0f)
            for (float& x : logits) if (std::isfinite(x)) x /= cfg_.temperature;
        bool selectable = false;
        for (float x : logits) {
            if (std::isnan(x) || x == std::numeric_limits<float>::infinity()) return false;
            if (std::isfinite(x)) selectable = true;
        }
        return selectable;
    }

    static uint32_t Argmax(const std::vector<float>& logits) {
        uint32_t best = 0;
        float value = -std::numeric_limits<float>::infinity();
        bool found = false;
        for (size_t i = 0; i < logits.size(); ++i) {
            if (std::isfinite(logits[i]) && (!found || logits[i] > value)) {
                value = logits[i]; best = static_cast<uint32_t>(i); found = true;
            }
        }
        if (!found) throw std::runtime_error("no selectable tokens");
        return best;
    }
};
} // namespace rawrxd::deep2
