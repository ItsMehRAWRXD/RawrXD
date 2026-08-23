#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <functional>
#include <unordered_map>
#include <algorithm>
#include <limits>

namespace RawrXD {

struct StreamToken {
    uint32_t id = 0;
    std::string text;
    float score = 0.0f;
};

struct StreamConfig {
    uint32_t max_tokens = 128;
    float temperature = 0.0f;       // 0 = greedy
    uint32_t repeat_window = 64;
    float repeat_penalty = 1.05f;
};

class TokenStreamDecoder {
public:
    using EmitFn =
        std::function<bool(const StreamToken&)>;

    TokenStreamDecoder() = default;

    void Reset() {
        history_.clear();
        emitted_ = 0;
        stopped_ = false;
    }

    void SetEOS(uint32_t eos) {
        eos_id_ = eos;
        has_eos_ = true;
    }

    void SetConfig(const StreamConfig& cfg) {
        cfg_ = cfg;

        if (cfg_.max_tokens == 0)
            cfg_.max_tokens = 1;

        if (cfg_.repeat_window == 0)
            cfg_.repeat_window = 1;

        if (cfg_.repeat_penalty < 1.0f)
            cfg_.repeat_penalty = 1.0f;
    }

    bool Stopped() const noexcept {
        return stopped_;
    }

    uint32_t Emitted() const noexcept {
        return emitted_;
    }

    const std::vector<uint32_t>& History() const noexcept {
        return history_;
    }

    bool Consume(
        const float* logits,
        size_t vocab_size,
        std::string_view token_text,
        const EmitFn& emit)
    {
        if (stopped_)
            return false;

        if (!logits || vocab_size == 0 || !emit)
            return false;

        if (emitted_ >= cfg_.max_tokens) {
            stopped_ = true;
            return true;
        }

        const uint32_t id =
            SelectToken(logits, vocab_size);

        const float score = logits[id];

        history_.push_back(id);

        StreamToken token;
        token.id = id;
        token.score = score;
        token.text.assign(token_text.data(), token_text.size());

        ++emitted_;

        if (!emit(token)) {
            stopped_ = true;
            return true;
        }

        if (has_eos_ && id == eos_id_) {
            stopped_ = true;
            return true;
        }

        if (emitted_ >= cfg_.max_tokens) {
            stopped_ = true;
        }

        return true;
    }

private:
    uint32_t SelectToken(
        const float* logits,
        size_t vocab_size) const
    {
        size_t best = 0;
        float best_score =
            PenalizedScore(logits[0], 0);

        for (size_t i = 1; i < vocab_size; ++i) {
            const float score =
                PenalizedScore(
                    logits[i],
                    static_cast<uint32_t>(i));

            if (score > best_score) {
                best_score = score;
                best = i;
            }
        }

        return static_cast<uint32_t>(best);
    }

    float PenalizedScore(
        float value,
        uint32_t id) const
    {
        if (cfg_.temperature > 0.0f) {
            value /= cfg_.temperature;
        }

        if (cfg_.repeat_penalty <= 1.0f)
            return value;

        const size_t begin =
            history_.size() > cfg_.repeat_window
                ? history_.size() - cfg_.repeat_window
                : 0;

        for (size_t i = begin; i < history_.size(); ++i) {
            if (history_[i] == id) {
                if (value >= 0.0f)
                    return value / cfg_.repeat_penalty;

                return value * cfg_.repeat_penalty;
            }
        }

        return value;
    }

private:
    StreamConfig cfg_{};

    std::vector<uint32_t> history_;

    uint32_t eos_id_ = 0;
    uint32_t emitted_ = 0;

    bool has_eos_ = false;
    bool stopped_ = false;
};

} // namespace RawrXD
