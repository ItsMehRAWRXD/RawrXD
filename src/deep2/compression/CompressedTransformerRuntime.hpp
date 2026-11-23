#pragma once
// Small, architecture-explicit decoder-only transformer runtime backed by
// CompressedGGUFModel. Intended as an executable integration contract for
// lazy compressed weights: embeddings/norms are range-read and every matrix
// projection uses compressed block-backed matvec. No full decoded model copy.
#include "CompressedGGUFModel.hpp"
#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace rawrxd::compression {

class CompressedTransformerRuntime {
public:
    struct Config {
        std::size_t hidden = 0;
        std::size_t intermediate = 0;
        std::size_t vocabulary = 0;
        std::size_t layers = 1;
        std::size_t heads = 1;
        // Zero preserves multi-head attention; smaller values enable GQA.
        std::size_t kv_heads = 0;
        std::size_t head_dim = 0;
        std::size_t max_context = 4096;
        std::size_t max_kv_cache_bytes = 1024ull * 1024ull * 1024ull;
        float rms_epsilon = 1.0e-5f;
        float rope_theta = 10000.0f;
        int32_t eos_token = -1;
    };

    explicit CompressedTransformerRuntime(const CompressedGGUFModel& model,
                                           Config config)
        : model_(model), config_(config) {
        if (!model_.loaded()) throw std::invalid_argument("compressed transformer requires a loaded model");
        if (!config_.hidden || !config_.intermediate || !config_.vocabulary ||
            !config_.layers || !config_.heads || !config_.head_dim ||
            config_.heads > std::numeric_limits<std::size_t>::max() / config_.head_dim ||
            config_.heads * config_.head_dim != config_.hidden ||
            (config_.head_dim & 1u) != 0 || !config_.max_context ||
            !config_.max_kv_cache_bytes ||
            !(config_.rms_epsilon > 0.0f) || !(config_.rope_theta > 0.0f) ||
            (config_.eos_token >= 0 &&
             static_cast<std::size_t>(config_.eos_token) >= config_.vocabulary))
            throw std::invalid_argument("invalid decoder-only transformer geometry or memory budget");
        if (config_.kv_heads == 0) config_.kv_heads = config_.heads;
        if (config_.kv_heads > config_.heads ||
            config_.heads % config_.kv_heads != 0)
            throw std::invalid_argument("KV head count must evenly divide query heads");
        const std::size_t kvDim = config_.kv_heads * config_.head_dim;
        validateTensor("token_embd.weight", config_.hidden, config_.vocabulary);
        validateTensor("output_norm.weight", config_.hidden, 1);
        validateTensor("output.weight", config_.hidden, config_.vocabulary);
        for (std::size_t l = 0; l < config_.layers; ++l) {
            const auto p = layerPrefix(l);
            validateTensor(p + "attn_norm.weight", config_.hidden, 1);
            validateTensor(p + "attn_q.weight", config_.hidden, config_.hidden);
            validateTensor(p + "attn_k.weight", config_.hidden, kvDim);
            validateTensor(p + "attn_v.weight", config_.hidden, kvDim);
            validateTensor(p + "attn_output.weight", config_.hidden, config_.hidden);
            validateTensor(p + "ffn_norm.weight", config_.hidden, 1);
            validateTensor(p + "ffn_gate.weight", config_.hidden, config_.intermediate);
            validateTensor(p + "ffn_up.weight", config_.hidden, config_.intermediate);
            validateTensor(p + "ffn_down.weight", config_.intermediate, config_.hidden);
        }
    }

    // Greedy autoregressive decode. Each token runs embedding -> RMSNorm ->
    // Q/K/V -> RoPE -> causal attention -> residual -> SwiGLU -> residual ->
    // final RMSNorm -> vocabulary projection. KV state is request-local.
    std::vector<int32_t> generate(const std::vector<int32_t>& prompt,
                                 std::size_t max_new_tokens) const {
        if (prompt.empty()) throw std::invalid_argument("transformer prompt cannot be empty");
        if (prompt.size() > config_.max_context ||
            max_new_tokens > config_.max_context - prompt.size())
            throw std::out_of_range("prompt plus generation exceeds transformer context");
        if (max_new_tokens == 0) return {};
        // The last emitted token is never forwarded. Reserve KV memory only
        // for prompt tokens and the preceding generated tokens.
        const std::size_t totalTokens = prompt.size() + max_new_tokens - 1u;
        constexpr std::size_t bytesPerScalar = sizeof(float);
        const std::size_t kvHeads = config_.kv_heads;
        const std::size_t kvDim = kvHeads * config_.head_dim;
        if (kvDim > std::numeric_limits<std::size_t>::max() /
                        (2u * bytesPerScalar) ||
            totalTokens > std::numeric_limits<std::size_t>::max() /
                              (kvDim * 2u * bytesPerScalar) ||
            config_.layers > std::numeric_limits<std::size_t>::max() /
                                 (totalTokens * kvDim * 2u * bytesPerScalar))
            throw std::overflow_error("transformer KV cache geometry overflow");
        // GQA stores one K/V vector per KV head, not per query head.
        const std::size_t kvBytes = config_.layers * totalTokens *
                                    kvDim * 2u * bytesPerScalar;
        if (kvBytes > config_.max_kv_cache_bytes)
            throw std::length_error("transformer KV cache exceeds configured byte budget");
        std::vector<std::vector<std::vector<float>>> keys(
            config_.layers), values(config_.layers);
        for (std::size_t layer = 0; layer < config_.layers; ++layer) {
            keys[layer].reserve(totalTokens);
            values[layer].reserve(totalTokens);
        }
        std::vector<float> logits;
        std::size_t position = 0;
        for (const auto token : prompt) {
            if (token < 0 || static_cast<std::size_t>(token) >= config_.vocabulary)
                throw std::out_of_range("prompt token is outside vocabulary");
            logits = forwardToken(token, position++, keys, values);
        }
        std::vector<int32_t> generated;
        generated.reserve(max_new_tokens);
        for (std::size_t n = 0; n < max_new_tokens; ++n) {
            const auto next = static_cast<int32_t>(
                std::distance(logits.begin(), std::max_element(logits.begin(), logits.end())));
            generated.push_back(next);
            if (next == config_.eos_token) break;
            // The final emitted token needs no forward pass: avoid an
            // unnecessary KV insertion and a context-boundary overrun.
            if (n + 1 < max_new_tokens)
                logits = forwardToken(next, position++, keys, values);
        }
        return generated;
    }

private:
    static std::string layerPrefix(std::size_t layer) {
        return "blk." + std::to_string(layer) + ".";
    }

    void validateTensor(const std::string& name, std::size_t cols,
                        std::size_t rows) const {
        if (!model_.contains(name))
            throw std::invalid_argument("compressed transformer missing tensor: " + name);
        const std::uint32_t type = model_.tensorType(name);
        const std::size_t scalar =
            (type == GGML_TYPE_F16 || type == GGML_TYPE_BF16) ? 2u :
            type == GGML_TYPE_F32 ? 4u : 0u;
        if (!scalar) throw std::invalid_argument("unsupported transformer tensor type: " + name);
        if (cols && rows > std::numeric_limits<std::size_t>::max() / cols)
            throw std::overflow_error("transformer tensor geometry overflow: " + name);
        if (cols * rows > std::numeric_limits<std::size_t>::max() / scalar ||
            model_.tensorBytes(name) != cols * rows * scalar)
            throw std::invalid_argument("transformer tensor byte geometry mismatch: " + name);
    }

    static float bfloat16ToFloat(std::uint16_t h) noexcept {
        const std::uint32_t bits = std::uint32_t(h) << 16;
        float value = 0.0f;
        std::memcpy(&value, &bits, sizeof(value));
        return value;
    }

    static float halfToFloat(std::uint16_t h) noexcept {
        const std::uint32_t sign = std::uint32_t(h & 0x8000u) << 16;
        std::uint32_t exp = (h >> 10) & 0x1fu;
        std::uint32_t mant = h & 0x3ffu;
        std::uint32_t bits = 0;
        if (exp == 0) {
            if (!mant) bits = sign;
            else {
                int e = -14;
                while ((mant & 0x400u) == 0) { mant <<= 1; --e; }
                mant &= 0x3ffu;
                bits = sign | (std::uint32_t(e + 127) << 23) | (mant << 13);
            }
        } else if (exp == 31) {
            bits = sign | 0x7f800000u | (mant << 13);
        } else {
            bits = sign | ((exp + 112u) << 23) | (mant << 13);
        }
        float value = 0.0f;
        std::memcpy(&value, &bits, sizeof(value));
        return value;
    }

    std::vector<float> readVector(const std::string& name,
                                  std::size_t count) const {
        const auto type = model_.tensorType(name);
        const std::size_t scalar =
            (type == GGML_TYPE_F16 || type == GGML_TYPE_BF16) ? 2u : 4u;
        if (count > std::numeric_limits<std::size_t>::max() / scalar)
            throw std::overflow_error("compressed vector byte size overflow");
        std::vector<std::uint8_t> bytes(count * scalar);
        std::string error;
        if (!model_.readTensorRange(name, 0, bytes.data(), bytes.size(), &error))
            throw std::runtime_error("compressed vector read failed for " + name + ": " + error);
        std::vector<float> result(count);
        for (std::size_t i = 0; i < count; ++i) {
            if (type == GGML_TYPE_F16 || type == GGML_TYPE_BF16) {
                const std::uint16_t h = std::uint16_t(bytes[2*i]) |
                                        (std::uint16_t(bytes[2*i+1]) << 8);
                result[i] = type == GGML_TYPE_F16 ? halfToFloat(h) : bfloat16ToFloat(h);
            } else {
                std::memcpy(&result[i], bytes.data() + 4*i, sizeof(float));
            }
        }
        return result;
    }

    void rmsNorm(std::vector<float>& x, const std::string& weightName) const {
        const auto w = readVector(weightName, config_.hidden);
        double sum = 0.0;
        for (float v : x) sum += static_cast<double>(v) * v;
        const float inv = 1.0f / std::sqrt(static_cast<float>(sum / x.size()) +
                                           config_.rms_epsilon);
        for (std::size_t i = 0; i < x.size(); ++i) x[i] = x[i] * inv * w[i];
    }

    void project(const std::string& name, const std::vector<float>& input,
                 std::vector<float>& output, std::size_t rows) const {
        output.resize(rows);
        std::string error;
        if (!model_.matvec(name, input.data(), output.data(), 64u * 1024u, &error))
            throw std::runtime_error("compressed projection failed for " + name + ": " + error);
    }

    void applyRope(std::vector<float>& x, std::size_t position,
                   std::size_t headCount) const {
        if (x.size() != headCount * config_.head_dim)
            throw std::invalid_argument("RoPE vector does not match head geometry");
        for (std::size_t h = 0; h < headCount; ++h) {
            const std::size_t base = h * config_.head_dim;
            for (std::size_t d = 0; d < config_.head_dim; d += 2) {
                const float frequency = 1.0f / std::pow(
                    config_.rope_theta, static_cast<float>(d) /
                    static_cast<float>(config_.head_dim));
                const float angle = static_cast<float>(position) * frequency;
                const float c = std::cos(angle), s = std::sin(angle);
                const float a = x[base + d], b = x[base + d + 1];
                x[base + d] = a * c - b * s;
                x[base + d + 1] = a * s + b * c;
            }
        }
    }

    std::vector<float> forwardToken(
        int32_t token, std::size_t position,
        std::vector<std::vector<std::vector<float>>>& keys,
        std::vector<std::vector<std::vector<float>>>& values) const {
        std::vector<float> hidden(config_.hidden);
        const auto embeddingType = model_.tensorType("token_embd.weight");
        const std::size_t scalar =
            (embeddingType == GGML_TYPE_F16 || embeddingType == GGML_TYPE_BF16) ? 2u : 4u;
        if (config_.hidden > std::numeric_limits<std::size_t>::max() / scalar)
            throw std::overflow_error("compressed embedding row size overflow");
        std::vector<std::uint8_t> row(config_.hidden * scalar);
        const std::size_t rowBytes = row.size();
        if (static_cast<std::size_t>(token) >
            std::numeric_limits<std::size_t>::max() / rowBytes)
            throw std::overflow_error("compressed embedding offset overflow");
        std::string error;
        if (!model_.readTensorRange("token_embd.weight",
                static_cast<std::size_t>(token) * rowBytes, row.data(), rowBytes, &error))
            throw std::runtime_error("compressed embedding read failed: " + error);
        for (std::size_t i = 0; i < config_.hidden; ++i) {
            if (embeddingType == GGML_TYPE_F16 || embeddingType == GGML_TYPE_BF16) {
                const std::uint16_t h = std::uint16_t(row[2*i]) |
                                        (std::uint16_t(row[2*i+1]) << 8);
                hidden[i] = embeddingType == GGML_TYPE_F16
                    ? halfToFloat(h) : bfloat16ToFloat(h);
            } else std::memcpy(&hidden[i], row.data() + 4*i, sizeof(float));
        }

        for (std::size_t layer = 0; layer < config_.layers; ++layer) {
            const auto p = layerPrefix(layer);
            auto residual = hidden;
            auto normed = hidden;
            rmsNorm(normed, p + "attn_norm.weight");
            std::vector<float> q, k, v;
            project(p + "attn_q.weight", normed, q, config_.hidden);
            const std::size_t kvDim = config_.kv_heads * config_.head_dim;
            project(p + "attn_k.weight", normed, k, kvDim);
            project(p + "attn_v.weight", normed, v, kvDim);
            applyRope(q, position, config_.heads);
            applyRope(k, position, config_.kv_heads);
            keys[layer].push_back(k);
            values[layer].push_back(v);

            std::vector<float> attended(config_.hidden, 0.0f);
            const std::size_t queryHeadsPerKv = config_.heads / config_.kv_heads;
            for (std::size_t head = 0; head < config_.heads; ++head) {
                const std::size_t queryBase = head * config_.head_dim;
                const std::size_t kvHead = head / queryHeadsPerKv;
                const std::size_t kvBase = kvHead * config_.head_dim;
                std::vector<float> scores(keys[layer].size());
                float maximum = -std::numeric_limits<float>::infinity();
                for (std::size_t t = 0; t < keys[layer].size(); ++t) {
                    double dot = 0.0;
                    for (std::size_t d = 0; d < config_.head_dim; ++d)
                        dot += static_cast<double>(q[queryBase+d]) *
                               keys[layer][t][kvBase+d];
                    scores[t] = static_cast<float>(dot / std::sqrt(
                        static_cast<float>(config_.head_dim)));
                    maximum = std::max(maximum, scores[t]);
                }
                double denom = 0.0;
                for (float& score : scores) { score = std::exp(score - maximum); denom += score; }
                for (std::size_t t = 0; t < scores.size(); ++t) {
                    const float probability = static_cast<float>(scores[t] / denom);
                    for (std::size_t d = 0; d < config_.head_dim; ++d)
                        attended[queryBase+d] += probability * values[layer][t][kvBase+d];
                }
            }
            std::vector<float> attnOut;
            project(p + "attn_output.weight", attended, attnOut, config_.hidden);
            for (std::size_t i = 0; i < config_.hidden; ++i) hidden[i] = residual[i] + attnOut[i];

            residual = hidden;
            normed = hidden;
            rmsNorm(normed, p + "ffn_norm.weight");
            std::vector<float> gate, up;
            project(p + "ffn_gate.weight", normed, gate, config_.intermediate);
            project(p + "ffn_up.weight", normed, up, config_.intermediate);
            for (std::size_t i = 0; i < gate.size(); ++i) {
                const float sigmoid = 1.0f / (1.0f + std::exp(-gate[i]));
                gate[i] = gate[i] * sigmoid * up[i];
            }
            std::vector<float> down;
            project(p + "ffn_down.weight", gate, down, config_.hidden);
            for (std::size_t i = 0; i < config_.hidden; ++i) hidden[i] = residual[i] + down[i];
        }

        rmsNorm(hidden, "output_norm.weight");
        std::vector<float> logits;
        project("output.weight", hidden, logits, config_.vocabulary);
        return logits;
    }

    const CompressedGGUFModel& model_;
    Config config_;
};

} // namespace rawrxd::compression
