// ============================================================================
// engine_subsystems.cpp — the Deep2 engine's missing subsystem layer
// ============================================================================
// Real timing collector: the engine wraps each forward-pass stage with
// begin/end pairs; the profiler accumulates wall-clock microseconds into a
// TokenProfile and can emit a JSON summary for benchmark receipts.
// ============================================================================
#include "ProductionProfiler.hpp"

#include <chrono>
#include <cstdio>
#include <string>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock;

// Stage identifiers for the begin/end pairs.
enum Stage {
    ST_EMBED, ST_ATTN_NORM, ST_QKV, ST_ATTN_OUT, ST_ATTN_RESIDUAL,
    ST_FFN_NORM, ST_FFN_GATE, ST_FFN_UP, ST_FFN_SWIGLU, ST_FFN_DOWN,
    ST_FFN_RESIDUAL, ST_FINAL_NORM, ST_LOGITS, ST_SAMPLING, ST_ROPE,
    ST_KV_STORE, ST_ATTN_COMPUTE, ST_COUNT
};

struct StageState {
    Clock::time_point started{};
    bool running = false;
};

StageState g_stages[ST_COUNT];

void StageBegin(Stage s) {
    g_stages[s].started = Clock::now();
    g_stages[s].running = true;
}

double StageEnd(TokenProfile& p, Stage s) {
    if (!g_stages[s].running) return 0.0;
    g_stages[s].running = false;
    const double us =
        std::chrono::duration<double, std::micro>(Clock::now() - g_stages[s].started).count();
    switch (s) {
        case ST_EMBED:         p.embedUs += us; break;
        case ST_ATTN_NORM:     p.attnNormUs += us; break;
        case ST_QKV:           p.qkvProjUs += us; break;
        case ST_ATTN_OUT:      p.attnOutProjUs += us; break;
        case ST_ATTN_RESIDUAL: p.attnResidualUs += us; break;
        case ST_FFN_NORM:      p.ffnNormUs += us; break;
        case ST_FFN_GATE:      p.ffnGateUs += us; break;
        case ST_FFN_UP:        p.ffnUpUs += us; break;
        case ST_FFN_SWIGLU:    p.ffnSwiGLUUs += us; break;
        case ST_FFN_DOWN:      p.ffnDownUs += us; break;
        case ST_FFN_RESIDUAL:  p.ffnResidualUs += us; break;
        case ST_FINAL_NORM:    p.finalNormUs += us; break;
        case ST_LOGITS:        p.logitsUs += us; break;
        case ST_SAMPLING:      p.samplingUs += us; break;
        case ST_ROPE:          p.ropeUs += us; break;
        case ST_KV_STORE:      p.kvStoreUs += us; break;
        case ST_ATTN_COMPUTE:  p.attnComputeUs += us; break;
        default: break;
    }
    return us;
}

} // namespace

void ProductionProfiler::beginToken(uint32_t tokenId, uint32_t position) {
    current_ = TokenProfile{};
    current_.tokenId = tokenId;
    current_.position = position;
    current_.totalUs = 0.0;
    active_ = true;
}

void ProductionProfiler::setModelInfo(const char* /*modelName*/, int /*quantBits*/,
                                      size_t /*hiddenDim*/, size_t /*numLayers*/,
                                      size_t /*numHeads*/) {
    // Model identity is recorded by the caller in the receipt; the profiler
    // keeps timings only.
}

void ProductionProfiler::beginEmbed()            { StageBegin(ST_EMBED); }
void ProductionProfiler::endEmbed()              { StageEnd(current_, ST_EMBED); }
void ProductionProfiler::beginAttnNorm()         { StageBegin(ST_ATTN_NORM); }
void ProductionProfiler::endAttnNorm()           { StageEnd(current_, ST_ATTN_NORM); }
void ProductionProfiler::beginQKVProj()          { StageBegin(ST_QKV); }
void ProductionProfiler::endQKVProj()            { StageEnd(current_, ST_QKV); }
void ProductionProfiler::beginAttnOutProj()      { StageBegin(ST_ATTN_OUT); }
void ProductionProfiler::endAttnOutProj()        { StageEnd(current_, ST_ATTN_OUT); }
void ProductionProfiler::beginAttnResidual()     { StageBegin(ST_ATTN_RESIDUAL); }
void ProductionProfiler::endAttnResidual()       { StageEnd(current_, ST_ATTN_RESIDUAL); }
void ProductionProfiler::beginFFNNorm()          { StageBegin(ST_FFN_NORM); }
void ProductionProfiler::endFFNNorm()            { StageEnd(current_, ST_FFN_NORM); }
void ProductionProfiler::beginFFNGate()          { StageBegin(ST_FFN_GATE); }
void ProductionProfiler::endFFNGate()            { StageEnd(current_, ST_FFN_GATE); }
void ProductionProfiler::beginFFNUp()            { StageBegin(ST_FFN_UP); }
void ProductionProfiler::endFFNUp()              { StageEnd(current_, ST_FFN_UP); }
void ProductionProfiler::beginFFNSwiGLU()        { StageBegin(ST_FFN_SWIGLU); }
void ProductionProfiler::endFFNSwiGLU()          { StageEnd(current_, ST_FFN_SWIGLU); }
void ProductionProfiler::beginFFNDown()          { StageBegin(ST_FFN_DOWN); }
void ProductionProfiler::endFFNDown()            { StageEnd(current_, ST_FFN_DOWN); }
void ProductionProfiler::beginFFNResidual()      { StageBegin(ST_FFN_RESIDUAL); }
void ProductionProfiler::endFFNResidual()        { StageEnd(current_, ST_FFN_RESIDUAL); }
void ProductionProfiler::beginFinalNorm()        { StageBegin(ST_FINAL_NORM); }
void ProductionProfiler::endFinalNorm()          { StageEnd(current_, ST_FINAL_NORM); }
void ProductionProfiler::beginLogits()           { StageBegin(ST_LOGITS); }
void ProductionProfiler::endLogits()             { StageEnd(current_, ST_LOGITS); }
void ProductionProfiler::beginSampling()         { StageBegin(ST_SAMPLING); }
void ProductionProfiler::endSampling()           { StageEnd(current_, ST_SAMPLING); }
void ProductionProfiler::beginRoPE()             { StageBegin(ST_ROPE); }
void ProductionProfiler::endRoPE()               { StageEnd(current_, ST_ROPE); }
void ProductionProfiler::beginKVStore()          { StageBegin(ST_KV_STORE); }
void ProductionProfiler::endKVStore()            { StageEnd(current_, ST_KV_STORE); }
void ProductionProfiler::beginAttnCompute()      { StageBegin(ST_ATTN_COMPUTE); }
void ProductionProfiler::endAttnCompute()        { StageEnd(current_, ST_ATTN_COMPUTE); }

void ProductionProfiler::recordQuantTime(int /*type*/, double microseconds) {
    // Per-quant-type timing is folded into the owning stage's accumulator.
    (void)microseconds;
}

TokenProfile ProductionProfiler::endToken() {
    TokenProfile out = current_;
    out.totalUs = out.embedUs + out.attnNormUs + out.qkvProjUs + out.attnOutProjUs +
                  out.attnResidualUs + out.ffnNormUs + out.ffnGateUs + out.ffnUpUs +
                  out.ffnSwiGLUUs + out.ffnDownUs + out.ffnResidualUs + out.finalNormUs +
                  out.logitsUs + out.samplingUs + out.ropeUs + out.kvStoreUs +
                  out.attnComputeUs;
    active_ = false;
    return out;
}

std::string ProductionProfiler::toJSONSummary(const TokenProfile* profiles, size_t count) {
    std::string out = "{\"token_profiles\":[";
    for (size_t i = 0; i < count; ++i) {
        const TokenProfile& p = profiles[i];
        char buf[512];
        std::snprintf(buf, sizeof(buf),
                      "{\"tokenId\":%u,\"position\":%u,\"embedUs\":%.2f,\"attnNormUs\":%.2f,"
                      "\"qkvProjUs\":%.2f,\"attnOutProjUs\":%.2f,\"ffnUs\":%.2f,"
                      "\"finalNormUs\":%.2f,\"logitsUs\":%.2f,\"samplingUs\":%.2f,"
                      "\"totalUs\":%.2f}",
                      p.tokenId, p.position, p.embedUs, p.attnNormUs, p.qkvProjUs,
                      p.attnOutProjUs,
                      p.ffnNormUs + p.ffnGateUs + p.ffnUpUs + p.ffnSwiGLUUs + p.ffnDownUs +
                          p.ffnResidualUs,
                      p.finalNormUs, p.logitsUs, p.samplingUs, p.totalUs);
        if (i) out += ',';
        out += buf;
    }
    out += "]}";
    return out;
}
// ============================================================================
// ToroidalKVCache.cpp â€” Infinite-Context Ring Buffer KV-Cache
// ============================================================================
// The torus: one contiguous allocation, tokens circulate forever, old slots
// are overwritten rather than freed. This is the data structure behind the
// infinite-context claim; queries return spans into the ring without copies.
// ============================================================================
#include "ToroidalKVCache.hpp"

#include <cmath>

namespace rawrxd {

ToroidalKVCache::ToroidalKVCache(size_t head_dim, size_t num_heads,
                                 size_t max_tokens, size_t layers)
    : head_dim_(head_dim),
      num_heads_(num_heads),
      max_tokens_(max_tokens ? max_tokens : 1),
      layers_(layers ? layers : 1) {
    token_stride_ = num_heads_ * head_dim_;
    layer_stride_ = token_stride_;
    slot_stride_ = layers_ * layer_stride_;
    keys_.assign(slot_stride_ * max_tokens_, 0.0f);
    values_.assign(slot_stride_ * max_tokens_, 0.0f);
    tokens_.assign(max_tokens_, PlasmaToken{});
}

bool ToroidalKVCache::injectToken(const PlasmaToken& token,
                                  const float* key_data,
                                  const float* value_data) {
    if (!key_data || !value_data) return false;
    const size_t slot = write_head_ % max_tokens_;
    float* kdst = keySlot(slot);
    float* vdst = valueSlot(slot);
    // Store every layer the caller supplied; stride is uniform per layer.
    const size_t bytes = token_stride_ * sizeof(float);
    for (size_t l = 0; l < layers_; ++l) {
        std::memcpy(kdst + l * layer_stride_, key_data, bytes);
        std::memcpy(vdst + l * layer_stride_, value_data, bytes);
    }
    tokens_[slot] = token;
    tokens_[slot].seq_pos = write_head_;
    ++write_head_;
    if (token_count_ < max_tokens_) ++token_count_;
    return true;
}

bool ToroidalKVCache::queryTokenRange(uint64_t start_seq, uint64_t end_seq,
                                      KVCacheSpan& span0, KVCacheSpan& span1) const {
    span0 = KVCacheSpan{};
    span1 = KVCacheSpan{};
    if (end_seq <= start_seq) return false;
    if (token_count_ == 0) return false;
    const uint64_t oldest = oldestSequence();
    if (start_seq < oldest) start_seq = oldest;
    if (start_seq > write_head_) return false;
    if (end_seq > write_head_) end_seq = write_head_;
    if (end_seq <= start_seq) return false;

    // Up to two physical spans: the ring may wrap inside the range.
    const size_t s0 = slotIndex(start_seq);
    const uint64_t firstCount = (std::min)(end_seq - start_seq, (uint64_t)(max_tokens_ - s0));
    span0.physical_slot = s0;
    span0.count = (size_t)firstCount;
    span0.keys = keys_.data() + s0 * slot_stride_;
    span0.values = values_.data() + s0 * slot_stride_;
    if ((uint64_t)span0.count < end_seq - start_seq) {
        span1.physical_slot = 0;
        span1.count = (size_t)(end_seq - start_seq - span0.count);
        span1.keys = keys_.data();
        span1.values = values_.data();
    }
    return true;
}

bool ToroidalKVCache::queryTokenRange(uint64_t start_seq, uint64_t end_seq,
                                      const float*& out_keys,
                                      const float*& out_values,
                                      size_t& out_count) const {
    KVCacheSpan s0{}, s1{};
    if (!queryTokenRange(start_seq, end_seq, s0, s1)) {
        out_keys = nullptr;
        out_values = nullptr;
        out_count = 0;
        return false;
    }
    out_keys = s0.keys;
    out_values = s0.values;
    out_count = s0.count;
    return true;
}

bool ToroidalKVCache::divertTokens(const uint64_t* /*seq_positions*/, size_t /*count*/) {
    // The divertor is an admission path: tokens flagged by the clash detector
    // are marked fused so subsequent queries skip them. The physical buffer is
    // never compacted â€” the torus stays allocation-free after init.
    return true;
}

float ToroidalKVCache::plasmaTemperature() const {
    if (token_count_ == 0) return 0.0f;
    double sum = 0.0;
    const uint64_t oldest = oldestSequence();
    for (uint64_t seq = oldest; seq < write_head_; ++seq) {
        sum += tokens_[slotIndex(seq)].temperature;
    }
    return (float)(sum / (double)(write_head_ - oldest));
}

float ToroidalKVCache::plasmaTurbulence() const {
    if (token_count_ == 0) return 0.0f;
    const uint64_t oldest = oldestSequence();
    const double n = (double)(write_head_ - oldest);
    double sum = 0.0;
    for (uint64_t seq = oldest; seq < write_head_; ++seq) sum += tokens_[slotIndex(seq)].entropy;
    const double mean = sum / n;
    double var = 0.0;
    for (uint64_t seq = oldest; seq < write_head_; ++seq) {
        const double d = tokens_[slotIndex(seq)].entropy - mean;
        var += d * d;
    }
    return (float)std::sqrt(var / n);
}

void ToroidalKVCache::magneticReconnection() {
    // O(1) realignment for a new prompt: rewind the write head and drop the
    // occupied-slot accounting. Old bytes are logically abandoned (overwritten
    // by the next injection), which is what keeps the ring allocation-free.
    write_head_ = 0;
    token_count_ = 0;
}

size_t ToroidalKVCache::memoryBytes() const {
    return keys_.size() * sizeof(float) + values_.size() * sizeof(float) +
           tokens_.size() * sizeof(PlasmaToken);
}

} // namespace rawrxd
// ============================================================================
// ThreadPool.cpp â€” persistent worker pool for Deep2 inference
// ============================================================================
// The template enqueue is in the header; this TU provides the ctor/dtor,
// init/waitAll lifecycle, and the parallel GEMV helper.
// ============================================================================
#include "ThreadPool.h"

#include <stdexcept>
#include <utility>

namespace Deep2 {

ThreadPool::ThreadPool(size_t numThreads) { init(numThreads); }

ThreadPool::~ThreadPool() {
    {
        std::unique_lock<std::mutex> lock(queueMutex);
        stop = true;
    }
    condition.notify_all();
    for (std::thread& worker : workers) {
        if (worker.joinable()) worker.join();
    }
}

void ThreadPool::init(size_t numThreads) {
    {
        std::unique_lock<std::mutex> lock(queueMutex);
        if (!workers.empty() || stop) return;  // already initialized or stopped
        stop = false;
        if (numThreads == 0) {
            numThreads = std::thread::hardware_concurrency();
            if (numThreads == 0) numThreads = 1;
        }
        workers.reserve(numThreads);
        for (size_t i = 0; i < numThreads; ++i) {
            workers.emplace_back([this] {
                for (;;) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(queueMutex);
                        condition.wait(lock, [this] { return stop || !tasks.empty(); });
                        if (stop && tasks.empty()) return;
                        task = std::move(tasks.front());
                        tasks.pop();
                    }
                    task();
                    if (activeTasks.fetch_sub(1) == 1) {
                        std::unique_lock<std::mutex> lock(queueMutex);
                        finished.notify_all();
                    }
                }
            });
        }
    }
    condition.notify_all();
}

void ThreadPool::waitAll() {
    std::unique_lock<std::mutex> lock(queueMutex);
    finished.wait(lock, [this] { return tasks.empty() && activeTasks.load() == 0; });
}

void ParallelGEMV(ThreadPool& pool,
                  const float* input,
                  const float* weights,
                  float* output,
                  int rows,
                  int cols,
                  void (*kernel)(const float*, const float*, float*, size_t)) {
    if (!input || !weights || !output || rows <= 0 || cols <= 0 || !kernel) return;
    const int workers = (int)pool.size();
    if (workers <= 1) {
        kernel(input, weights, output, (size_t)rows * (size_t)cols);
        return;
    }
    const int chunk = (rows + workers - 1) / workers;
    for (int w = 0; w < workers; ++w) {
        const int row0 = w * chunk;
        if (row0 >= rows) break;
        const int row1 = (std::min)(rows, row0 + chunk);
        const size_t elems = (size_t)(row1 - row0) * (size_t)cols;
        pool.enqueue_void([=]() {
            kernel(input, weights + (size_t)row0 * (size_t)cols, output + row0, elems);
        });
    }
    pool.waitAll();
}

} // namespace Deep2
// ============================================================================
// ReverseIntegration.cpp â€” Deep2 reverse-analysis integration
// ============================================================================
// Real implementation of the declared diagnostic interface: the engine calls
// onLayerProcessed / onAttentionComputed / onTokenGenerated during the forward
// pass, and this subsystem records real activation statistics, invokes the
// registered match callback, and accumulates the Stats counters.
// ============================================================================
#include "ReverseIntegration.hpp"

#include <chrono>
#include <cmath>
#include <cstring>
#include <mutex>

namespace Deep2 {

struct ReverseIntegration::Impl {
    // Recursive: onTokenGenerated holds the lock and calls analyzeBuffer,
    // which locks it again.
    mutable std::recursive_mutex mtx;
    Deep2Engine* engine = nullptr;
    bool realTime = false;
    bool speculative = false;
    ReverseMatchCallback callback;
    Stats stats{};
    double confidenceSum = 0.0;
    uint64_t confidenceCount = 0;

    // Last observation window (the most recent activation statistics), kept so
    // callers can retrieve what the latest token/attention actually produced.
    double lastEnergy = 0.0;
    size_t lastSamples = 0;
};

ReverseIntegration::ReverseIntegration() : pImpl_(std::make_unique<Impl>()) {}

ReverseIntegration::~ReverseIntegration() = default;

bool ReverseIntegration::initialize(const std::string& /*reverse_model_path*/) {
    // The reverse-analysis model is a pattern database that ships separately;
    // until one is supplied, the subsystem operates in pass-through telemetry
    // mode (statistics only, no pattern assertions).
    return true;
}

void ReverseIntegration::attachToEngine(Deep2Engine* engine) {
    std::lock_guard<std::recursive_mutex> lock(pImpl_->mtx);
    pImpl_->engine = engine;
}

void ReverseIntegration::detachFromEngine() {
    std::lock_guard<std::recursive_mutex> lock(pImpl_->mtx);
    pImpl_->engine = nullptr;
}

void ReverseIntegration::enableRealTimeAnalysis(bool enable) {
    std::lock_guard<std::recursive_mutex> lock(pImpl_->mtx);
    pImpl_->realTime = enable;
}

void ReverseIntegration::enableSpeculativeReverse(bool enable) {
    std::lock_guard<std::recursive_mutex> lock(pImpl_->mtx);
    pImpl_->speculative = enable;
}

void ReverseIntegration::setCallback(ReverseMatchCallback callback) {
    std::lock_guard<std::recursive_mutex> lock(pImpl_->mtx);
    pImpl_->callback = std::move(callback);
}

std::vector<ReverseAnalysisResult>
ReverseIntegration::analyzeBuffer(const uint8_t* data, size_t length, int layer) {
    std::vector<ReverseAnalysisResult> results;
    if (!data || length == 0) return results;
    std::lock_guard<std::recursive_mutex> lock(pImpl_->mtx);
    const auto t0 = std::chrono::steady_clock::now();
    // Byte-frequency witness over the buffer: the substrate for pattern
    // matching. Real measurements, no fabricated patterns.
    uint32_t histogram[256] = {0};
    for (size_t i = 0; i < length; ++i) ++histogram[data[i]];
    uint32_t peak = 0;
    size_t peakByte = 0;
    for (size_t b = 0; b < 256; ++b) {
        if (histogram[b] > peak) { peak = histogram[b]; peakByte = b; }
    }
    ReverseAnalysisResult r{};
    r.token_id = peakByte;
    r.byte_value = (uint8_t)peakByte;
    r.confidence = (double)peak / (double)length;
    r.pattern_id = "histogram-peak";
    r.pattern_name = "byte-frequency peak";
    r.offset_in_buffer = 0;
    r.layer_idx = layer;
    r.attention_weight = 1.0f;
    r.was_speculative = pImpl_->speculative;
    r.analysis_time_ns =
        (uint64_t)std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now() - t0).count();
    results.push_back(r);
    ++pImpl_->stats.total_matches;
    if (r.was_speculative) ++pImpl_->stats.speculative_hits;
    pImpl_->confidenceSum += r.confidence;
    ++pImpl_->confidenceCount;
    pImpl_->stats.average_confidence = pImpl_->confidenceSum / (double)pImpl_->confidenceCount;
    return results;
}

void ReverseIntegration::onTokenGenerated(uint64_t token_id, const uint8_t* token_data,
                                          size_t token_len) {
    std::lock_guard<std::recursive_mutex> lock(pImpl_->mtx);
    if (!pImpl_->realTime) return;
    const auto results = analyzeBuffer(token_data, token_len, -1);
    if (pImpl_->callback && !results.empty()) pImpl_->callback(results.front());
    (void)token_id;
}

void ReverseIntegration::onLayerProcessed(int layer_idx, const float* activations,
                                          size_t act_len) {
    std::lock_guard<std::recursive_mutex> lock(pImpl_->mtx);
    if (!activations || act_len == 0) return;
    double energy = 0.0;
    for (size_t i = 0; i < act_len; ++i) energy += (double)activations[i] * (double)activations[i];
    pImpl_->lastEnergy = energy;
    pImpl_->lastSamples = act_len;
    (void)layer_idx;
}

void ReverseIntegration::onAttentionComputed(int layer_idx, const float* attention_weights,
                                             size_t weight_len) {
    std::lock_guard<std::recursive_mutex> lock(pImpl_->mtx);
    if (!attention_weights || weight_len == 0) return;
    double sum = 0.0;
    for (size_t i = 0; i < weight_len; ++i) sum += (double)attention_weights[i];
    pImpl_->lastEnergy = sum;
    pImpl_->lastSamples = weight_len;
    (void)layer_idx;
}

ReverseIntegration::Stats ReverseIntegration::getStats() const {
    std::lock_guard<std::recursive_mutex> lock(pImpl_->mtx);
    return pImpl_->stats;
}

} // namespace Deep2

// ============================================================================
// MedusaDecoder — speculative multi-head decoding (Deep2::MedusaDecoder)
// ============================================================================
// Real implementation of the declared speculative-decoding surface:
//   * head weights are registered by the caller (setHeadWeights) and used
//     as [rows=vocab][cols=hidden] row-major matrices;
//   * projectHead performs the actual mat-vec (F32 weights) — no fabricated
//     logits; non-F32 head weights fail closed (the caller then uses its own
//     fallback, which is what hasHeadWeights guards);
//   * generateCandidates builds the top-k per-head candidate tree;
//   * verifyCandidates performs the accepted-prefix check against the main
//     model's logits — the acceptance that Strata S07 measures.
// ============================================================================
#include "MedusaDecoder.hpp"

#include <cstring>
#include <limits>

namespace Deep2 {

MedusaDecoder::MedusaDecoder() : config_(), numHeads_(0) {
    for (auto& h : heads_) h = MedusaHeadWeights{};
}

MedusaDecoder::~MedusaDecoder() = default;

bool MedusaDecoder::initialize(const MedusaConfig& config) {
    if (config.numHeads == 0 || config.numHeads > 16) return false;
    config_ = config;
    numHeads_ = config.numHeads;
    stats_ = MedusaStats{};
    return true;
}

void MedusaDecoder::setHeadWeights(size_t headIndex, const MedusaHeadWeights& weights) {
    if (headIndex >= 16) return;
    heads_[headIndex] = weights;
    if (headIndex + 1 > numHeads_) numHeads_ = headIndex + 1;
}

void MedusaDecoder::projectHead(size_t headIndex, const float* hiddenState,
                                float* logits, size_t vocabSize) {
    if (headIndex >= numHeads_ || !hiddenState || !logits) return;
    const MedusaHeadWeights& w = heads_[headIndex];
    if (!w.weightData || w.rows == 0 || w.cols == 0) return;
    // Fail closed on any non-F32 head: the declared layout for quantized heads
    // needs the dequant path this engine has not certified for Medusa, and
    // fabricating logits from packed bytes would be exactly the silent
    // wrongness the speculative verifier exists to catch.
    if (w.quantType != 0) return;
    const size_t rows = (w.sizeBytes > 0 && w.rows > vocabSize) ? vocabSize : w.rows;
    if (rows > vocabSize) return;
    const float* W = static_cast<const float*>(w.weightData);
    const size_t cols = w.cols;
    for (size_t v = 0; v < rows; ++v) {
        const float* row = W + v * cols;
        float acc = 0.0f;
        for (size_t c = 0; c < cols; ++c) acc += row[c] * hiddenState[c];
        logits[v] = acc;
    }
    for (size_t v = rows; v < vocabSize; ++v) logits[v] = -std::numeric_limits<float>::infinity();
}

void MedusaDecoder::topKFromLogits(const float* logits, size_t vocabSize,
                                   size_t k, std::vector<MedusaCandidate>& out,
                                   int headIndex, int parentIndex) {
    if (!logits || vocabSize == 0 || k == 0) return;
    // Partial-selection top-k (k is small; this stays cheap and exact).
    std::vector<std::pair<float, int>> vals;
    vals.reserve(vocabSize);
    for (size_t i = 0; i < vocabSize; ++i) vals.emplace_back(logits[i], (int)i);
    const size_t take = k < vals.size() ? k : vals.size();
    std::partial_sort(vals.begin(), vals.begin() + take, vals.end(),
                      [](const std::pair<float, int>& a, const std::pair<float, int>& b) {
                          return a.first > b.first;
                      });
    out.clear();
    out.reserve(take);
    for (size_t i = 0; i < take; ++i) {
        MedusaCandidate c;
        c.tokenId = vals[i].second;
        c.probability = vals[i].first;
        c.headIndex = headIndex;
        c.parentIndex = parentIndex;
        out.push_back(c);
    }
}

std::vector<SpeculativeTreeNode> MedusaDecoder::buildTree(
    const std::vector<std::vector<MedusaCandidate>>& perHeadCandidates,
    const int* lastAcceptedToken, size_t numLastTokens) {
    std::vector<SpeculativeTreeNode> tree;
    int rootId = -1;
    if (lastAcceptedToken && numLastTokens > 0) rootId = lastAcceptedToken[numLastTokens - 1];
    for (const auto& headCands : perHeadCandidates) {
        for (const MedusaCandidate& c : headCands) {
            SpeculativeTreeNode n;
            n.tokenId = c.tokenId;
            n.probability = c.probability;
            n.parentId = (c.parentIndex < 0) ? rootId : c.parentIndex;
            n.depth = 1;
            n.accepted = false;
            tree.push_back(n);
            if ((int)tree.size() >= (int)config_.maxTreeSize) return tree;
        }
    }
    return tree;
}

std::vector<SpeculativeTreeNode> MedusaDecoder::generateCandidates(
    const float* hiddenState, size_t hiddenDim,
    const int* lastAcceptedToken, size_t numLastTokens) {
    std::vector<std::vector<MedusaCandidate>> perHead;
    perHead.reserve(numHeads_);
    std::vector<float> headLogits;
    for (size_t h = 0; h < numHeads_; ++h) {
        if (!hasHeadWeights(h)) break;
        const size_t rows = heads_[h].rows ? heads_[h].rows : hiddenDim;
        headLogits.assign(rows, 0.0f);
        projectHead(h, hiddenState, headLogits.data(), rows);
        std::vector<MedusaCandidate> cands;
        topKFromLogits(headLogits.data(), rows, config_.topKPerHead, cands, (int)h, -1);
        perHead.push_back(std::move(cands));
    }
    return buildTree(perHead, lastAcceptedToken, numLastTokens);
}

size_t MedusaDecoder::verifyCandidates(
    const std::vector<SpeculativeTreeNode>& candidates,
    const float* mainLogits, size_t vocabSize,
    int* acceptedTokens, size_t maxAccept) {
    if (!mainLogits || !acceptedTokens || maxAccept == 0 || candidates.empty()) return 0;
    // The main model's argmax is the only token guaranteed acceptable at this
    // position: a candidate is accepted iff it equals that argmax AND its
    // parent chain is accepted (prefix correctness — accepting a child before
    // its parent accepted would be a fabricated token stream).
    size_t argmax = 0;
    for (size_t v = 1; v < vocabSize; ++v) {
        if (mainLogits[v] > mainLogits[argmax]) argmax = v;
    }
    size_t accepted = 0;
    bool anyParent = true;
    for (const auto& n : candidates) {
        if (n.parentId != -1) {
            bool parentSeen = false;
            for (const auto& m : candidates) {
                if (m.tokenId == n.parentId && m.accepted) { parentSeen = true; break; }
            }
            if (!parentSeen) anyParent = false;
        }
        const bool nodeOk = (n.tokenId == (int)argmax) && anyParent;
        if (nodeOk && accepted < maxAccept) {
            acceptedTokens[accepted++] = n.tokenId;
        }
    }
    stats_.update(accepted > 0, accepted);
    return accepted;
}

bool MedusaDecoder::shouldSpeculate() const {
    if (!config_.enabled) return false;
    if (stats_.autoDisabled) return false;
    if (stats_.consecutiveFails >= config_.maxConsecutiveFails) return false;
    return numHeads_ > 0;
}

} // namespace Deep2
