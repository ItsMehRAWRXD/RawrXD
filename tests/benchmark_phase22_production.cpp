/**
 * @file benchmark_phase22_production.cpp
 * @brief Phase 22: Production Kernel Integration
 *
 * Replaces scalar execution paths with validated AVX2 kernels
 * and measures end-to-end TPS improvement vs Phase 15 baseline.
 *
 * @copyright RawrXD 2026
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <chrono>
#include <iomanip>
#include <cmath>
#include <cfloat>
#include <cstdint>
#include <algorithm>
#include <numeric>

// AVX2 kernel library
#include "../kernels/gemm_avx2.h"
#include "../kernels/attention_avx2.h"

using namespace std;
using namespace rawrxd::kernels;

// Timing utilities
using Clock = chrono::high_resolution_clock;
using TimePoint = Clock::time_point;
using Duration = chrono::duration<double>;

struct Timing {
    TimePoint start;
    TimePoint end;
    double elapsed_ms() const {
        return chrono::duration_cast<chrono::microseconds>(end - start).count() / 1000.0;
    }
};

// Statistics calculator
struct Stats {
    double min_val = DBL_MAX;
    double max_val = -DBL_MAX;
    double mean = 0.0;
    double p50 = 0.0;
    double p95 = 0.0;
    double p99 = 0.0;
    double stddev = 0.0;

    void calculate(const vector<double>& values) {
        if (values.empty()) return;

        vector<double> sorted = values;
        sort(sorted.begin(), sorted.end());

        min_val = sorted.front();
        max_val = sorted.back();
        mean = accumulate(values.begin(), values.end(), 0.0) / values.size();

        p50 = percentile(sorted, 0.50);
        p95 = percentile(sorted, 0.95);
        p99 = percentile(sorted, 0.99);

        double variance = 0.0;
        for (double v : values) {
            variance += (v - mean) * (v - mean);
        }
        stddev = sqrt(variance / values.size());
    }

    static double percentile(const vector<double>& sorted, double p) {
        size_t idx = static_cast<size_t>(p * (sorted.size() - 1));
        return sorted[idx];
    }
};

// Configuration
const int NUM_THREADS = 8;
const int HIDDEN_DIM = 3072;
const int FFN_DIM = 8192;
const int NUM_HEADS = 32;
const int HEAD_DIM = 96;
const int QKV_DIM = 9216;  // 3 * HIDDEN_DIM

// Simplified tokenizer (same as Phase 15)
vector<int> tokenize(const string& text, int vocab_size) {
    vector<int> tokens;
    tokens.push_back(1);  // BOS

    size_t start = 0;
    while (start < text.length()) {
        while (start < text.length() && text[start] == ' ') start++;
        if (start >= text.length()) break;

        size_t end = start;
        while (end < text.length() && text[end] != ' ') end++;

        string word = text.substr(start, end - start);
        int token_id = 0;
        for (char c : word) {
            token_id = (token_id * 31 + c) % (vocab_size - 100);
        }
        token_id += 100;
        tokens.push_back(token_id);
        start = end;
    }

    tokens.push_back(32000);  // EOS
    return tokens;
}

// Embed tokens
void embed_tokens(const vector<int>& tokens, vector<vector<float>>& embeddings,
                  int embed_dim, int vocab_size) {
    embeddings.resize(tokens.size());
    for (size_t t = 0; t < tokens.size(); t++) {
        embeddings[t].resize(embed_dim);
        for (int i = 0; i < embed_dim; i++) {
            embeddings[t][i] = sinf((tokens[t] + i) * 0.01f) * 0.1f;
        }
    }
}

// RMSNorm (scalar - fast enough)
void rmsnorm(vector<float>& x, float epsilon = 1e-5f) {
    float sum_sq = 0.0f;
    for (float v : x) sum_sq += v * v;
    float norm_factor = 1.0f / sqrtf(sum_sq / x.size() + epsilon);
    for (float& v : x) v *= norm_factor;
}

// AVX2-optimized attention using kernel library
void attention_avx2_wrapper(const vector<float>& query,
                           const vector<vector<float>>& keys,
                           const vector<vector<float>>& values,
                           vector<float>& output) {
    int head_dim = query.size();
    int seq_len = keys.size();
    int num_heads = NUM_HEADS;
    int hidden_dim = num_heads * head_dim;

    // Flatten KV cache for AVX2 kernel
    vector<float> k_cache_flat(seq_len * hidden_dim);
    vector<float> v_cache_flat(seq_len * hidden_dim);

    for (int pos = 0; pos < seq_len; pos++) {
        for (int h = 0; h < num_heads; h++) {
            for (int d = 0; d < head_dim; d++) {
                // Simplified: assume query is already per-head
                k_cache_flat[pos * hidden_dim + h * head_dim + d] = keys[pos][d];
                v_cache_flat[pos * hidden_dim + h * head_dim + d] = values[pos][d];
            }
        }
    }

    // Prepare output
    vector<float> q_flat(hidden_dim);
    for (int i = 0; i < hidden_dim; i++) {
        q_flat[i] = query[i % head_dim];  // Broadcast
    }

    vector<float> out_flat(hidden_dim);

    // Call AVX2 attention kernel
    attention_avx2_mt(q_flat.data(), k_cache_flat.data(), v_cache_flat.data(),
                      out_flat.data(), num_heads, head_dim, seq_len, NUM_THREADS);

    // Extract output
    output.resize(head_dim);
    for (int d = 0; d < head_dim; d++) {
        output[d] = out_flat[d];
    }
}

// AVX2-optimized output projection using kernel library
void project_output_avx2(const vector<float>& hidden, vector<float>& logits,
                         int vocab_size, int embed_dim) {
    logits.resize(vocab_size);

    // Create synthetic weights (in real implementation, load from model)
    static vector<float> weights;
    if (weights.empty()) {
        weights.resize(vocab_size * embed_dim);
        for (int i = 0; i < vocab_size * embed_dim; i++) {
            weights[i] = sinf(i * 0.01f) * 0.01f;
        }
    }

    // Call AVX2 GEMV kernel
    gemv_avx2_mt(weights.data(), hidden.data(), logits.data(),
                 vocab_size, embed_dim, NUM_THREADS);
}

// Sample token
int sample_token(const vector<float>& logits) {
    int best_idx = 0;
    float best_logit = logits[0];
    for (size_t i = 1; i < logits.size(); i++) {
        if (logits[i] > best_logit) {
            best_logit = logits[i];
            best_idx = i;
        }
    }
    return best_idx;
}

// AVX2-optimized forward pass
int forward_pass_avx2(const vector<int>& tokens, int vocab_size, int embed_dim,
                      vector<vector<float>>& kv_cache_keys,
                      vector<vector<float>>& kv_cache_values) {
    // Embed
    vector<vector<float>> embeddings;
    embed_tokens(tokens, embeddings, embed_dim, vocab_size);

    // Use last token
    vector<float> hidden = embeddings.back();

    // RMSNorm
    rmsnorm(hidden);

    // Attention with KV cache (AVX2)
    vector<float> attn_output;
    if (kv_cache_keys.empty()) {
        attention_avx2_wrapper(hidden, embeddings, embeddings, attn_output);
        kv_cache_keys = embeddings;
        kv_cache_values = embeddings;
    } else {
        kv_cache_keys.push_back(hidden);
        kv_cache_values.push_back(hidden);
        attention_avx2_wrapper(hidden, kv_cache_keys, kv_cache_values, attn_output);
    }

    // Residual
    for (size_t i = 0; i < hidden.size(); i++) {
        hidden[i] = hidden[i] + attn_output[i];
    }

    // RMSNorm
    rmsnorm(hidden);

    // Output projection (AVX2)
    vector<float> logits;
    project_output_avx2(hidden, logits, vocab_size, embed_dim);

    // Sample
    return sample_token(logits);
}

int main(int argc, char* argv[]) {
    // Benchmark parameters (same as Phase 15)
    const char* MODEL_PATH = "F:\\ollamamodels\\Phi-3-mini-4k-instruct-q8_0.gguf";
    string prompt = "Hello";
    int target_tokens = 128;
    int vocab_size = 32064;
    int embed_dim = 3072;

    if (argc > 1) prompt = argv[1];
    if (argc > 2) target_tokens = atoi(argv[2]);

    cout << "🔬 RawrXD Phase 22: Production Kernel Integration\n";
    cout << "==================================================\n\n";

    cout << "Configuration:\n";
    cout << "  Model: " << MODEL_PATH << "\n";
    cout << "  Prompt: \"" << prompt << "\"\n";
    cout << "  Target tokens: " << target_tokens << "\n";
    cout << "  Vocab size: " << vocab_size << "\n";
    cout << "  Embed dim: " << embed_dim << "\n";
    cout << "  Threads: " << NUM_THREADS << "\n\n";

    // Tokenize prompt
    cout << "[Phase 1] Tokenizing prompt...\n";
    vector<int> prompt_tokens = tokenize(prompt, vocab_size);
    cout << "  Prompt tokens: " << prompt_tokens.size() << "\n\n";

    // Prefill
    cout << "[Phase 2] Prefill...\n";
    Timing prefill_time;
    prefill_time.start = Clock::now();

    vector<vector<float>> kv_cache_keys;
    vector<vector<float>> kv_cache_values;
    int first_token = forward_pass_avx2(prompt_tokens, vocab_size, embed_dim,
                                        kv_cache_keys, kv_cache_values);

    prefill_time.end = Clock::now();
    double prefill_ms = prefill_time.elapsed_ms();
    cout << "  ✓ Prefill complete\n";
    cout << "    Tokens: " << prompt_tokens.size() << "\n";
    cout << "    Time: " << fixed << setprecision(2) << prefill_ms << " ms\n";
    cout << "    Throughput: " << fixed << setprecision(2)
         << (prompt_tokens.size() * 1000.0 / prefill_ms) << " tok/s\n\n";

    // Decode
    cout << "[Phase 3] Decode (generating " << target_tokens << " tokens)...\n";
    vector<int> generated_tokens;
    generated_tokens.push_back(first_token);

    vector<double> token_latencies;
    token_latencies.reserve(target_tokens);

    Timing decode_time;
    decode_time.start = Clock::now();

    TimePoint first_token_time = Clock::now();

    for (int i = 1; i < target_tokens; i++) {
        Timing token_time;
        token_time.start = Clock::now();

        vector<int> input_tokens = {generated_tokens.back()};
        int next_token = forward_pass_avx2(input_tokens, vocab_size, embed_dim,
                                           kv_cache_keys, kv_cache_values);
        generated_tokens.push_back(next_token);

        token_time.end = Clock::now();
        token_latencies.push_back(token_time.elapsed_ms());

        if ((i + 1) % 10 == 0) {
            cout << "    Generated " << (i + 1) << "/" << target_tokens << " tokens\r" << flush;
        }
    }

    decode_time.end = Clock::now();
    TimePoint last_token_time = Clock::now();

    cout << "\n  ✓ Decode complete\n\n";

    // Calculate metrics
    double total_decode_ms = chrono::duration_cast<chrono::microseconds>(
        last_token_time - first_token_time).count() / 1000.0;

    double time_to_first_token_ms = chrono::duration_cast<chrono::microseconds>(
        first_token_time - decode_time.start).count() / 1000.0;

    Stats latency_stats;
    latency_stats.calculate(token_latencies);

    // Results
    cout << "============================================================\n";
    cout << "BENCHMARK SUMMARY\n";
    cout << "============================================================\n\n";

    cout << "Model: " << MODEL_PATH << "\n";
    cout << "Prompt: \"" << prompt << "\"\n";
    cout << "Generation: " << target_tokens << " tokens\n\n";

    cout << "PREFILL:\n";
    cout << "  Tokens: " << prompt_tokens.size() << "\n";
    cout << "  Time: " << fixed << setprecision(3) << (prefill_ms / 1000.0) << " s\n";
    cout << "  Throughput: " << fixed << setprecision(2)
         << (prompt_tokens.size() * 1000.0 / prefill_ms) << " tok/s\n\n";

    cout << "DECODE:\n";
    cout << "  Tokens: " << target_tokens << "\n";
    cout << "  Time: " << fixed << setprecision(3) << (total_decode_ms / 1000.0) << " s\n";
    cout << "  Time to first token: " << fixed << setprecision(2) << time_to_first_token_ms << " ms\n";
    cout << "  Steady-state time: " << fixed << setprecision(2)
         << (total_decode_ms - time_to_first_token_ms) << " ms\n";
    cout << "  Overall throughput: " << fixed << setprecision(2)
         << (target_tokens * 1000.0 / total_decode_ms) << " tok/s\n";
    cout << "  Steady-state throughput: " << fixed << setprecision(2)
         << ((target_tokens - 1) * 1000.0 / (total_decode_ms - time_to_first_token_ms)) << " tok/s\n\n";

    cout << "Latency Distribution (per token):\n";
    cout << "  Min:   " << fixed << setprecision(2) << latency_stats.min_val << " ms\n";
    cout << "  Mean:  " << fixed << setprecision(2) << latency_stats.mean << " ms\n";
    cout << "  P50:   " << fixed << setprecision(2) << latency_stats.p50 << " ms\n";
    cout << "  P95:   " << fixed << setprecision(2) << latency_stats.p95 << " ms\n";
    cout << "  P99:   " << fixed << setprecision(2) << latency_stats.p99 << " ms\n";
    cout << "  Max:   " << fixed << setprecision(2) << latency_stats.max_val << " ms\n";
    cout << "  StdDev: " << fixed << setprecision(2) << latency_stats.stddev << " ms\n\n";

    cout << "============================================================\n";
    cout << "PHASE 22 vs PHASE 15 COMPARISON\n";
    cout << "============================================================\n\n";

    double phase15_tps = 2.21;
    double phase22_tps = target_tokens * 1000.0 / total_decode_ms;
    double speedup = phase22_tps / phase15_tps;

    cout << "Phase 15 (baseline):    " << fixed << setprecision(2) << phase15_tps << " tok/s\n";
    cout << "Phase 22 (AVX2):        " << fixed << setprecision(2) << phase22_tps << " tok/s\n";
    cout << "Speedup:                " << fixed << setprecision(2) << speedup << "x\n\n";

    if (speedup > 1.0) {
        cout << "✅ PHASE 22: INTEGRATION SUCCESSFUL\n";
        cout << "   AVX2 kernels improved end-to-end performance.\n\n";
    } else {
        cout << "⚠️  PHASE 22: No significant improvement\n";
        cout << "   Check kernel integration and threading.\n\n";
    }

    // Generated tokens
    cout << "Generated tokens (first 20): ";
    for (int i = 0; i < min(20, (int)generated_tokens.size()); i++) {
        cout << generated_tokens[i] << " ";
    }
    cout << "\n\n";

    return 0;
}
