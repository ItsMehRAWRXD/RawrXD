/**
 * @file benchmark_profile.cpp
 * @brief Phase 15b: Component-Level Profiling
 * 
 * Breaks down token generation time by component:
 *   1. Token embedding
 *   2. RMSNorm
 *   3. QKV projection
 *   4. RoPE
 *   5. Attention
 *   6. FFN/SwiGLU
 *   7. Output projection
 *   8. Sampling
 * 
 * @copyright RawrXD 2026
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <chrono>
#include <iomanip>
#include <cmath>
#include <cfloat>
#include <cstdint>
#include <algorithm>
#include <numeric>

using namespace std;

using Clock = chrono::high_resolution_clock;
using TimePoint = Clock::time_point;

struct ProfileTimer {
    const char* name;
    TimePoint start;
    double elapsed_ms = 0.0;
    int calls = 0;
    
    void begin() {
        start = Clock::now();
    }
    
    void end() {
        auto end = Clock::now();
        elapsed_ms += chrono::duration_cast<chrono::microseconds>(end - start).count() / 1000.0;
        calls++;
    }
    
    double avg_ms() const {
        return calls > 0 ? elapsed_ms / calls : 0.0;
    }
};

// Simplified tokenizer
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

// Component: Token embedding
void embed_token(int token_id, vector<float>& embedding, int embed_dim, int vocab_size) {
    embedding.resize(embed_dim);
    for (int i = 0; i < embed_dim; i++) {
        embedding[i] = sinf((token_id + i) * 0.01f) * 0.1f;
    }
}

// Component: RMSNorm
void rmsnorm(vector<float>& x, float epsilon = 1e-5f) {
    float sum_sq = 0.0f;
    for (float v : x) sum_sq += v * v;
    float norm_factor = 1.0f / sqrtf(sum_sq / x.size() + epsilon);
    for (float& v : x) v *= norm_factor;
}

// Component: QKV projection (simplified)
void qkv_projection(const vector<float>& input, vector<float>& qkv_output,
                      int embed_dim, int qkv_dim) {
    qkv_output.resize(qkv_dim);
    // Simplified: just copy with scaling
    for (int i = 0; i < qkv_dim; i++) {
        float sum = 0.0f;
        for (int j = 0; j < embed_dim; j++) {
            sum += input[j] * sinf((i + j) * 0.01f) * 0.01f;
        }
        qkv_output[i] = sum;
    }
}

// Component: RoPE
void apply_rope(vector<float>& vec, int position, float base = 10000.0f) {
    int dim = vec.size();
    for (int i = 0; i < dim; i += 2) {
        float theta = position * powf(base, -2.0f * i / dim);
        float cos_theta = cosf(theta);
        float sin_theta = sinf(theta);
        
        float v0 = vec[i];
        float v1 = vec[i + 1];
        
        vec[i] = v0 * cos_theta - v1 * sin_theta;
        vec[i + 1] = v0 * sin_theta + v1 * cos_theta;
    }
}

// Component: Attention (simplified)
void attention(const vector<float>& query, const vector<vector<float>>& keys,
               const vector<vector<float>>& values, vector<float>& output) {
    int head_dim = query.size();
    int n_keys = keys.size();
    output.resize(head_dim);
    fill(output.begin(), output.end(), 0.0f);
    
    vector<float> scores(n_keys);
    float scale = 1.0f / sqrtf(head_dim);
    
    for (int k = 0; k < n_keys; k++) {
        float dot = 0.0f;
        for (int d = 0; d < head_dim; d++) {
            dot += query[d] * keys[k][d];
        }
        scores[k] = dot * scale;
    }
    
    float max_score = *max_element(scores.begin(), scores.end());
    float sum_exp = 0.0f;
    for (float& s : scores) {
        s = expf(s - max_score);
        sum_exp += s;
    }
    for (float& s : scores) s /= sum_exp;
    
    for (int d = 0; d < head_dim; d++) {
        for (int k = 0; k < n_keys; k++) {
            output[d] += scores[k] * values[k][d];
        }
    }
}

// Component: FFN/SwiGLU
void swiglu(const vector<float>& input, vector<float>& output,
            int embed_dim, int hidden_dim) {
    // Gate projection
    vector<float> gate(hidden_dim);
    for (int i = 0; i < hidden_dim; i++) {
        float sum = 0.0f;
        for (int j = 0; j < embed_dim; j++) {
            sum += input[j] * sinf((i + j) * 0.01f) * 0.001f;
        }
        gate[i] = sum;
    }
    
    // Up projection
    vector<float> up(hidden_dim);
    for (int i = 0; i < hidden_dim; i++) {
        float sum = 0.0f;
        for (int j = 0; j < embed_dim; j++) {
            sum += input[j] * cosf((i + j) * 0.01f) * 0.001f;
        }
        up[i] = sum;
    }
    
    // SwiGLU activation
    vector<float> activated(hidden_dim);
    for (int i = 0; i < hidden_dim; i++) {
        float sigmoid_gate = 1.0f / (1.0f + expf(-gate[i]));
        activated[i] = gate[i] * sigmoid_gate * up[i];
    }
    
    // Down projection
    output.resize(embed_dim);
    for (int i = 0; i < embed_dim; i++) {
        float sum = 0.0f;
        for (int j = 0; j < hidden_dim; j++) {
            sum += activated[j] * sinf((i + j) * 0.01f) * 0.001f;
        }
        output[i] = sum;
    }
}

// Component: Output projection
void output_projection(const vector<float>& hidden, vector<float>& logits,
                         int vocab_size, int embed_dim) {
    logits.resize(vocab_size);
    for (int i = 0; i < vocab_size; i++) {
        float logit = 0.0f;
        for (int j = 0; j < embed_dim; j++) {
            logit += hidden[j] * sinf((i + j) * 0.01f);
        }
        logits[i] = logit;
    }
}

// Component: Sampling
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

int main() {
    cout << "🔬 RawrXD Phase 15b: Component-Level Profiling\n";
    cout << "================================================\n\n";
    
    // Configuration
    int vocab_size = 32064;
    int embed_dim = 3072;
    int hidden_dim = 8192;
    int qkv_dim = 9216;  // 3 * embed_dim
    int num_tokens = 10;  // Profile first 10 tokens
    
    cout << "Configuration:\n";
    cout << "  Vocab size: " << vocab_size << "\n";
    cout << "  Embed dim: " << embed_dim << "\n";
    cout << "  Hidden dim: " << hidden_dim << "\n";
    cout << "  Profile tokens: " << num_tokens << "\n\n";
    
    // Initialize timers
    ProfileTimer timer_embedding{"Token Embedding"};
    ProfileTimer timer_rmsnorm{"RMSNorm"};
    ProfileTimer timer_qkv{"QKV Projection"};
    ProfileTimer timer_rope{"RoPE"};
    ProfileTimer timer_attention{"Attention"};
    ProfileTimer timer_ffn{"FFN/SwiGLU"};
    ProfileTimer timer_output{"Output Projection"};
    ProfileTimer timer_sampling{"Sampling"};
    
    // KV cache
    vector<vector<float>> kv_cache_keys;
    vector<vector<float>> kv_cache_values;
    
    // Profile loop
    cout << "Profiling " << num_tokens << " tokens...\n\n";
    
    for (int token_idx = 0; token_idx < num_tokens; token_idx++) {
        int token_id = 100 + token_idx;  // Simulated token IDs
        
        // Step 1: Token Embedding
        timer_embedding.begin();
        vector<float> embedding;
        embed_token(token_id, embedding, embed_dim, vocab_size);
        timer_embedding.end();
        
        // Step 2: RMSNorm
        timer_rmsnorm.begin();
        rmsnorm(embedding);
        timer_rmsnorm.end();
        
        // Step 3: QKV Projection
        timer_qkv.begin();
        vector<float> qkv_output;
        qkv_projection(embedding, qkv_output, embed_dim, qkv_dim);
        timer_qkv.end();
        
        // Split Q, K, V
        vector<float> Q(embed_dim);
        vector<float> K(embed_dim);
        vector<float> V(embed_dim);
        for (int i = 0; i < embed_dim; i++) {
            Q[i] = qkv_output[i];
            K[i] = qkv_output[i + embed_dim];
            V[i] = qkv_output[i + 2 * embed_dim];
        }
        
        // Step 4: RoPE
        timer_rope.begin();
        apply_rope(Q, token_idx);
        apply_rope(K, token_idx);
        timer_rope.end();
        
        // Update KV cache
        kv_cache_keys.push_back(K);
        kv_cache_values.push_back(V);
        
        // Step 5: Attention
        timer_attention.begin();
        vector<float> attn_output;
        attention(Q, kv_cache_keys, kv_cache_values, attn_output);
        timer_attention.end();
        
        // Residual
        for (size_t i = 0; i < embedding.size(); i++) {
            embedding[i] = embedding[i] + attn_output[i];
        }
        
        // RMSNorm
        rmsnorm(embedding);
        
        // Step 6: FFN/SwiGLU
        timer_ffn.begin();
        vector<float> ffn_output;
        swiglu(embedding, ffn_output, embed_dim, hidden_dim);
        timer_ffn.end();
        
        // Residual
        for (size_t i = 0; i < embedding.size(); i++) {
            embedding[i] = embedding[i] + ffn_output[i];
        }
        
        // RMSNorm
        rmsnorm(embedding);
        
        // Step 7: Output Projection
        timer_output.begin();
        vector<float> logits;
        output_projection(embedding, logits, vocab_size, embed_dim);
        timer_output.end();
        
        // Step 8: Sampling
        timer_sampling.begin();
        int next_token = sample_token(logits);
        timer_sampling.end();
        
        // Progress
        if ((token_idx + 1) % 5 == 0) {
            cout << "  Profiled " << (token_idx + 1) << "/" << num_tokens << " tokens\r";
            cout.flush();
        }
    }
    
    cout << "\n\n" << string(60, '=') << "\n";
    cout << "DECODE TOKEN PROFILE\n";
    cout << string(60, '=') << "\n\n";
    
    // Calculate total
    double total_ms = timer_embedding.elapsed_ms + timer_rmsnorm.elapsed_ms +
                      timer_qkv.elapsed_ms + timer_rope.elapsed_ms +
                      timer_attention.elapsed_ms + timer_ffn.elapsed_ms +
                      timer_output.elapsed_ms + timer_sampling.elapsed_ms;
    
    // Report each component
    auto report_component = [](const ProfileTimer& timer, double total_ms) {
        double avg_ms = timer.avg_ms();
        double pct = (timer.elapsed_ms / total_ms) * 100.0;
        
        cout << left << setw(20) << (string(timer.name) + ":");
        cout << fixed << setprecision(2);
        cout << setw(10) << avg_ms << " ms/token";
        cout << " (" << setw(5) << setprecision(1) << pct << "%)";
        cout << " [" << timer.calls << " calls]\n";
    };
    
    report_component(timer_embedding, total_ms);
    report_component(timer_rmsnorm, total_ms);
    report_component(timer_qkv, total_ms);
    report_component(timer_rope, total_ms);
    report_component(timer_attention, total_ms);
    report_component(timer_ffn, total_ms);
    report_component(timer_output, total_ms);
    report_component(timer_sampling, total_ms);
    
    cout << "\n" << string(60, '-') << "\n";
    cout << left << setw(20) << "TOTAL:";
    cout << fixed << setprecision(2);
    cout << setw(10) << (total_ms / num_tokens) << " ms/token";
    cout << " (100.0%)\n";
    cout << "                      " << setw(10) << (1000.0 / (total_ms / num_tokens));
    cout << " tok/s estimated\n";
    
    cout << "\n" << string(60, '=') << "\n";
    cout << "BOTTLENECK ANALYSIS\n";
    cout << string(60, '=') << "\n\n";
    
    // Find top 3 bottlenecks
    vector<pair<double, string>> components = {
        {timer_embedding.avg_ms(), timer_embedding.name},
        {timer_rmsnorm.avg_ms(), timer_rmsnorm.name},
        {timer_qkv.avg_ms(), timer_qkv.name},
        {timer_rope.avg_ms(), timer_rope.name},
        {timer_attention.avg_ms(), timer_attention.name},
        {timer_ffn.avg_ms(), timer_ffn.name},
        {timer_output.avg_ms(), timer_output.name},
        {timer_sampling.avg_ms(), timer_sampling.name}
    };
    
    sort(components.begin(), components.end(), greater<pair<double, string>>());
    
    cout << "Top 3 bottlenecks:\n";
    for (int i = 0; i < 3 && i < (int)components.size(); i++) {
        double pct = (components[i].first / (total_ms / num_tokens)) * 100.0;
        cout << "  " << (i + 1) << ". " << components[i].second << "\n";
        cout << "      " << fixed << setprecision(2) << components[i].first << " ms/token (";
        cout << setprecision(1) << pct << "%)\n";
    }
    
    cout << "\n" << string(60, '=') << "\n";
    cout << "OPTIMIZATION RECOMMENDATIONS\n";
    cout << string(60, '=') << "\n\n";
    
    cout << "Priority 1 (Biggest Impact):\n";
    cout << "  → " << components[0].second << "\n";
    cout << "    Current: " << fixed << setprecision(2) << components[0].first << " ms/token\n";
    cout << "    Action: Optimize matrix operations, add SIMD\n\n";
    
    cout << "Priority 2:\n";
    cout << "  → " << components[1].second << "\n";
    cout << "    Current: " << fixed << setprecision(2) << components[1].first << " ms/token\n";
    cout << "    Action: Parallelize or vectorize\n\n";
    
    cout << "Priority 3:\n";
    cout << "  → " << components[2].second << "\n";
    cout << "    Current: " << fixed << setprecision(2) << components[2].first << " ms/token\n";
    cout << "    Action: Algorithmic improvements\n\n";
    
    cout << "STATUS: ✅ PHASE 15b PROFILING COMPLETE\n";
    
    return 0;
}
