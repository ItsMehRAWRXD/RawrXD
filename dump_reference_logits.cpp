#include <llama.h>
#include <iostream>
#include <vector>
#include <algorithm>
#include <cmath>
#include <fstream>
#include <iomanip>

void write_binary(const char* path, const float* data, size_t count) {
    std::ofstream f(path, std::ios::binary);
    f.write(reinterpret_cast<const char*>(data), count * sizeof(float));
    f.close();
    std::cout << "Wrote " << count << " floats to " << path << std::endl;
}

struct LogitStats {
    float max_abs_diff = 0.0f;
    float rmse = 0.0f;
    float cosine_sim = 0.0f;
    int argmax_a = 0;
    int argmax_b = 0;
    bool argmax_match = false;
    std::vector<std::pair<int, float>> top10_a;
    std::vector<std::pair<int, float>> top10_b;
    int top10_match_count = 0;
    float diff_at_185 = 0.0f;
    float diff_at_93633 = 0.0f;
};

LogitStats compare_logits(const float* a, const float* b, int n_vocab) {
    LogitStats stats;
    
    // Argmax
    float max_a = a[0], max_b = b[0];
    for (int i = 1; i < n_vocab; ++i) {
        if (a[i] > max_a) { max_a = a[i]; stats.argmax_a = i; }
        if (b[i] > max_b) { max_b = b[i]; stats.argmax_b = i; }
    }
    stats.argmax_match = (stats.argmax_a == stats.argmax_b);
    
    // Top-10
    std::vector<std::pair<int, float>> idx_val_a, idx_val_b;
    idx_val_a.reserve(n_vocab);
    idx_val_b.reserve(n_vocab);
    for (int i = 0; i < n_vocab; ++i) {
        idx_val_a.emplace_back(i, a[i]);
        idx_val_b.emplace_back(i, b[i]);
    }
    std::partial_sort(idx_val_a.begin(), idx_val_a.begin() + 10, idx_val_a.end(),
                      [](const auto& x, const auto& y) { return x.second > y.second; });
    std::partial_sort(idx_val_b.begin(), idx_val_b.begin() + 10, idx_val_b.end(),
                      [](const auto& x, const auto& y) { return x.second > y.second; });
    stats.top10_a = std::vector<std::pair<int, float>>(idx_val_a.begin(), idx_val_a.begin() + 10);
    stats.top10_b = std::vector<std::pair<int, float>>(idx_val_b.begin(), idx_val_b.begin() + 10);
    
    // Count top-10 overlap
    for (const auto& pa : stats.top10_a) {
        for (const auto& pb : stats.top10_b) {
            if (pa.first == pb.first) {
                stats.top10_match_count++;
                break;
            }
        }
    }
    
    // Full stats
    double sum_sq_diff = 0.0;
    double dot = 0.0, norm_a = 0.0, norm_b = 0.0;
    for (int i = 0; i < n_vocab; ++i) {
        float diff = a[i] - b[i];
        float abs_diff = std::abs(diff);
        if (abs_diff > stats.max_abs_diff) stats.max_abs_diff = abs_diff;
        sum_sq_diff += double(diff) * double(diff);
        dot += double(a[i]) * double(b[i]);
        norm_a += double(a[i]) * double(a[i]);
        norm_b += double(b[i]) * double(b[i]);
    }
    stats.rmse = std::sqrt(sum_sq_diff / n_vocab);
    stats.cosine_sim = static_cast<float>(dot / (std::sqrt(norm_a) * std::sqrt(norm_b)));
    
    stats.diff_at_185 = std::abs(a[185] - b[185]);
    stats.diff_at_93633 = std::abs(a[93633] - b[93633]);
    
    return stats;
}

int main() {
    llama_backend_init();
    
    llama_model_params model_params = llama_model_default_params();
    model_params.n_gpu_layers = 0;
    
    const char* model_path = "G:\\~dev\\rawrxd\\models\\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf";
    llama_model* model = llama_model_load_from_file(model_path, model_params);
    if (!model) {
        std::cerr << "Failed to load model\n";
        return 1;
    }
    
    llama_context_params ctx_params = llama_context_default_params();
    ctx_params.n_ctx = 512;
    ctx_params.n_batch = 512;
    ctx_params.n_ubatch = 512;
    ctx_params.n_threads = 1;
    ctx_params.n_threads_batch = 1;
    
    llama_context* ctx = llama_init_from_model(model, ctx_params);
    if (!ctx) {
        std::cerr << "Failed to create context\n";
        return 1;
    }
    
    const llama_vocab* vocab = llama_model_get_vocab(model);
    int n_vocab = llama_vocab_n_tokens(vocab);
    std::cout << "Vocab size: " << n_vocab << std::endl;
    
    // Input token 1
    llama_token tokens[] = {1};
    llama_batch batch = llama_batch_get_one(tokens, 1);
    
    if (llama_decode(ctx, batch)) {
        std::cerr << "Failed to decode\n";
        return 1;
    }
    
    float* logits = llama_get_logits_ith(ctx, 0);
    if (!logits) {
        std::cerr << "Failed to get logits\n";
        return 1;
    }
    
    // Write logits to binary file
    write_binary("F:\\rawrxd\\evidence\\NUGVERSE_ESTIMATOR_001\\reference_logits.bin", logits, n_vocab);
    
    llama_free(ctx);
    llama_model_free(model);
    llama_backend_free();
    return 0;
}