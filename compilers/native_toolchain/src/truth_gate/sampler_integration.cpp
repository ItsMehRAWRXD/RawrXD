/*
 * Truth Gate 003: Sampler Integration Implementation
 */

#include "sampler_integration.h"
#include <cstdio>
#include <cstring>
#include <cmath>
#include <algorithm>
#include <vector>

struct SamplerHandle {
    int vocab_size;
    std::vector<int> token_history;
};

SamplerHandle* SamplerIntegration_Init(GGUFModel* model) {
    printf("    [Sampler] Initializing sampler\n");
    
    SamplerHandle* sampler = new SamplerHandle();
    
    ModelInfo info;
    if (model && GGUFIntegration_GetModelInfo(model, &info)) {
        sampler->vocab_size = info.vocab_size;
    } else {
        sampler->vocab_size = 32000;  // Default for tinyllama
    }
    
    printf("    [Sampler] Vocab size: %d\n", sampler->vocab_size);
    
    return sampler;
}

void SamplerIntegration_Free(SamplerHandle* sampler) {
    if (sampler) {
        delete sampler;
    }
}

// Softmax
static void Softmax(float* logits, int vocab_size) {
    float max_logit = logits[0];
    for (int i = 1; i < vocab_size; i++) {
        if (logits[i] > max_logit) max_logit = logits[i];
    }
    
    float sum = 0.0f;
    for (int i = 0; i < vocab_size; i++) {
        logits[i] = expf(logits[i] - max_logit);
        sum += logits[i];
    }
    
    for (int i = 0; i < vocab_size; i++) {
        logits[i] /= sum;
    }
}

// Top-k filtering
void SamplerIntegration_ApplyTopK(float* logits, int vocab_size, int k) {
    if (k >= vocab_size) return;
    
    // Find k-th largest
    std::vector<float> sorted(logits, logits + vocab_size);
    std::nth_element(sorted.begin(), sorted.begin() + (vocab_size - k), sorted.end());
    float kth_largest = sorted[vocab_size - k];
    
    // Zero out below k-th
    for (int i = 0; i < vocab_size; i++) {
        if (logits[i] < kth_largest) {
            logits[i] = -INFINITY;
        }
    }
}

// Top-p (nucleus) filtering
void SamplerIntegration_ApplyTopP(float* logits, int vocab_size, float p) {
    if (p >= 1.0f) return;
    
    // Sort logits descending
    std::vector<std::pair<float, int>> sorted;
    for (int i = 0; i < vocab_size; i++) {
        sorted.push_back({logits[i], i});
    }
    std::sort(sorted.begin(), sorted.end(), 
              [](auto& a, auto& b) { return a.first > b.first; });
    
    // Compute softmax
    float max_logit = sorted[0].first;
    float sum = 0.0f;
    for (auto& pair : sorted) {
        pair.first = expf(pair.first - max_logit);
        sum += pair.first;
    }
    
    // Find cutoff
    float cumsum = 0.0f;
    float cutoff = 0.0f;
    for (auto& pair : sorted) {
        cumsum += pair.first / sum;
        if (cumsum >= p) {
            cutoff = pair.first / sum;
            break;
        }
    }
    
    // Apply cutoff
    for (int i = 0; i < vocab_size; i++) {
        float prob = expf(logits[i] - max_logit) / sum;
        if (prob < cutoff) {
            logits[i] = -INFINITY;
        }
    }
}

// Temperature scaling
void SamplerIntegration_ApplyTemperature(float* logits, int vocab_size, float temp) {
    if (temp <= 0.0f) temp = 1.0f;
    if (temp == 1.0f) return;
    
    for (int i = 0; i < vocab_size; i++) {
        logits[i] /= temp;
    }
}

// Repeat penalty
void SamplerIntegration_ApplyRepeatPenalty(float* logits, int vocab_size,
                                               const int* past_tokens,
                                               int num_past,
                                               float penalty) {
    if (penalty <= 0.0f || num_past == 0) return;
    
    for (int i = 0; i < num_past; i++) {
        int token = past_tokens[i];
        if (token >= 0 && token < vocab_size) {
            if (logits[token] > 0) {
                logits[token] /= penalty;
            } else {
                logits[token] *= penalty;
            }
        }
    }
}

// Greedy sampling
int SamplerIntegration_SampleGreedy(const float* logits, int vocab_size) {
    int max_idx = 0;
    float max_val = logits[0];
    
    for (int i = 1; i < vocab_size; i++) {
        if (logits[i] > max_val) {
            max_val = logits[i];
            max_idx = i;
        }
    }
    
    return max_idx;
}

// Main sampling function
int SamplerIntegration_Sample(SamplerHandle* sampler,
                               const float* logits,
                               int vocab_size,
                               const TG003SamplerConfig* config) {
    if (!sampler || !logits || !config) return 0;
    
    // Make mutable copy
    std::vector<float> mutable_logits(logits, logits + vocab_size);
    
    // Apply temperature
    SamplerIntegration_ApplyTemperature(mutable_logits.data(), vocab_size, config->temperature);
    
    // Apply repeat penalty
    SamplerIntegration_ApplyRepeatPenalty(mutable_logits.data(), vocab_size,
                                           sampler->token_history.data(),
                                           (int)sampler->token_history.size(),
                                           config->repeat_penalty);
    
    // Apply top-k
    SamplerIntegration_ApplyTopK(mutable_logits.data(), vocab_size, config->top_k);
    
    // Apply top-p
    SamplerIntegration_ApplyTopP(mutable_logits.data(), vocab_size, config->top_p);
    
    // Convert to probabilities
    Softmax(mutable_logits.data(), vocab_size);
    
    // Sample
    float r = (float)rand() / (float)RAND_MAX;
    float cumsum = 0.0f;
    int selected = 0;
    
    for (int i = 0; i < vocab_size; i++) {
        cumsum += mutable_logits[i];
        if (r <= cumsum) {
            selected = i;
            break;
        }
    }
    
    // Update history
    sampler->token_history.push_back(selected);
    if ((int)sampler->token_history.size() > config->repeat_last_n) {
        sampler->token_history.erase(sampler->token_history.begin());
    }
    
    return selected;
}
