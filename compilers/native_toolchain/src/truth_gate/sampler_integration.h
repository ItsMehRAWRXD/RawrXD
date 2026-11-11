/*
 * Truth Gate 003: Sampler Integration
 * 
 * Token sampling from logits
 */

#ifndef SAMPLER_INTEGRATION_H
#define SAMPLER_INTEGRATION_H

#include "gguf_integration.h"

// Opaque sampler handle
struct SamplerHandle;

// Sampler configuration (TG003 specific)
struct TG003SamplerConfig {
    float temperature;
    float top_p;
    int top_k;
    float repeat_penalty;
    int repeat_last_n;
};

// Default config
inline TG003SamplerConfig TG003SamplerConfig_Default() {
    TG003SamplerConfig cfg;
    cfg.temperature = 0.8f;
    cfg.top_p = 0.95f;
    cfg.top_k = 40;
    cfg.repeat_penalty = 1.1f;
    cfg.repeat_last_n = 64;
    return cfg;
}

// Initialize sampler
SamplerHandle* SamplerIntegration_Init(GGUFModel* model);

// Free sampler
void SamplerIntegration_Free(SamplerHandle* sampler);

// Sample next token
int SamplerIntegration_Sample(SamplerHandle* sampler,
                               const float* logits,
                               int vocab_size,
                               const TG003SamplerConfig* config);

// Greedy sampling (argmax)
int SamplerIntegration_SampleGreedy(const float* logits, int vocab_size);

// Apply temperature scaling
void SamplerIntegration_ApplyTemperature(float* logits, int vocab_size, float temp);

// Apply top-p (nucleus) filtering
void SamplerIntegration_ApplyTopP(float* logits, int vocab_size, float p);

// Apply top-k filtering
void SamplerIntegration_ApplyTopK(float* logits, int vocab_size, int k);

// Apply repeat penalty
void SamplerIntegration_ApplyRepeatPenalty(float* logits, int vocab_size,
                                               const int* past_tokens,
                                               int num_past,
                                               float penalty);

#endif // SAMPLER_INTEGRATION_H
