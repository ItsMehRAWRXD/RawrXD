/*
 * Truth Gate 003: GGUF Integration
 * 
 * Loads real GGUF models through the Sovereign Runtime
 */

#ifndef GGUF_INTEGRATION_H
#define GGUF_INTEGRATION_H

#include <cstdint>
#include <cstddef>

// Opaque handle
struct GGUFModel;

// Load a GGUF model from file
GGUFModel* GGUFIntegration_Load(const char* path);

// Free model resources
void GGUFIntegration_Free(GGUFModel* model);

// Get tensor count
int GGUFIntegration_GetTensorCount(GGUFModel* model);

// Check if tensor exists
bool GGUFIntegration_HasTensor(GGUFModel* model, const char* name);

// Get tensor data (returns pointer to raw data)
void* GGUFIntegration_GetTensorData(GGUFModel* model, const char* name);

// Get tensor shape
bool GGUFIntegration_GetTensorShape(GGUFModel* model, const char* name, 
                                       int* dims, int* ndims);

// Get model architecture info
struct ModelInfo {
    int num_layers;
    int hidden_dim;
    int num_heads;
    int num_kv_heads;
    int vocab_size;
    int context_length;
    float norm_eps;
};

bool GGUFIntegration_GetModelInfo(GGUFModel* model, ModelInfo* info);

#endif // GGUF_INTEGRATION_H
