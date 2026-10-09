// ============================================================================
// Deep2CAPI.cpp - C API DLL for Deep2 Engine
// Exports: Deep2_CreateEngine, Deep2_Initialize, Deep2_LoadModel, RawrLaneGenerateStream
// ============================================================================

#define RAWRXD_BUILD_WIN32IDE ON
#define LOCAL_ONLY_001 1
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN

#include "Deep2Engine.cpp"  // Include the full implementation
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <functional>

// The Deep2Engine.cpp already defines these as extern "C" functions:
// - Deep2_CreateEngine
// - Deep2_DestroyEngine
// - Deep2_Initialize
// - Deep2_LoadModel
// - RawrLaneGenerateStream
// - Deep2_HasAVX2
// - Deep2_HasAVX512
// - Deep2_VecDotProduct
// - Deep2_SwiGLU
// - Deep2_RMSNorm
// etc.

// We just need to ensure they're exported from this DLL
// The functions are already marked __declspec(dllexport) in the extern "C" block

// Additional helper for streaming with custom callback
extern "C" __declspec(dllexport) int Deep2_GenerateStreamCallback(
    void* engine,
    const char* prompt,
    uint32_t max_tokens,
    void (*callback)(const char* token, bool done, void* user_data),
    void* user_data
) {
    if (!engine || !prompt || !callback) return -1;
    
    Deep2::Deep2Engine* e = static_cast<Deep2::Deep2Engine*>(engine);
    
    Deep2::GenerationOptions opts{};
    opts.maxTokens = max_tokens ? max_tokens : 512;
    opts.temperature = 0.7f;
    opts.topP = 0.9f;
    opts.topK = 40;
    
    // We need to hook into the internal streaming mechanism
    // For now, use the existing generateStream with a wrapper
    
    std::string accumulated;
    bool cancelled = false;
    
    auto wrapped_callback = [&](int32_t token_id, const std::string& token) -> bool {
        if (cancelled) return false;
        accumulated += token;
        callback(token.c_str(), false, user_data);
        return true;
    };
    
    try {
        e->generateStream(prompt, opts, wrapped_callback);
        callback("", true, user_data);  // Signal done
        return 1;
    } catch (const std::exception& ex) {
        fprintf(stderr, "[Deep2CAPI] Generation exception: %s\n", ex.what());
        callback("", true, user_data);
        return -2;
    } catch (...) {
        fprintf(stderr, "[Deep2CAPI] Generation unknown exception\n");
        callback("", true, user_data);
        return -3;
    }
}

// Simple blocking generate (collects all tokens and returns via output buffer)
extern "C" __declspec(dllexport) int Deep2_GenerateBlocking(
    void* engine,
    const char* prompt,
    char* output_buf,
    unsigned int output_buf_size,
    unsigned int* output_required,
    uint32_t max_tokens,
    float temperature
) {
    if (!engine || !prompt || !output_buf || output_buf_size == 0) return -1;
    
    Deep2::Deep2Engine* e = static_cast<Deep2::Deep2Engine*>(engine);
    
    Deep2::GenerationOptions opts{};
    opts.maxTokens = max_tokens ? max_tokens : 512;
    opts.temperature = temperature;
    opts.topP = 0.9f;
    opts.topK = 40;
    
    std::string accumulated;
    
    auto callback = [&](int32_t, const std::string& token) -> bool {
        accumulated += token;
        return true;
    };
    
    try {
        e->generateStream(prompt, opts, callback);
        
        const unsigned int required = static_cast<unsigned int>(accumulated.size() + 1);
        if (output_required) *output_required = required;
        
        size_t copy_len = std::min<size_t>(accumulated.size(), output_buf_size - 1);
        if (copy_len > 0) {
            std::memcpy(output_buf, accumulated.c_str(), copy_len);
        }
        output_buf[copy_len] = '\0';
        
        return (required <= output_buf_size) ? 0 : 1;
    } catch (const std::exception& ex) {
        fprintf(stderr, "[Deep2CAPI] Blocking generation exception: %s\n", ex.what());
        std::string err = "[ERROR] " + std::string(ex.what());
        if (output_required) *output_required = static_cast<unsigned int>(err.size() + 1);
        size_t copy_len = std::min<size_t>(err.size(), output_buf_size - 1);
        if (copy_len > 0) std::memcpy(output_buf, err.c_str(), copy_len);
        output_buf[copy_len] = '\0';
        return -2;
    } catch (...) {
        return -3;
    }
}

// Version info
extern "C" __declspec(dllexport) const char* Deep2CAPI_Version() {
    return "Deep2CAPI/1.0 (Deep2Engine C API)";
}