#pragma once
// G4_LOCALSERVER_PRODUCT_NO_DEPS_DROP_001 — header-only product bootstrap/native bridge.
#include "../cpu_inference_engine.h"
#include <atomic>
#include <exception>
#include <functional>
#include <memory>
#include <string>

namespace RawrXD::HeadlessProduct {
inline std::atomic<bool>& RuntimeReadyFlag() { static std::atomic<bool> v{false}; return v; }
inline std::atomic<bool>& LocalOnlyFlag() { static std::atomic<bool> v{true}; return v; }
inline void SetRuntimeReady(bool v) { RuntimeReadyFlag().store(v, std::memory_order_release); }
inline bool RuntimeReady() { return RuntimeReadyFlag().load(std::memory_order_acquire); }
inline void SetLocalOnly(bool v) { LocalOnlyFlag().store(v, std::memory_order_release); }
inline bool LocalOnly() { return LocalOnlyFlag().load(std::memory_order_acquire); }
inline std::shared_ptr<CPUInferenceEngine> NativeEngine() { return CPUInferenceEngine::GetSharedInstance(); }

inline bool UnloadNativeModel() {
    /* Soft unload no-op: CIE UnloadModel dual-arms Product+CIE and can AV on
     * reload_gen (large GGUF). HeadlessIDE clears flags only; tensors stay. */
    return true;
}

inline bool LoadNativeModel(const std::string& path, std::string& error) {
    error.clear();
    auto engine = NativeEngine();
    if (!engine) { error = "CPUInferenceEngine::GetSharedInstance returned null"; return false; }
    try {
        if (!engine->LoadModel(path)) {
            error = engine->GetLastLoadErrorMessage();
            if (error.empty()) error = "native CPUInferenceEngine::LoadModel failed";
            return false;
        }
    } catch (const std::exception& e) {
        error = std::string("native model load exception: ") + e.what(); return false;
    } catch (...) { error = "native model load exception"; return false; }
    if (!engine->IsModelLoaded()) {
        error = "native engine returned success but IsModelLoaded=false"; return false;
    }
    return true;
}

inline bool GenerateNativeStreaming(const std::string& prompt, int maxTokens,
    const std::function<void(const std::string&)>& onToken, std::string& error) {
    error.clear();
    auto engine = NativeEngine();
    if (!engine || !engine->IsModelLoaded()) { error = "no native LocalGGUF model is loaded"; return false; }
    auto input = engine->Tokenize(prompt.empty() ? std::string(" ") : prompt);
    if (input.empty()) { error = "native tokenizer returned zero tokens"; return false; }
    try {
        engine->GenerateStreaming(input, maxTokens > 0 ? maxTokens : 1,
            [&](const std::string& token) { if (onToken) onToken(token); }, []() {});
    } catch (const std::exception& e) {
        error = std::string("native generation exception: ") + e.what(); return false;
    } catch (...) { error = "native generation exception"; return false; }
    return true;
}

inline std::string GenerateNative(const std::string& prompt, int maxTokens, std::string& error) {
    std::string out;
    if (!GenerateNativeStreaming(prompt, maxTokens, [&](const std::string& t) { out += t; }, error)) return {};
    if (out.empty()) error = "native generation emitted zero text bytes";
    return out;
}

inline const char* HttpReason(int code) {
    switch (code) {
        case 200: return "OK"; case 204: return "No Content";
        case 400: return "Bad Request"; case 403: return "Forbidden";
        case 404: return "Not Found"; case 409: return "Conflict";
        case 500: return "Internal Server Error"; case 503: return "Service Unavailable";
        default: return "OK";
    }
}
} // namespace RawrXD::HeadlessProduct
