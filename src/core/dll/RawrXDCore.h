#pragma once

// RawrXDCore Exports - Core runtime DLL interface
#include "RawrXDCore_exports.h"

#ifdef __cplusplus
#include <functional>
extern "C" {
#endif

// Version information
RawrXDCore_EXPORT const char* RawrXDCore_GetVersion(void);
RawrXDCore_EXPORT int RawrXDCore_GetVersionMajor(void);
RawrXDCore_EXPORT int RawrXDCore_GetVersionMinor(void);
RawrXDCore_EXPORT int RawrXDCore_GetVersionPatch(void);

// Initialization/Shutdown
RawrXDCore_EXPORT bool RawrXDCore_Initialize(void);
RawrXDCore_EXPORT void RawrXDCore_Shutdown(void);
RawrXDCore_EXPORT bool RawrXDCore_IsInitialized(void);

// Logging
typedef enum RawrXDLogLevel {
    RAWXD_LOG_TRACE = 0,
    RAWXD_LOG_DEBUG = 1,
    RAWXD_LOG_INFO  = 2,
    RAWXD_LOG_WARN  = 3,
    RAWXD_LOG_ERROR = 4,
    RAWXD_LOG_FATAL = 5
} RawrXDLogLevel;

typedef void (*RawrXDLogCallback)(RawrXDLogLevel level, const char* message, void* userData);

RawrXDCore_EXPORT void RawrXDCore_SetLogCallback(RawrXDLogCallback callback, void* userData);
RawrXDCore_EXPORT void RawrXDCore_SetLogLevel(RawrXDLogLevel level);

// Configuration
typedef struct RawrXDConfig {
    bool enableVulkan;
    bool enableMASM;
    bool enableTelemetry;
    int  workerThreadCount;
    size_t maxMemoryMB;
    const char* modelCachePath;
    const char* logFilePath;
} RawrXDConfig;

RawrXDCore_EXPORT void RawrXDCore_GetDefaultConfig(RawrXDConfig* config);
RawrXDCore_EXPORT bool RawrXDCore_Configure(const RawrXDConfig* config);

// Model Management
typedef struct RawrXDModel RawrXDModel;

RawrXDCore_EXPORT RawrXDModel* RawrXDCore_LoadModel(const char* path);
RawrXDCore_EXPORT void RawrXDCore_UnloadModel(RawrXDModel* model);
RawrXDCore_EXPORT const char* RawrXDCore_GetModelName(const RawrXDModel* model);
RawrXDCore_EXPORT size_t RawrXDCore_GetModelSize(const RawrXDModel* model);
RawrXDCore_EXPORT int RawrXDCore_GetModelLayerCount(const RawrXDModel* model);

// NEW: Extended model metadata
RawrXDCore_EXPORT size_t RawrXDCore_GetModelTensorCount(const RawrXDModel* model);
RawrXDCore_EXPORT uint64_t RawrXDCore_GetModelMappedBytes(const RawrXDModel* model);
RawrXDCore_EXPORT int64_t RawrXDCore_GetModelMetaInt(const RawrXDModel* model, const char* key, int64_t def);
RawrXDCore_EXPORT double RawrXDCore_GetModelMetaFloat(const RawrXDModel* model, const char* key, double def);
RawrXDCore_EXPORT const char* RawrXDCore_GetModelMetaString(const RawrXDModel* model, const char* key);
RawrXDCore_EXPORT size_t RawrXDCore_ListModelTensors(const RawrXDModel* model, char*** outNames);
RawrXDCore_EXPORT void RawrXDCore_FreeTensorList(char** names, size_t count);

// Inference
typedef struct RawrXDInferenceContext RawrXDInferenceContext;

RawrXDCore_EXPORT RawrXDInferenceContext* RawrXDCore_CreateContext(RawrXDModel* model);
RawrXDCore_EXPORT void RawrXDCore_DestroyContext(RawrXDInferenceContext* ctx);

typedef struct RawrXDInferenceParams {
    int maxTokens;
    float temperature;
    float topP;
    int topK;
    float repeatPenalty;
    int seed;
    bool useGPU;
    int gpuDeviceId;
} RawrXDInferenceParams;

RawrXDCore_EXPORT void RawrXDCore_GetDefaultInferenceParams(RawrXDInferenceParams* params);

// Streaming callback for token-by-token generation
typedef bool (*RawrXDTokenCallback)(int tokenId, const char* tokenText, void* userData);

RawrXDCore_EXPORT int RawrXDCore_RunInference(
    RawrXDInferenceContext* ctx,
    const char* prompt,
    const RawrXDInferenceParams* params,
    RawrXDTokenCallback callback,
    void* userData
);

// Native tokenizer access (RAWRXD_MODELGENIE_NATIVE_CHAT_001).
// Tokenizes text with the model's native SentencePiece
// tokenizer - the same GGUFEmbeddedTokenizer implementation
// the runtime's mg_model_tokenize uses. No BOS is prepended
// and no chat template is applied; the text is encoded
// exactly as given.
// Returns the total token count. When outTokens is non-null
// up to maxTokens ids are written; pass a null outTokens to
// query the required capacity.
RawrXDCore_EXPORT size_t RawrXDCore_Tokenize(
    const RawrXDModel* model,
    const char* text,
    int* outTokens,
    size_t maxTokens
);

// Native detokenizer access (RAWRXD_MODELGENIE_NATIVE_CHAT_001).
// Converts token ids to unescaped UTF-8 text with the model's
// native tokenizer - the runtime's mg_model_detokenize path,
// with GPT-2/SentencePiece byte escapes (e.g. U+0120 = space)
// resolved to raw bytes, matching llama.cpp detokenization.
// Returns the length written (excluding the null terminator).
// When outText is null (or outSize is too small), it reports
// the required buffer size (including the null terminator) in
// *outSize and returns 0.

RawrXDCore_EXPORT size_t RawrXDCore_Detokenize(
    const RawrXDModel* model,
    const int* tokenIds,
    size_t count,
    char* outText,
    size_t* outSize
);

// Memory Management
typedef struct RawrXDMemoryStats {
    size_t totalAllocated;
    size_t totalReserved;
    size_t gpuAllocated;
    size_t gpuReserved;
    size_t peakUsage;
} RawrXDMemoryStats;

RawrXDCore_EXPORT void RawrXDCore_GetMemoryStats(RawrXDMemoryStats* stats);
RawrXDCore_EXPORT void RawrXDCore_TrimMemory(void);

// Error handling
typedef enum RawrXDError {
    RAWXD_OK = 0,
    RAWXD_ERROR_INVALID_ARGUMENT = -1,
    RAWXD_ERROR_OUT_OF_MEMORY = -2,
    RAWXD_ERROR_MODEL_NOT_FOUND = -3,
    RAWXD_ERROR_MODEL_CORRUPT = -4,
    RAWXD_ERROR_GPU_UNAVAILABLE = -5,
    RAWXD_ERROR_VULKAN_UNSUPPORTED = -6,
    RAWXD_ERROR_NOT_INITIALIZED = -7,
    RAWXD_ERROR_ALREADY_INITIALIZED = -8,
    RAWXD_ERROR_INTERNAL = -100
} RawrXDError;

RawrXDCore_EXPORT const char* RawrXDCore_GetErrorString(RawrXDError error);
RawrXDCore_EXPORT RawrXDError RawrXDCore_GetLastError(void);

// Hardware Capabilities
typedef struct RawrXDHardwareCaps {
    bool hasAVX2;
    bool hasAVX512;
    bool hasVulkan;
    bool hasCUDA;
    int  cpuCoreCount;
    size_t systemMemoryMB;
    int  gpuCount;
    size_t gpuMemoryMB[4];
    char gpuNames[4][128];
} RawrXDHardwareCaps;

RawrXDCore_EXPORT void RawrXDCore_GetHardwareCaps(RawrXDHardwareCaps* caps);

#ifdef __cplusplus
}
#endif

// C++ API (optional, for convenience)
#ifdef __cplusplus

namespace rawrxd {

class RawrXDCore_EXPORT Core {
public:
    static bool Initialize(const RawrXDConfig* config = nullptr);
    static void Shutdown();
    static bool IsInitialized();
    static const char* GetVersion();
    
    static void SetLogCallback(RawrXDLogCallback callback, void* userData = nullptr);
    static void SetLogLevel(RawrXDLogLevel level);
    
    struct Config : RawrXDConfig {
        Config() { RawrXDCore_GetDefaultConfig(this); }
    };
    
    class Model {
    public:
        Model() : handle_(nullptr) {}
        explicit Model(const char* path) { load(path); }
        ~Model() { if (handle_) RawrXDCore_UnloadModel(handle_); }
        
        Model(Model&& other) noexcept : handle_(other.handle_) { other.handle_ = nullptr; }
        Model& operator=(Model&& other) noexcept {
            if (handle_) RawrXDCore_UnloadModel(handle_);
            handle_ = other.handle_;
            other.handle_ = nullptr;
            return *this;
        }
        
        Model(const Model&) = delete;
        Model& operator=(const Model&) = delete;
        
        bool load(const char* path) {
            if (handle_) RawrXDCore_UnloadModel(handle_);
            handle_ = RawrXDCore_LoadModel(path);
            return handle_ != nullptr;
        }
        
        const char* name() const { return handle_ ? RawrXDCore_GetModelName(handle_) : ""; }
        size_t size() const { return handle_ ? RawrXDCore_GetModelSize(handle_) : 0; }
        int layerCount() const { return handle_ ? RawrXDCore_GetModelLayerCount(handle_) : 0; }
        operator bool() const { return handle_ != nullptr; }
        RawrXDModel* get() const { return handle_; }
        
    private:
        RawrXDModel* handle_;
    };
    
    class InferenceContext {
    public:
        InferenceContext() : handle_(nullptr) {}
        explicit InferenceContext(Model& model) { create(model); }
        ~InferenceContext() { if (handle_) RawrXDCore_DestroyContext(handle_); }
        
        InferenceContext(InferenceContext&& other) noexcept : handle_(other.handle_) { other.handle_ = nullptr; }
        InferenceContext& operator=(InferenceContext&& other) noexcept {
            if (handle_) RawrXDCore_DestroyContext(handle_);
            handle_ = other.handle_;
            other.handle_ = nullptr;
            return *this;
        }
        
        InferenceContext(const InferenceContext&) = delete;
        InferenceContext& operator=(const InferenceContext&) = delete;
        
        bool create(Model& model) {
            if (handle_) RawrXDCore_DestroyContext(handle_);
            handle_ = RawrXDCore_CreateContext(model.get());
            return handle_ != nullptr;
        }
        
        int run(const char* prompt, const RawrXDInferenceParams& params, 
                std::function<bool(int, const char*)> callback) {
            return RawrXDCore_RunInference(handle_, prompt, &params,
                [](int id, const char* text, void* ud) -> bool {
                    auto* cb = static_cast<std::function<bool(int, const char*)>*>(ud);
                    return (*cb)(id, text);
                },
                &callback
            );
        }
        
        operator bool() const { return handle_ != nullptr; }
        RawrXDInferenceContext* get() const { return handle_; }
        
    private:
        RawrXDInferenceContext* handle_;
    };
    
    static void GetMemoryStats(RawrXDMemoryStats& stats);
    static void TrimMemory();
    static RawrXDError GetLastError();
    static const char* GetErrorString(RawrXDError error);
    static void GetHardwareCaps(RawrXDHardwareCaps& caps);
};

} // namespace rawrxd

#endif // __cplusplus
