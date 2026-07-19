/*===========================================================================
 * RawrXD_IDE_RuntimeBridge.hpp
 * 
 * Bridges the Win32 IDE to the SovereignRuntime DLL
 * Uses the same backend as the CLI (rawrxd-infer.exe)
 * 
 * Architecture:
 *   IDE.exe → SovereignRuntime.dll → Kernel Dispatch → MASM Kernels
 *===========================================================================*/

#pragma once

#include <windows.h>
#include <string>
#include <functional>
#include "../runtime/SovereignRuntime.h"

namespace RawrXD {

/*===========================================================================
 * IDE Runtime Bridge
 * Wraps SovereignRuntime C API for C++ use with IDE-specific callbacks
 *=========================================================================*/
class IDE_RuntimeBridge {
public:
    /* Token callback type - called for each generated token */
    using TokenCallback = std::function<void(const std::wstring& token, 
                                               uint32_t tokenIndex, 
                                               bool isComplete)>;
    
    /* Progress callback - called during model loading */
    using ProgressCallback = std::function<void(const std::wstring& operation,
                                                  uint32_t current,
                                                  uint32_t total)>;
    
    /* Singleton access */
    static IDE_RuntimeBridge& Instance();
    
    /* Lifecycle */
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    /* Model management */
    bool LoadModel(const std::wstring& ggufPath, 
                   ProgressCallback progress = nullptr);
    void UnloadModel();
    bool IsModelLoaded() const;
    SR_ModelInfo GetModelInfo() const;
    
    /* Inference - streaming (non-blocking) */
    bool Generate(const std::wstring& prompt,
                  const SR_InferenceConfig& config,
                  TokenCallback callback);
    
    /* Inference - blocking (simpler) */
    std::wstring GenerateBlocking(const std::wstring& prompt,
                                   const SR_InferenceConfig& config,
                                   uint32_t* outTokensGenerated = nullptr);
    
    /* Control */
    void CancelGeneration();
    bool IsGenerating() const;
    bool WaitForCompletion(uint32_t timeoutMs = 0);
    
    /* Telemetry */
    SR_Telemetry GetTelemetry() const;
    std::wstring GetLastError() const;
    
    /* Configuration */
    void SetVerbose(bool enable);
    
    /* Capabilities */
    static void GetCapabilities(bool& outHasAVX2, 
                                 bool& outHasAVX512,
                                 uint32_t& outNumCores);

private:
    IDE_RuntimeBridge() = default;
    ~IDE_RuntimeBridge() = default;
    
    IDE_RuntimeBridge(const IDE_RuntimeBridge&) = delete;
    IDE_RuntimeBridge& operator=(const IDE_RuntimeBridge&) = delete;
    
    /* Static callback trampoline for C API */
    static void TokenCallbackTrampoline(const WCHAR* tokenText,
                                        uint32_t tokenId,
                                        uint32_t tokenIndex,
                                        BOOL isComplete,
                                        float logits[],
                                        uint32_t vocabSize,
                                        void* userData);
    
    static void ProgressCallbackTrampoline(const WCHAR* operation,
                                           uint32_t current,
                                           uint32_t total,
                                           void* userData);
    
    /* Current callback storage (not thread-safe, only one generation at a time) */
    TokenCallback m_tokenCallback;
    ProgressCallback m_progressCallback;
};

/*===========================================================================
 * Ghost Text Integration
 * Helper class for streaming tokens into the IDE's Ghost Text Engine
 *=========================================================================*/
class GhostTextStreamer {
public:
    /* Initialize with target editor handle */
    explicit GhostTextStreamer(HWND hEditor);
    
    /* Called for each token from the runtime */
    void OnToken(const std::wstring& token, uint32_t index, bool isComplete);
    
    /* Clear current ghost text */
    void Clear();
    
    /* Check if streaming is active */
    bool IsActive() const;

private:
    HWND m_hEditor;
    std::wstring m_accumulated;
    bool m_isActive;
    uint32_t m_tokenCount;
};

/*===========================================================================
 * IDE-Specific Configuration Presets
 *=========================================================================*/
struct IDE_InferencePresets {
    /* Fast completion - low latency, fewer tokens */
    static SR_InferenceConfig FastCompletion();
    
    /* Balanced - good quality/speed tradeoff */
    static SR_InferenceConfig Balanced();
    
    /* High quality - better output, slower */
    static SR_InferenceConfig HighQuality();
    
    /* Code completion - optimized for code */
    static SR_InferenceConfig CodeCompletion();
};

} /* namespace RawrXD */
