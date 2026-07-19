/*===========================================================================
 * RawrXD_IDE_RuntimeBridge.cpp
 * 
 * Implementation of IDE-to-Runtime bridge
 *===========================================================================*/

#include "RawrXD_IDE_RuntimeBridge.hpp"
#include <chrono>

namespace RawrXD {

/*===========================================================================
 * IDE_RuntimeBridge Implementation
 *=========================================================================*/

IDE_RuntimeBridge& IDE_RuntimeBridge::Instance() {
    static IDE_RuntimeBridge instance;
    return instance;
}

bool IDE_RuntimeBridge::Initialize() {
    SR_Status status = SR_Initialize();
    if (status != SR_OK) {
        return false;
    }
    return true;
}

void IDE_RuntimeBridge::Shutdown() {
    SR_Shutdown();
}

bool IDE_RuntimeBridge::IsInitialized() const {
    return SR_IsInitialized() == TRUE;
}

bool IDE_RuntimeBridge::LoadModel(const std::wstring& ggufPath, 
                                   ProgressCallback progress) {
    m_progressCallback = progress;
    
    SR_ModelInfo info;
    SR_Status status = SR_LoadModel(
        ggufPath.c_str(),
        &info,
        progress ? ProgressCallbackTrampoline : nullptr,
        this
    );
    
    m_progressCallback = nullptr;
    return status == SR_OK;
}

void IDE_RuntimeBridge::UnloadModel() {
    SR_UnloadModel();
}

bool IDE_RuntimeBridge::IsModelLoaded() const {
    return SR_IsModelLoaded() == TRUE;
}

SR_ModelInfo IDE_RuntimeBridge::GetModelInfo() const {
    SR_ModelInfo info;
    if (!SR_GetModelInfo(&info)) {
        ZeroMemory(&info, sizeof(info));
    }
    return info;
}

bool IDE_RuntimeBridge::Generate(const std::wstring& prompt,
                                  const SR_InferenceConfig& config,
                                  TokenCallback callback) {
    m_tokenCallback = callback;
    
    SR_Status status = SR_Generate(
        prompt.c_str(),
        &config,
        TokenCallbackTrampoline,
        this
    );
    
    return status == SR_OK;
}

std::wstring IDE_RuntimeBridge::GenerateBlocking(const std::wstring& prompt,
                                                    const SR_InferenceConfig& config,
                                                    uint32_t* outTokensGenerated) {
    std::wstring result;
    result.reserve(4096);
    
    uint32_t tokenCount = 0;
    
    /* Use streaming API but accumulate */
    auto accumulator = [&result, &tokenCount](const std::wstring& token, 
                                               uint32_t index, 
                                               bool isComplete) {
        result += token;
        tokenCount++;
    };
    
    if (Generate(prompt, config, accumulator)) {
        WaitForCompletion(0); /* Infinite wait */
    }
    
    if (outTokensGenerated) {
        *outTokensGenerated = tokenCount;
    }
    
    return result;
}

void IDE_RuntimeBridge::CancelGeneration() {
    SR_CancelGeneration();
}

bool IDE_RuntimeBridge::IsGenerating() const {
    return SR_IsGenerating() == TRUE;
}

bool IDE_RuntimeBridge::WaitForCompletion(uint32_t timeoutMs) {
    return SR_WaitForCompletion(timeoutMs) == TRUE;
}

SR_Telemetry IDE_RuntimeBridge::GetTelemetry() const {
    SR_Telemetry telemetry;
    SR_GetTelemetry(&telemetry);
    return telemetry;
}

std::wstring IDE_RuntimeBridge::GetLastError() const {
    const WCHAR* err = SR_GetLastError();
    return err ? err : L"Unknown error";
}

void IDE_RuntimeBridge::SetVerbose(bool enable) {
    SR_SetVerbose(enable ? TRUE : FALSE);
}

void IDE_RuntimeBridge::GetCapabilities(bool& outHasAVX2, 
                                        bool& outHasAVX512,
                                        uint32_t& outNumCores) {
    SR_GetCapabilities(
        (BOOL*)&outHasAVX2,
        (BOOL*)&outHasAVX512,
        nullptr,  /* hasLargePages */
        &outNumCores
    );
}

/* Static callback trampolines */

void IDE_RuntimeBridge::TokenCallbackTrampoline(const WCHAR* tokenText,
                                                uint32_t tokenId,
                                                uint32_t tokenIndex,
                                                BOOL isComplete,
                                                float logits[],
                                                uint32_t vocabSize,
                                                void* userData) {
    IDE_RuntimeBridge* bridge = static_cast<IDE_RuntimeBridge*>(userData);
    if (bridge && bridge->m_tokenCallback) {
        bridge->m_tokenCallback(tokenText, tokenIndex, isComplete == TRUE);
    }
}

void IDE_RuntimeBridge::ProgressCallbackTrampoline(const WCHAR* operation,
                                                     uint32_t current,
                                                     uint32_t total,
                                                     void* userData) {
    IDE_RuntimeBridge* bridge = static_cast<IDE_RuntimeBridge*>(userData);
    if (bridge && bridge->m_progressCallback) {
        bridge->m_progressCallback(operation, current, total);
    }
}

/*===========================================================================
 * GhostTextStreamer Implementation
 *=========================================================================*/

GhostTextStreamer::GhostTextStreamer(HWND hEditor) 
    : m_hEditor(hEditor), m_isActive(false), m_tokenCount(0) {
}

void GhostTextStreamer::OnToken(const std::wstring& token, uint32_t index, bool isComplete) {
    m_accumulated += token;
    m_tokenCount++;
    m_isActive = !isComplete;
    
    /* Send message to editor to update ghost text */
    /* WM_USER + 100 = custom ghost text update message */
    SendMessageW(m_hEditor, WM_USER + 100, 
                 (WPARAM)m_accumulated.c_str(), 
                 (LPARAM)m_accumulated.length());
}

void GhostTextStreamer::Clear() {
    m_accumulated.clear();
    m_tokenCount = 0;
    m_isActive = false;
    
    SendMessageW(m_hEditor, WM_USER + 100, 0, 0);
}

bool GhostTextStreamer::IsActive() const {
    return m_isActive;
}

/*===========================================================================
 * IDE_InferencePresets Implementation
 *=========================================================================*/

SR_InferenceConfig IDE_InferencePresets::FastCompletion() {
    SR_InferenceConfig config = SR_DEFAULT_CONFIG;
    config.maxTokens = 32;
    config.temperature = 0.3f;
    config.topP = 0.9f;
    config.topK = 20;
    config.streamOutput = TRUE;
    return config;
}

SR_InferenceConfig IDE_InferencePresets::Balanced() {
    SR_InferenceConfig config = SR_DEFAULT_CONFIG;
    config.maxTokens = 128;
    config.temperature = 0.7f;
    config.topP = 0.9f;
    config.topK = 40;
    config.streamOutput = TRUE;
    return config;
}

SR_InferenceConfig IDE_InferencePresets::HighQuality() {
    SR_InferenceConfig config = SR_DEFAULT_CONFIG;
    config.maxTokens = 256;
    config.temperature = 0.8f;
    config.topP = 0.95f;
    config.topK = 60;
    config.repeatPenalty = 1.15f;
    config.streamOutput = TRUE;
    return config;
}

SR_InferenceConfig IDE_InferencePresets::CodeCompletion() {
    SR_InferenceConfig config = SR_DEFAULT_CONFIG;
    config.maxTokens = 64;
    config.temperature = 0.2f;  /* Low temp for deterministic code */
    config.topP = 0.95f;
    config.topK = 10;
    config.repeatPenalty = 1.1f;
    config.repeatLastN = 128;   /* Look back further for context */
    config.streamOutput = TRUE;
    return config;
}

} /* namespace RawrXD */
