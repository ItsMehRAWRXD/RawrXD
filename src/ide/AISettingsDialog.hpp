// ============================================================================
// AISettingsDialog.hpp - AI Configuration Dialog
// ============================================================================
// Production-ready settings dialog for AI completion configuration
// ============================================================================

#pragma once

#include <Windows.h>
#include <string>
#include <memory>

namespace RawrXD {
namespace IDE {

// ============================================================================
// AI Settings Structure
// ============================================================================
struct AISettings {
    // Generation parameters
    int maxTokens = 256;
    float temperature = 0.7f;
    float topP = 0.9f;
    int topK = 40;
    float repetitionPenalty = 1.0f;
    
    // UI behavior
    bool enableGhostText = true;
    bool autoTrigger = true;
    int autoTriggerDelayMs = 500;
    bool showInlineSuggestions = true;
    bool multiLineCompletions = true;
    
    // Model selection
    std::string modelPath;
    int contextWindow = 2048;
    int gpuLayers = 0;  // 0 = CPU only
    
    // Advanced
    bool useSpeculativeDecoding = false;
    int draftModelTokens = 4;
    bool cacheKV = true;
    
    // Load/save
    bool LoadFromFile(const char* filename);
    bool SaveToFile(const char* filename) const;
    void ResetToDefaults();
};

// ============================================================================
// AI Settings Dialog
// ============================================================================
class AISettingsDialog {
public:
    AISettingsDialog();
    ~AISettingsDialog();
    
    // Show the dialog modally
    // Returns true if user clicked OK, false if Cancel
    bool Show(HWND parentWindow);
    
    // Get/set settings
    const AISettings& GetSettings() const { return settings_; }
    void SetSettings(const AISettings& settings) { settings_ = settings; }
    
    // Static convenience function
    static bool EditSettings(HWND parentWindow, AISettings& settings);
    
private:
    AISettings settings_;
    AISettings originalSettings_;
    HWND hDialog_;
    
    // Dialog procedure
    static INT_PTR CALLBACK DialogProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    INT_PTR HandleMessage(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    
    // Initialize controls
    void InitializeControls(HWND hwnd);
    void UpdateUIFromSettings(HWND hwnd);
    void UpdateSettingsFromUI(HWND hwnd);
    
    // Validation
    bool ValidateSettings(HWND hwnd);
    
    // Control IDs
    enum ControlIDs {
        IDC_MAX_TOKENS = 100,
        IDC_TEMPERATURE,
        IDC_TOP_P,
        IDC_TOP_K,
        IDC_REP_PENALTY,
        IDC_ENABLE_GHOST,
        IDC_AUTO_TRIGGER,
        IDC_TRIGGER_DELAY,
        IDC_SHOW_INLINE,
        IDC_MULTI_LINE,
        IDC_MODEL_PATH,
        IDC_BROWSE_MODEL,
        IDC_CONTEXT_WINDOW,
        IDC_GPU_LAYERS,
        IDC_USE_SPECULATIVE,
        IDC_DRAFT_TOKENS,
        IDC_CACHE_KV,
        IDC_DEFAULTS,
        IDC_APPLY
    };
};

// ============================================================================
// Global Settings Access
// ============================================================================
AISettings* GetGlobalAISettings();
bool LoadGlobalAISettings();
bool SaveGlobalAISettings();

} // namespace IDE
} // namespace RawrXD
