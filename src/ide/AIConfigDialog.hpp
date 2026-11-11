// ============================================================================
// AIConfigDialog.hpp - AI Configuration Dialog
// ============================================================================
// Production-ready preferences UI for AI completion settings
// ============================================================================

#pragma once

#include <Windows.h>
#include <string>

namespace RawrXD {
namespace IDE {

// ============================================================================
// AI Configuration Structure
// ============================================================================
struct AIConfig {
    // Generation parameters
    float temperature = 0.7f;      // 0.0 - 2.0
    float topP = 0.9f;             // 0.0 - 1.0
    int maxTokens = 256;           // 16 - 2048
    int topK = 40;                 // 1 - 100
    float repeatPenalty = 1.1f;    // 1.0 - 2.0
    
    // UI behavior
    bool autoTrigger = true;       // Auto-trigger on '.' and '->'
    int triggerDelayMs = 300;      // Delay before triggering (ms)
    bool showInline = true;        // Show ghost text inline
    bool grayOutCompleted = true;  // Gray out accepted completions
    
    // Model selection
    std::string modelPath;         // Path to GGUF model
    std::string modelName;         // Display name
    
    // Advanced
    bool useGPU = true;            // Use GPU acceleration
    int gpuLayerCount = -1;        // -1 = all layers, 0 = CPU only
    int contextLength = 4096;      // Context window size
    bool useFlashAttention = true; // Use Flash Attention
    
    // Telemetry
    bool enableTelemetry = true;   // Collect usage metrics
    bool shareAnonymous = false;   // Share anonymous usage data
    
    // Load/save
    bool LoadFromRegistry();
    bool SaveToRegistry();
    void ResetToDefaults();
};

// ============================================================================
// Configuration Dialog
// ============================================================================
class AIConfigDialog {
public:
    AIConfigDialog();
    ~AIConfigDialog();
    
    // Show the configuration dialog
    // Returns true if user clicked OK, false if Cancel
    bool Show(HWND hParent);
    
    // Get/set configuration
    const AIConfig& GetConfig() const { return config_; }
    void SetConfig(const AIConfig& config) { config_ = config; }
    
    // Static convenience method
    static bool ShowDialog(HWND hParent, AIConfig& config);
    
private:
    // Dialog procedure
    static INT_PTR CALLBACK DialogProc(HWND hwnd, UINT msg, 
                                        WPARAM wParam, LPARAM lParam);
    
    // Instance dialog procedure
    INT_PTR HandleMessage(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    
    // Initialize controls
    void InitDialog(HWND hwnd);
    void UpdateControls(HWND hwnd);
    void UpdateSliderLabels(HWND hwnd);
    
    // Command handlers
    void OnCommand(HWND hwnd, int id, int code);
    void OnHScroll(HWND hwnd, HWND hSlider);
    void OnOK(HWND hwnd);
    void OnCancel(HWND hwnd);
    void OnReset(HWND hwnd);
    void OnBrowseModel(HWND hwnd);
    void OnAdvancedClicked(HWND hwnd);
    
    // Data
    AIConfig config_;
    AIConfig originalConfig_;
    HWND hwndDlg_ = nullptr;
    bool showingAdvanced_ = false;
    
    // Control IDs
    static constexpr int IDC_TEMP_SLIDER = 1001;
    static constexpr int IDC_TEMP_LABEL = 1002;
    static constexpr int IDC_TOPP_SLIDER = 1003;
    static constexpr int IDC_TOPP_LABEL = 1004;
    static constexpr int IDC_MAXTOKENS = 1005;
    static constexpr int IDC_TOPK = 1006;
    static constexpr int IDC_REPEAT_PENALTY = 1007;
    static constexpr int IDC_AUTO_TRIGGER = 1008;
    static constexpr int IDC_TRIGGER_DELAY = 1009;
    static constexpr int IDC_SHOW_INLINE = 1010;
    static constexpr int IDC_MODEL_PATH = 1011;
    static constexpr int IDC_BROWSE_MODEL = 1012;
    static constexpr int IDC_USE_GPU = 1013;
    static constexpr int IDC_GPU_LAYERS = 1014;
    static constexpr int IDC_CONTEXT_LENGTH = 1015;
    static constexpr int IDC_FLASH_ATTENTION = 1016;
    static constexpr int IDC_ENABLE_TELEMETRY = 1017;
    static constexpr int IDC_SHARE_ANONYMOUS = 1018;
    static constexpr int IDC_ADVANCED_GROUP = 1019;
    static constexpr int IDC_RESET_DEFAULTS = 1020;
    static constexpr int ID_ADVANCED_TOGGLE = 1021;
};

// ============================================================================
// Global Configuration Access
// ============================================================================

// Get global AI configuration
AIConfig& GetGlobalAIConfig();

// Load configuration from registry
bool LoadAIConfig();

// Save configuration to registry
bool SaveAIConfig();

} // namespace IDE
} // namespace RawrXD
