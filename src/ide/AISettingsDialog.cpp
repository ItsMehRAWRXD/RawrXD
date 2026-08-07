// ============================================================================
// AISettingsDialog.cpp - AI Configuration Dialog Implementation
// ============================================================================

#include "AISettingsDialog.hpp"
#include <commctrl.h>
#include <shlobj.h>
#include <fstream>
#include <sstream>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")

namespace RawrXD {
namespace IDE {

// ============================================================================
// AISettings Implementation
// ============================================================================
bool AISettings::LoadFromFile(const char* filename) {
    std::ifstream file(filename);
    if (!file.is_open()) return false;
    
    std::string line;
    while (std::getline(file, line)) {
        size_t pos = line.find('=');
        if (pos == std::string::npos) continue;
        
        std::string key = line.substr(0, pos);
        std::string value = line.substr(pos + 1);
        
        if (key == "maxTokens") maxTokens = std::stoi(value);
        else if (key == "temperature") temperature = std::stof(value);
        else if (key == "topP") topP = std::stof(value);
        else if (key == "topK") topK = std::stoi(value);
        else if (key == "repetitionPenalty") repetitionPenalty = std::stof(value);
        else if (key == "enableGhostText") enableGhostText = (value == "1");
        else if (key == "autoTrigger") autoTrigger = (value == "1");
        else if (key == "autoTriggerDelayMs") autoTriggerDelayMs = std::stoi(value);
        else if (key == "showInlineSuggestions") showInlineSuggestions = (value == "1");
        else if (key == "multiLineCompletions") multiLineCompletions = (value == "1");
        else if (key == "modelPath") modelPath = value;
        else if (key == "contextWindow") contextWindow = std::stoi(value);
        else if (key == "gpuLayers") gpuLayers = std::stoi(value);
        else if (key == "useSpeculativeDecoding") useSpeculativeDecoding = (value == "1");
        else if (key == "draftModelTokens") draftModelTokens = std::stoi(value);
        else if (key == "cacheKV") cacheKV = (value == "1");
    }
    
    return true;
}

bool AISettings::SaveToFile(const char* filename) const {
    std::ofstream file(filename);
    if (!file.is_open()) return false;
    
    file << "# RawrXD AI Settings\n";
    file << "maxTokens=" << maxTokens << "\n";
    file << "temperature=" << temperature << "\n";
    file << "topP=" << topP << "\n";
    file << "topK=" << topK << "\n";
    file << "repetitionPenalty=" << repetitionPenalty << "\n";
    file << "enableGhostText=" << (enableGhostText ? "1" : "0") << "\n";
    file << "autoTrigger=" << (autoTrigger ? "1" : "0") << "\n";
    file << "autoTriggerDelayMs=" << autoTriggerDelayMs << "\n";
    file << "showInlineSuggestions=" << (showInlineSuggestions ? "1" : "0") << "\n";
    file << "multiLineCompletions=" << (multiLineCompletions ? "1" : "0") << "\n";
    file << "modelPath=" << modelPath << "\n";
    file << "contextWindow=" << contextWindow << "\n";
    file << "gpuLayers=" << gpuLayers << "\n";
    file << "useSpeculativeDecoding=" << (useSpeculativeDecoding ? "1" : "0") << "\n";
    file << "draftModelTokens=" << draftModelTokens << "\n";
    file << "cacheKV=" << (cacheKV ? "1" : "0") << "\n";
    
    return true;
}

void AISettings::ResetToDefaults() {
    maxTokens = 256;
    temperature = 0.7f;
    topP = 0.9f;
    topK = 40;
    repetitionPenalty = 1.0f;
    enableGhostText = true;
    autoTrigger = true;
    autoTriggerDelayMs = 500;
    showInlineSuggestions = true;
    multiLineCompletions = true;
    modelPath.clear();
    contextWindow = 2048;
    gpuLayers = 0;
    useSpeculativeDecoding = false;
    draftModelTokens = 4;
    cacheKV = true;
}

// ============================================================================
// AISettingsDialog Implementation
// ============================================================================
AISettingsDialog::AISettingsDialog() : hDialog_(nullptr) {
    settings_.ResetToDefaults();
}

AISettingsDialog::~AISettingsDialog() {
}

bool AISettingsDialog::Show(HWND parentWindow) {
    originalSettings_ = settings_;
    
    INT_PTR result = DialogBoxParam(
        GetModuleHandle(nullptr),
        MAKEINTRESOURCE(IDD_AI_SETTINGS),
        parentWindow,
        DialogProc,
        reinterpret_cast<LPARAM>(this)
    );
    
    return (result == IDOK);
}

bool AISettingsDialog::EditSettings(HWND parentWindow, AISettings& settings) {
    AISettingsDialog dialog;
    dialog.SetSettings(settings);
    
    if (dialog.Show(parentWindow)) {
        settings = dialog.GetSettings();
        return true;
    }
    
    return false;
}

INT_PTR CALLBACK AISettingsDialog::DialogProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    AISettingsDialog* pThis = nullptr;
    
    if (msg == WM_INITDIALOG) {
        pThis = reinterpret_cast<AISettingsDialog*>(lParam);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(pThis));
        pThis->hDialog_ = hwnd;
    } else {
        pThis = reinterpret_cast<AISettingsDialog*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    }
    
    if (pThis) {
        return pThis->HandleMessage(hwnd, msg, wParam, lParam);
    }
    
    return FALSE;
}

INT_PTR AISettingsDialog::HandleMessage(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_INITDIALOG:
            InitializeControls(hwnd);
            UpdateUIFromSettings(hwnd);
            return TRUE;
            
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case IDOK:
                    UpdateSettingsFromUI(hwnd);
                    if (ValidateSettings(hwnd)) {
                        EndDialog(hwnd, IDOK);
                    }
                    return TRUE;
                    
                case IDCANCEL:
                    settings_ = originalSettings_;
                    EndDialog(hwnd, IDCANCEL);
                    return TRUE;
                    
                case IDC_DEFAULTS:
                    settings_.ResetToDefaults();
                    UpdateUIFromSettings(hwnd);
                    return TRUE;
                    
                case IDC_BROWSE_MODEL:
                    // Open file browser for model selection
                    {
                        char filename[MAX_PATH] = {};
                        OPENFILENAMEA ofn = {};
                        ofn.lStructSize = sizeof(ofn);
                        ofn.hwndOwner = hwnd;
                        ofn.lpstrFilter = "GGUF Models (*.gguf)\0*.gguf\0All Files (*.*)\0*.*\0";
                        ofn.lpstrFile = filename;
                        ofn.nMaxFile = MAX_PATH;
                        ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
                        
                        if (GetOpenFileNameA(&ofn)) {
                            SetDlgItemTextA(hwnd, IDC_MODEL_PATH, filename);
                        }
                    }
                    return TRUE;
                    
                case IDC_ENABLE_GHOST:
                    // Enable/disable dependent controls
                    {
                        BOOL enabled = IsDlgButtonChecked(hwnd, IDC_ENABLE_GHOST);
                        EnableWindow(GetDlgItem(hwnd, IDC_AUTO_TRIGGER), enabled);
                        EnableWindow(GetDlgItem(hwnd, IDC_SHOW_INLINE), enabled);
                    }
                    return TRUE;
            }
            break;
            
        case WM_HSCROLL:
            // Handle slider movements
            if ((HWND)lParam == GetDlgItem(hwnd, IDC_TEMPERATURE)) {
                int pos = SendMessage((HWND)lParam, TBM_GETPOS, 0, 0);
                float temp = pos / 100.0f;
                std::ostringstream oss;
                oss << temp;
                SetDlgItemTextA(hwnd, IDC_TEMPERATURE + 100, oss.str().c_str());
            }
            return TRUE;
    }
    
    return FALSE;
}

void AISettingsDialog::InitializeControls(HWND hwnd) {
    // Initialize slider ranges
    HWND hTemp = GetDlgItem(hwnd, IDC_TEMPERATURE);
    SendMessage(hTemp, TBM_SETRANGE, TRUE, MAKELPARAM(0, 200)); // 0.0 to 2.0
    SendMessage(hTemp, TBM_SETTICFREQ, 10, 0);
    
    HWND hTopP = GetDlgItem(hwnd, IDC_TOP_P);
    SendMessage(hTopP, TBM_SETRANGE, TRUE, MAKELPARAM(0, 100)); // 0.0 to 1.0
    SendMessage(hTopP, TBM_SETTICFREQ, 10, 0);
}

void AISettingsDialog::UpdateUIFromSettings(HWND hwnd) {
    // Generation parameters
    SetDlgItemInt(hwnd, IDC_MAX_TOKENS, settings_.maxTokens, FALSE);
    
    HWND hTemp = GetDlgItem(hwnd, IDC_TEMPERATURE);
    SendMessage(hTemp, TBM_SETPOS, TRUE, static_cast<LPARAM>(settings_.temperature * 100));
    
    HWND hTopP = GetDlgItem(hwnd, IDC_TOP_P);
    SendMessage(hTopP, TBM_SETPOS, TRUE, static_cast<LPARAM>(settings_.topP * 100));
    
    SetDlgItemInt(hwnd, IDC_TOP_K, settings_.topK, FALSE);
    SetDlgItemInt(hwnd, IDC_REP_PENALTY, static_cast<UINT>(settings_.repetitionPenalty * 100), FALSE);
    
    // UI behavior
    CheckDlgButton(hwnd, IDC_ENABLE_GHOST, settings_.enableGhostText ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hwnd, IDC_AUTO_TRIGGER, settings_.autoTrigger ? BST_CHECKED : BST_UNCHECKED);
    SetDlgItemInt(hwnd, IDC_TRIGGER_DELAY, settings_.autoTriggerDelayMs, FALSE);
    CheckDlgButton(hwnd, IDC_SHOW_INLINE, settings_.showInlineSuggestions ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hwnd, IDC_MULTI_LINE, settings_.multiLineCompletions ? BST_CHECKED : BST_UNCHECKED);
    
    // Model selection
    SetDlgItemTextA(hwnd, IDC_MODEL_PATH, settings_.modelPath.c_str());
    SetDlgItemInt(hwnd, IDC_CONTEXT_WINDOW, settings_.contextWindow, FALSE);
    SetDlgItemInt(hwnd, IDC_GPU_LAYERS, settings_.gpuLayers, FALSE);
    
    // Advanced
    CheckDlgButton(hwnd, IDC_USE_SPECULATIVE, settings_.useSpeculativeDecoding ? BST_CHECKED : BST_UNCHECKED);
    SetDlgItemInt(hwnd, IDC_DRAFT_TOKENS, settings_.draftModelTokens, FALSE);
    CheckDlgButton(hwnd, IDC_CACHE_KV, settings_.cacheKV ? BST_CHECKED : BST_UNCHECKED);
}

void AISettingsDialog::UpdateSettingsFromUI(HWND hwnd) {
    // Generation parameters
    settings_.maxTokens = GetDlgItemInt(hwnd, IDC_MAX_TOKENS, nullptr, FALSE);
    
    HWND hTemp = GetDlgItem(hwnd, IDC_TEMPERATURE);
    settings_.temperature = SendMessage(hTemp, TBM_GETPOS, 0, 0) / 100.0f;
    
    HWND hTopP = GetDlgItem(hwnd, IDC_TOP_P);
    settings_.topP = SendMessage(hTopP, TBM_GETPOS, 0, 0) / 100.0f;
    
    settings_.topK = GetDlgItemInt(hwnd, IDC_TOP_K, nullptr, FALSE);
    settings_.repetitionPenalty = GetDlgItemInt(hwnd, IDC_REP_PENALTY, nullptr, FALSE) / 100.0f;
    
    // UI behavior
    settings_.enableGhostText = (IsDlgButtonChecked(hwnd, IDC_ENABLE_GHOST) == BST_CHECKED);
    settings_.autoTrigger = (IsDlgButtonChecked(hwnd, IDC_AUTO_TRIGGER) == BST_CHECKED);
    settings_.autoTriggerDelayMs = GetDlgItemInt(hwnd, IDC_TRIGGER_DELAY, nullptr, FALSE);
    settings_.showInlineSuggestions = (IsDlgButtonChecked(hwnd, IDC_SHOW_INLINE) == BST_CHECKED);
    settings_.multiLineCompletions = (IsDlgButtonChecked(hwnd, IDC_MULTI_LINE) == BST_CHECKED);
    
    // Model selection
    char modelPath[MAX_PATH];
    GetDlgItemTextA(hwnd, IDC_MODEL_PATH, modelPath, MAX_PATH);
    settings_.modelPath = modelPath;
    settings_.contextWindow = GetDlgItemInt(hwnd, IDC_CONTEXT_WINDOW, nullptr, FALSE);
    settings_.gpuLayers = GetDlgItemInt(hwnd, IDC_GPU_LAYERS, nullptr, FALSE);
    
    // Advanced
    settings_.useSpeculativeDecoding = (IsDlgButtonChecked(hwnd, IDC_USE_SPECULATIVE) == BST_CHECKED);
    settings_.draftModelTokens = GetDlgItemInt(hwnd, IDC_DRAFT_TOKENS, nullptr, FALSE);
    settings_.cacheKV = (IsDlgButtonChecked(hwnd, IDC_CACHE_KV) == BST_CHECKED);
}

bool AISettingsDialog::ValidateSettings(HWND hwnd) {
    // Validate max tokens
    if (settings_.maxTokens < 1 || settings_.maxTokens > 4096) {
        MessageBoxA(hwnd, "Max tokens must be between 1 and 4096", "Validation Error", MB_OK | MB_ICONERROR);
        SetFocus(GetDlgItem(hwnd, IDC_MAX_TOKENS));
        return false;
    }
    
    // Validate temperature
    if (settings_.temperature < 0.0f || settings_.temperature > 2.0f) {
        MessageBoxA(hwnd, "Temperature must be between 0.0 and 2.0", "Validation Error", MB_OK | MB_ICONERROR);
        return false;
    }
    
    // Validate topP
    if (settings_.topP < 0.0f || settings_.topP > 1.0f) {
        MessageBoxA(hwnd, "Top-P must be between 0.0 and 1.0", "Validation Error", MB_OK | MB_ICONERROR);
        return false;
    }
    
    // Validate model path if specified
    if (!settings_.modelPath.empty()) {
        DWORD attrs = GetFileAttributesA(settings_.modelPath.c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES) {
            int result = MessageBoxA(hwnd, 
                "Model file not found. Continue anyway?",
                "Warning", MB_YESNO | MB_ICONWARNING);
            if (result == IDNO) {
                SetFocus(GetDlgItem(hwnd, IDC_MODEL_PATH));
                return false;
            }
        }
    }
    
    return true;
}

// ============================================================================
// Global Settings
// ============================================================================
static AISettings g_globalSettings;
static bool g_settingsLoaded = false;

AISettings* GetGlobalAISettings() {
    if (!g_settingsLoaded) {
        LoadGlobalAISettings();
    }
    return &g_globalSettings;
}

bool LoadGlobalAISettings() {
    g_settingsLoaded = g_globalSettings.LoadFromFile("ai_settings.ini");
    return g_settingsLoaded;
}

bool SaveGlobalAISettings() {
    return g_globalSettings.SaveToFile("ai_settings.ini");
}

} // namespace IDE
} // namespace RawrXD
