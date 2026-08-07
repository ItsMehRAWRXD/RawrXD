// ============================================================================
// AIConfigDialog.cpp - AI Configuration Dialog Implementation
// ============================================================================

#include "AIConfigDialog.hpp"
#include "resource.h"
#include <commctrl.h>
#include <shlobj.h>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")

namespace RawrXD {
namespace IDE {

// ============================================================================
// Registry Keys
// ============================================================================
static constexpr wchar_t REG_KEY_PATH[] = L"Software\\RawrXD\\AIConfig";

// ============================================================================
// Global Configuration
// ============================================================================
static AIConfig g_GlobalAIConfig;

AIConfig& GetGlobalAIConfig() {
    return g_GlobalAIConfig;
}

bool LoadAIConfig() {
    return g_GlobalAIConfig.LoadFromRegistry();
}

bool SaveAIConfig() {
    return g_GlobalAIConfig.SaveToRegistry();
}

// ============================================================================
// AIConfig Implementation
// ============================================================================
bool AIConfig::LoadFromRegistry() {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, REG_KEY_PATH, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        // Use defaults
        ResetToDefaults();
        return false;
    }
    
    DWORD type, size;
    
    // Temperature
    size = sizeof(float);
    RegQueryValueExW(hKey, L"Temperature", nullptr, &type, 
                     reinterpret_cast<LPBYTE>(&temperature), &size);
    
    // TopP
    size = sizeof(float);
    RegQueryValueExW(hKey, L"TopP", nullptr, &type, 
                     reinterpret_cast<LPBYTE>(&topP), &size);
    
    // MaxTokens
    size = sizeof(int);
    RegQueryValueExW(hKey, L"MaxTokens", nullptr, &type, 
                     reinterpret_cast<LPBYTE>(&maxTokens), &size);
    
    // TopK
    size = sizeof(int);
    RegQueryValueExW(hKey, L"TopK", nullptr, &type, 
                     reinterpret_cast<LPBYTE>(&topK), &size);
    
    // RepeatPenalty
    size = sizeof(float);
    RegQueryValueExW(hKey, L"RepeatPenalty", nullptr, &type, 
                     reinterpret_cast<LPBYTE>(&repeatPenalty), &size);
    
    // AutoTrigger
    size = sizeof(BOOL);
    RegQueryValueExW(hKey, L"AutoTrigger", nullptr, &type, 
                     reinterpret_cast<LPBYTE>(&autoTrigger), &size);
    
    // TriggerDelayMs
    size = sizeof(int);
    RegQueryValueExW(hKey, L"TriggerDelayMs", nullptr, &type, 
                     reinterpret_cast<LPBYTE>(&triggerDelayMs), &size);
    
    // ShowInline
    size = sizeof(BOOL);
    RegQueryValueExW(hKey, L"ShowInline", nullptr, &type, 
                     reinterpret_cast<LPBYTE>(&showInline), &size);
    
    // GrayOutCompleted
    size = sizeof(BOOL);
    RegQueryValueExW(hKey, L"GrayOutCompleted", nullptr, &type, 
                     reinterpret_cast<LPBYTE>(&grayOutCompleted), &size);
    
    // UseGPU
    size = sizeof(BOOL);
    RegQueryValueExW(hKey, L"UseGPU", nullptr, &type, 
                     reinterpret_cast<LPBYTE>(&useGPU), &size);
    
    // GpuLayerCount
    size = sizeof(int);
    RegQueryValueExW(hKey, L"GpuLayerCount", nullptr, &type, 
                     reinterpret_cast<LPBYTE>(&gpuLayerCount), &size);
    
    // ContextLength
    size = sizeof(int);
    RegQueryValueExW(hKey, L"ContextLength", nullptr, &type, 
                     reinterpret_cast<LPBYTE>(&contextLength), &size);
    
    // UseFlashAttention
    size = sizeof(BOOL);
    RegQueryValueExW(hKey, L"UseFlashAttention", nullptr, &type, 
                     reinterpret_cast<LPBYTE>(&useFlashAttention), &size);
    
    // EnableTelemetry
    size = sizeof(BOOL);
    RegQueryValueExW(hKey, L"EnableTelemetry", nullptr, &type, 
                     reinterpret_cast<LPBYTE>(&enableTelemetry), &size);
    
    // ShareAnonymous
    size = sizeof(BOOL);
    RegQueryValueExW(hKey, L"ShareAnonymous", nullptr, &type, 
                     reinterpret_cast<LPBYTE>(&shareAnonymous), &size);
    
    // ModelPath
    wchar_t wPath[MAX_PATH] = {};
    size = sizeof(wPath);
    if (RegQueryValueExW(hKey, L"ModelPath", nullptr, &type, 
                         reinterpret_cast<LPBYTE>(wPath), &size) == ERROR_SUCCESS) {
        char path[MAX_PATH];
        WideCharToMultiByte(CP_UTF8, 0, wPath, -1, path, MAX_PATH, nullptr, nullptr);
        modelPath = path;
    }
    
    // ModelName
    wchar_t wName[MAX_PATH] = {};
    size = sizeof(wName);
    if (RegQueryValueExW(hKey, L"ModelName", nullptr, &type, 
                         reinterpret_cast<LPBYTE>(wName), &size) == ERROR_SUCCESS) {
        char name[MAX_PATH];
        WideCharToMultiByte(CP_UTF8, 0, wName, -1, name, MAX_PATH, nullptr, nullptr);
        modelName = name;
    }
    
    RegCloseKey(hKey);
    return true;
}

bool AIConfig::SaveToRegistry() {
    HKEY hKey;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, REG_KEY_PATH, 0, nullptr, 
                        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, 
                        &hKey, nullptr) != ERROR_SUCCESS) {
        return false;
    }
    
    // Temperature
    RegSetValueExW(hKey, L"Temperature", 0, REG_BINARY, 
                   reinterpret_cast<const BYTE*>(&temperature), sizeof(float));
    
    // TopP
    RegSetValueExW(hKey, L"TopP", 0, REG_BINARY, 
                   reinterpret_cast<const BYTE*>(&topP), sizeof(float));
    
    // MaxTokens
    RegSetValueExW(hKey, L"MaxTokens", 0, REG_BINARY, 
                   reinterpret_cast<const BYTE*>(&maxTokens), sizeof(int));
    
    // TopK
    RegSetValueExW(hKey, L"TopK", 0, REG_BINARY, 
                   reinterpret_cast<const BYTE*>(&topK), sizeof(int));
    
    // RepeatPenalty
    RegSetValueExW(hKey, L"RepeatPenalty", 0, REG_BINARY, 
                   reinterpret_cast<const BYTE*>(&repeatPenalty), sizeof(float));
    
    // AutoTrigger
    RegSetValueExW(hKey, L"AutoTrigger", 0, REG_BINARY, 
                   reinterpret_cast<const BYTE*>(&autoTrigger), sizeof(BOOL));
    
    // TriggerDelayMs
    RegSetValueExW(hKey, L"TriggerDelayMs", 0, REG_BINARY, 
                   reinterpret_cast<const BYTE*>(&triggerDelayMs), sizeof(int));
    
    // ShowInline
    RegSetValueExW(hKey, L"ShowInline", 0, REG_BINARY, 
                   reinterpret_cast<const BYTE*>(&showInline), sizeof(BOOL));
    
    // GrayOutCompleted
    RegSetValueExW(hKey, L"GrayOutCompleted", 0, REG_BINARY, 
                   reinterpret_cast<const BYTE*>(&grayOutCompleted), sizeof(BOOL));
    
    // UseGPU
    RegSetValueExW(hKey, L"UseGPU", 0, REG_BINARY, 
                   reinterpret_cast<const BYTE*>(&useGPU), sizeof(BOOL));
    
    // GpuLayerCount
    RegSetValueExW(hKey, L"GpuLayerCount", 0, REG_BINARY, 
                   reinterpret_cast<const BYTE*>(&gpuLayerCount), sizeof(int));
    
    // ContextLength
    RegSetValueExW(hKey, L"ContextLength", 0, REG_BINARY, 
                   reinterpret_cast<const BYTE*>(&contextLength), sizeof(int));
    
    // UseFlashAttention
    RegSetValueExW(hKey, L"UseFlashAttention", 0, REG_BINARY, 
                   reinterpret_cast<const BYTE*>(&useFlashAttention), sizeof(BOOL));
    
    // EnableTelemetry
    RegSetValueExW(hKey, L"EnableTelemetry", 0, REG_BINARY, 
                   reinterpret_cast<const BYTE*>(&enableTelemetry), sizeof(BOOL));
    
    // ShareAnonymous
    RegSetValueExW(hKey, L"ShareAnonymous", 0, REG_BINARY, 
                   reinterpret_cast<const BYTE*>(&shareAnonymous), sizeof(BOOL));
    
    // ModelPath
    wchar_t wPath[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, modelPath.c_str(), -1, wPath, MAX_PATH);
    RegSetValueExW(hKey, L"ModelPath", 0, REG_SZ, 
                   reinterpret_cast<const BYTE*>(wPath), 
                   (wcslen(wPath) + 1) * sizeof(wchar_t));
    
    // ModelName
    wchar_t wName[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, modelName.c_str(), -1, wName, MAX_PATH);
    RegSetValueExW(hKey, L"ModelName", 0, REG_SZ, 
                   reinterpret_cast<const BYTE*>(wName), 
                   (wcslen(wName) + 1) * sizeof(wchar_t));
    
    RegCloseKey(hKey);
    return true;
}

void AIConfig::ResetToDefaults() {
    temperature = 0.7f;
    topP = 0.9f;
    maxTokens = 256;
    topK = 40;
    repeatPenalty = 1.1f;
    autoTrigger = true;
    triggerDelayMs = 300;
    showInline = true;
    grayOutCompleted = true;
    modelPath.clear();
    modelName.clear();
    useGPU = true;
    gpuLayerCount = -1;
    contextLength = 4096;
    useFlashAttention = true;
    enableTelemetry = true;
    shareAnonymous = false;
}

// ============================================================================
// AIConfigDialog Implementation
// ============================================================================
AIConfigDialog::AIConfigDialog() = default;
AIConfigDialog::~AIConfigDialog() = default;

bool AIConfigDialog::Show(HWND hParent) {
    originalConfig_ = config_;
    
    INT_PTR result = DialogBoxParamW(
        GetModuleHandle(nullptr),
        MAKEINTRESOURCE(IDD_AI_PREFERENCES),
        hParent,
        DialogProc,
        reinterpret_cast<LPARAM>(this)
    );
    
    return result == IDOK;
}

bool AIConfigDialog::ShowDialog(HWND hParent, AIConfig& config) {
    AIConfigDialog dlg;
    dlg.SetConfig(config);
    if (dlg.Show(hParent)) {
        config = dlg.GetConfig();
        return true;
    }
    return false;
}

INT_PTR CALLBACK AIConfigDialog::DialogProc(HWND hwnd, UINT msg, 
                                            WPARAM wParam, LPARAM lParam) {
    AIConfigDialog* pDlg = nullptr;
    
    if (msg == WM_INITDIALOG) {
        pDlg = reinterpret_cast<AIConfigDialog*>(lParam);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(pDlg));
        pDlg->hwndDlg_ = hwnd;
    } else {
        pDlg = reinterpret_cast<AIConfigDialog*>(
            GetWindowLongPtr(hwnd, GWLP_USERDATA));
    }
    
    if (pDlg) {
        return pDlg->HandleMessage(hwnd, msg, wParam, lParam);
    }
    
    return FALSE;
}

INT_PTR AIConfigDialog::HandleMessage(HWND hwnd, UINT msg, 
                                      WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_INITDIALOG:
            InitDialog(hwnd);
            return TRUE;
            
        case WM_COMMAND:
            OnCommand(hwnd, LOWORD(wParam), HIWORD(wParam));
            return TRUE;
            
        case WM_HSCROLL:
            OnHScroll(hwnd, reinterpret_cast<HWND>(lParam));
            return TRUE;
            
        case WM_CLOSE:
            OnCancel(hwnd);
            return TRUE;
    }
    
    return FALSE;
}

void AIConfigDialog::InitDialog(HWND hwnd) {
    // Initialize sliders
    HWND hTemp = GetDlgItem(hwnd, IDC_TEMP_SLIDER);
    SendMessage(hTemp, TBM_SETRANGE, TRUE, MAKELPARAM(0, 200)); // 0.0 - 2.0
    SendMessage(hTemp, TBM_SETPOS, TRUE, static_cast<LPARAM>(config_.temperature * 100));
    
    HWND hTopP = GetDlgItem(hwnd, IDC_TOPP_SLIDER);
    SendMessage(hTopP, TBM_SETRANGE, TRUE, MAKELPARAM(0, 100)); // 0.0 - 1.0
    SendMessage(hTopP, TBM_SETPOS, TRUE, static_cast<LPARAM>(config_.topP * 100));
    
    // Initialize edit controls
    SetDlgItemInt(hwnd, IDC_MAXTOKENS, config_.maxTokens, FALSE);
    SetDlgItemInt(hwnd, IDC_TOPK, config_.topK, FALSE);
    SetDlgItemInt(hwnd, IDC_TRIGGER_DELAY, config_.triggerDelayMs, FALSE);
    
    // Initialize checkboxes
    CheckDlgButton(hwnd, IDC_AUTO_TRIGGER, config_.autoTrigger ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hwnd, IDC_SHOW_INLINE, config_.showInline ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hwnd, IDC_USE_GPU, config_.useGPU ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hwnd, IDC_FLASH_ATTENTION, config_.useFlashAttention ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hwnd, IDC_ENABLE_TELEMETRY, config_.enableTelemetry ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hwnd, IDC_SHARE_ANONYMOUS, config_.shareAnonymous ? BST_CHECKED : BST_UNCHECKED);
    
    // Model path
    SetDlgItemTextA(hwnd, IDC_MODEL_PATH, config_.modelPath.c_str());
    
    // Update labels
    UpdateSliderLabels(hwnd);
    
    // Hide advanced controls initially
    showingAdvanced_ = false;
}

void AIConfigDialog::UpdateSliderLabels(HWND hwnd) {
    // Temperature
    HWND hTemp = GetDlgItem(hwnd, IDC_TEMP_SLIDER);
    int tempPos = static_cast<int>(SendMessage(hTemp, TBM_GETPOS, 0, 0));
    float temp = tempPos / 100.0f;
    
    std::wostringstream tempStr;
    tempStr << std::fixed << std::setprecision(2) << temp;
    SetDlgItemTextW(hwnd, IDC_TEMP_LABEL, tempStr.str().c_str());
    
    // TopP
    HWND hTopP = GetDlgItem(hwnd, IDC_TOPP_SLIDER);
    int topPPos = static_cast<int>(SendMessage(hTopP, TBM_GETPOS, 0, 0));
    float topP = topPPos / 100.0f;
    
    std::wostringstream topPStr;
    topPStr << std::fixed << std::setprecision(2) << topP;
    SetDlgItemTextW(hwnd, IDC_TOPP_LABEL, topPStr.str().c_str());
}

void AIConfigDialog::OnCommand(HWND hwnd, int id, int code) {
    switch (id) {
        case IDOK:
            OnOK(hwnd);
            break;
            
        case IDCANCEL:
            OnCancel(hwnd);
            break;
            
        case IDC_RESET_DEFAULTS:
            OnReset(hwnd);
            break;
            
        case IDC_BROWSE_MODEL:
            OnBrowseModel(hwnd);
            break;
            
        case ID_ADVANCED_TOGGLE:
            OnAdvancedClicked(hwnd);
            break;
    }
}

void AIConfigDialog::OnHScroll(HWND hwnd, HWND hSlider) {
    UpdateSliderLabels(hwnd);
}

void AIConfigDialog::OnOK(HWND hwnd) {
    // Read values from controls
    HWND hTemp = GetDlgItem(hwnd, IDC_TEMP_SLIDER);
    int tempPos = static_cast<int>(SendMessage(hTemp, TBM_GETPOS, 0, 0));
    config_.temperature = tempPos / 100.0f;
    
    HWND hTopP = GetDlgItem(hwnd, IDC_TOPP_SLIDER);
    int topPPos = static_cast<int>(SendMessage(hTopP, TBM_GETPOS, 0, 0));
    config_.topP = topPPos / 100.0f;
    
    config_.maxTokens = GetDlgItemInt(hwnd, IDC_MAXTOKENS, nullptr, FALSE);
    config_.topK = GetDlgItemInt(hwnd, IDC_TOPK, nullptr, FALSE);
    config_.triggerDelayMs = GetDlgItemInt(hwnd, IDC_TRIGGER_DELAY, nullptr, FALSE);
    
    config_.autoTrigger = IsDlgButtonChecked(hwnd, IDC_AUTO_TRIGGER) == BST_CHECKED;
    config_.showInline = IsDlgButtonChecked(hwnd, IDC_SHOW_INLINE) == BST_CHECKED;
    config_.useGPU = IsDlgButtonChecked(hwnd, IDC_USE_GPU) == BST_CHECKED;
    config_.useFlashAttention = IsDlgButtonChecked(hwnd, IDC_FLASH_ATTENTION) == BST_CHECKED;
    config_.enableTelemetry = IsDlgButtonChecked(hwnd, IDC_ENABLE_TELEMETRY) == BST_CHECKED;
    config_.shareAnonymous = IsDlgButtonChecked(hwnd, IDC_SHARE_ANONYMOUS) == BST_CHECKED;
    
    char path[MAX_PATH];
    GetDlgItemTextA(hwnd, IDC_MODEL_PATH, path, MAX_PATH);
    config_.modelPath = path;
    
    // Save to registry
    config_.SaveToRegistry();
    
    EndDialog(hwnd, IDOK);
}

void AIConfigDialog::OnCancel(HWND hwnd) {
    config_ = originalConfig_;
    EndDialog(hwnd, IDCANCEL);
}

void AIConfigDialog::OnReset(HWND hwnd) {
    if (MessageBoxW(hwnd, 
        L"Reset all AI settings to defaults?",
        L"Confirm Reset", 
        MB_YESNO | MB_ICONQUESTION) == IDYES) {
        config_.ResetToDefaults();
        UpdateControls(hwnd);
    }
}

void AIConfigDialog::OnBrowseModel(HWND hwnd) {
    wchar_t filename[MAX_PATH] = {};
    
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = L"GGUF Models (*.gguf)\0*.gguf\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = filename;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    
    if (GetOpenFileNameW(&ofn)) {
        SetDlgItemTextW(hwnd, IDC_MODEL_PATH, filename);
        
        // Extract model name from path
        wchar_t* name = wcsrchr(filename, L'\\');
        if (name) {
            name++;
        } else {
            name = filename;
        }
        
        // Remove extension
        wchar_t* ext = wcsrchr(name, L'.');
        if (ext) {
            *ext = L'\0';
        }
        
        char nameA[MAX_PATH];
        WideCharToMultiByte(CP_UTF8, 0, name, -1, nameA, MAX_PATH, nullptr, nullptr);
        config_.modelName = nameA;
    }
}

void AIConfigDialog::OnAdvancedClicked(HWND hwnd) {
    showingAdvanced_ = !showingAdvanced_;
    
    // Show/hide advanced controls
    int showCmd = showingAdvanced_ ? SW_SHOW : SW_HIDE;
    
    ShowWindow(GetDlgItem(hwnd, IDC_ADVANCED_GROUP), showCmd);
    ShowWindow(GetDlgItem(hwnd, IDC_USE_GPU), showCmd);
    ShowWindow(GetDlgItem(hwnd, IDC_GPU_LAYERS), showCmd);
    ShowWindow(GetDlgItem(hwnd, IDC_CONTEXT_LENGTH), showCmd);
    ShowWindow(GetDlgItem(hwnd, IDC_FLASH_ATTENTION), showCmd);
    ShowWindow(GetDlgItem(hwnd, IDC_ENABLE_TELEMETRY), showCmd);
    ShowWindow(GetDlgItem(hwnd, IDC_SHARE_ANONYMOUS), showCmd);
    
    // Update button text
    SetDlgItemTextW(hwnd, ID_ADVANCED_TOGGLE, 
        showingAdvanced_ ? L"Hide Advanced ▲" : L"Show Advanced ▼");
}

void AIConfigDialog::UpdateControls(HWND hwnd) {
    // Re-initialize all controls with current config
    InitDialog(hwnd);
}

} // namespace IDE
} // namespace RawrXD
