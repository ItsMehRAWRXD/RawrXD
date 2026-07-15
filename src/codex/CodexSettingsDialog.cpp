// ============================================================================
// RawrXD Codex Settings Dialog Implementation
// ============================================================================

#include "CodexSettingsDialog.hpp"
#include "CodexCLI.hpp"
#include <windows.h>
#include <commctrl.h>
#include <sstream>
#include <iomanip>

// Trackbar message constants if not defined
#ifndef TBM_SETPOS
#define TBM_SETPOS (WM_USER+5)
#endif
#ifndef TBM_GETPOS
#define TBM_GETPOS (WM_USER+0)
#endif

namespace RawrXD {
namespace Codex {

CodexSettingsDialog::CodexSettingsDialog() = default;
CodexSettingsDialog::~CodexSettingsDialog() = default;

bool CodexSettingsDialog::Initialize(std::shared_ptr<CodexSettingsManager> settings) {
    m_settings = settings;
    m_initialized = true;
    return true;
}

bool CodexSettingsDialog::Show(HWND parentHwnd) {
    if (!m_initialized || !m_settings) {
        return false;
    }

    // Create modal dialog
    // Note: In a real implementation, you'd load from resource or create dynamically
    // This is a simplified version
    return DialogBoxParam(GetModuleHandle(nullptr),
                          MAKEINTRESOURCE(100), // Dialog resource ID
                          parentHwnd,
                          DialogProc,
                          reinterpret_cast<LPARAM>(this)) == IDOK;
}

INT_PTR CALLBACK CodexSettingsDialog::DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    CodexSettingsDialog* pThis = nullptr;

    if (uMsg == WM_INITDIALOG) {
        pThis = reinterpret_cast<CodexSettingsDialog*>(lParam);
        SetWindowLongPtr(hwndDlg, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(pThis));
        pThis->OnInitDialog(hwndDlg);
        return TRUE;
    }

    pThis = reinterpret_cast<CodexSettingsDialog*>(GetWindowLongPtr(hwndDlg, GWLP_USERDATA));
    if (!pThis) {
        return FALSE;
    }

    switch (uMsg) {
        case WM_COMMAND:
            pThis->OnCommand(hwndDlg, LOWORD(wParam),
                            reinterpret_cast<HWND>(lParam), HIWORD(wParam));
            return TRUE;

        case WM_CLOSE:
            pThis->OnCancel(hwndDlg);
            return TRUE;
    }

    return FALSE;
}

void CodexSettingsDialog::OnInitDialog(HWND hwndDlg) {
    m_hwndDialog = hwndDlg;

    // Set dialog title
    SetWindowText(hwndDlg, TEXT("Codex Settings"));

    // Create controls (simplified - in real implementation use resource file)
    // For now, just load existing settings
    LoadSettings();
}

void CodexSettingsDialog::OnCommand(HWND hwndDlg, int id, HWND hwndCtl, UINT codeNotify) {
    switch (id) {
        case IDC_OK:
            OnOK(hwndDlg);
            break;
        case IDC_CANCEL:
            OnCancel(hwndDlg);
            break;
        case IDC_TEST_CONNECTION:
            OnTestConnection(hwndDlg);
            break;
        case IDC_RESET_DEFAULTS:
            OnResetDefaults(hwndDlg);
            break;
    }
}

void CodexSettingsDialog::OnOK(HWND hwndDlg) {
    if (SaveSettings()) {
        EndDialog(hwndDlg, IDOK);
    }
}

void CodexSettingsDialog::OnCancel(HWND hwndDlg) {
    EndDialog(hwndDlg, IDCANCEL);
}

void CodexSettingsDialog::OnTestConnection(HWND hwndDlg) {
    // Test connection to Ollama
    std::string baseUrl = GetWindowTextString(GetDlgItem(hwndDlg, IDC_BASEURL));

    CodexCLI::Config config;
    config.baseUrl = baseUrl;
    config.model = "gemma3";

    CodexCLI cli;
    bool success = cli.Initialize(config);

    if (success) {
        MessageBox(hwndDlg,
                   TEXT("Connection successful!"),
                   TEXT("Test Connection"),
                   MB_OK | MB_ICONINFORMATION);
    } else {
        MessageBox(hwndDlg,
                   TEXT("Failed to connect. Please check the base URL."),
                   TEXT("Test Connection"),
                   MB_OK | MB_ICONERROR);
    }
}

void CodexSettingsDialog::OnResetDefaults(HWND hwndDlg) {
    if (MessageBox(hwndDlg,
                   TEXT("Reset all settings to defaults?"),
                   TEXT("Reset Settings"),
                   MB_YESNO | MB_ICONQUESTION) == IDYES) {
        m_settings->ResetToDefaults();
        LoadSettings();
    }
}

void CodexSettingsDialog::LoadSettings() {
    if (!m_settings) return;

    const auto& settings = m_settings->GetSettings();

    // Model settings
    SetDlgItemText(m_hwndDialog, IDC_MODEL, settings.model.c_str());
    SetDlgItemText(m_hwndDialog, IDC_BASEURL, settings.baseUrl.c_str());

    // Numeric settings
    SetDlgItemInt(m_hwndDialog, IDC_MAXTOKENS, settings.maxTokens, FALSE);

    // Temperature slider (0.0 - 1.0)
    int tempSlider = static_cast<int>(settings.temperature * 100);
    SendDlgItemMessage(m_hwndDialog, IDC_TEMPERATURE, TBM_SETPOS, TRUE, tempSlider);

    // Confidence threshold
    int confSlider = static_cast<int>(settings.confidenceThreshold * 100);
    SendDlgItemMessage(m_hwndDialog, IDC_CONFIDENCE, TBM_SETPOS, TRUE, confSlider);

    // Checkboxes
    SetCheckbox(GetDlgItem(m_hwndDialog, IDC_ENABLE_INLINE), settings.enableInlineCompletions);
    SetCheckbox(GetDlgItem(m_hwndDialog, IDC_ENABLE_CHAT), settings.enableChat);
    SetCheckbox(GetDlgItem(m_hwndDialog, IDC_ENABLE_CODEACTIONS), settings.enableCodeActions);
    SetCheckbox(GetDlgItem(m_hwndDialog, IDC_ENABLE_HOVER), settings.enableHoverInfo);
    SetCheckbox(GetDlgItem(m_hwndDialog, IDC_STREAMING), settings.streamingEnabled);

    // System prompt
    SetDlgItemText(m_hwndDialog, IDC_SYSTEM_PROMPT, settings.systemPrompt.c_str());
}

bool CodexSettingsDialog::SaveSettings() {
    if (!m_settings) return false;

    auto& settings = m_settings->GetSettingsMutable();

    // Model settings
    settings.model = GetWindowTextString(GetDlgItem(m_hwndDialog, IDC_MODEL));
    settings.baseUrl = GetWindowTextString(GetDlgItem(m_hwndDialog, IDC_BASEURL));
    settings.maxTokens = GetWindowInt(GetDlgItem(m_hwndDialog, IDC_MAXTOKENS));

    // Temperature
    int tempSlider = static_cast<int>(SendDlgItemMessage(m_hwndDialog, IDC_TEMPERATURE, TBM_GETPOS, 0, 0));
    settings.temperature = tempSlider / 100.0f;

    // Confidence threshold
    int confSlider = static_cast<int>(SendDlgItemMessage(m_hwndDialog, IDC_CONFIDENCE, TBM_GETPOS, 0, 0));
    settings.confidenceThreshold = confSlider / 100.0f;

    // Checkboxes
    settings.enableInlineCompletions = IsCheckboxChecked(GetDlgItem(m_hwndDialog, IDC_ENABLE_INLINE));
    settings.enableChat = IsCheckboxChecked(GetDlgItem(m_hwndDialog, IDC_ENABLE_CHAT));
    settings.enableCodeActions = IsCheckboxChecked(GetDlgItem(m_hwndDialog, IDC_ENABLE_CODEACTIONS));
    settings.enableHoverInfo = IsCheckboxChecked(GetDlgItem(m_hwndDialog, IDC_ENABLE_HOVER));
    settings.streamingEnabled = IsCheckboxChecked(GetDlgItem(m_hwndDialog, IDC_STREAMING));

    // System prompt
    settings.systemPrompt = GetWindowTextString(GetDlgItem(m_hwndDialog, IDC_SYSTEM_PROMPT));

    // Save to disk
    return m_settings->Save();
}

std::string CodexSettingsDialog::GetWindowTextString(HWND hwnd) {
    if (!hwnd) return "";

    int len = GetWindowTextLengthW(hwnd);
    if (len == 0) return "";

    std::wstring wtext(len + 1, 0);
    GetWindowTextW(hwnd, &wtext[0], len + 1);

    // Convert to UTF-8
    int size = WideCharToMultiByte(CP_UTF8, 0, wtext.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string result(size - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wtext.c_str(), -1, &result[0], size, nullptr, nullptr);
    return result;
}

int CodexSettingsDialog::GetWindowInt(HWND hwnd) {
    std::string text = GetWindowTextString(hwnd);
    try {
        return std::stoi(text);
    } catch (...) {
        return 0;
    }
}

float CodexSettingsDialog::GetWindowFloat(HWND hwnd) {
    std::string text = GetWindowTextString(hwnd);
    try {
        return std::stof(text);
    } catch (...) {
        return 0.0f;
    }
}

bool CodexSettingsDialog::IsCheckboxChecked(HWND hwnd) {
    if (!hwnd) return false;
    return SendMessage(hwnd, BM_GETCHECK, 0, 0) == BST_CHECKED;
}

void CodexSettingsDialog::SetCheckbox(HWND hwnd, bool checked) {
    if (!hwnd) return;
    SendMessage(hwnd, BM_SETCHECK, checked ? BST_CHECKED : BST_UNCHECKED, 0);
}

} // namespace Codex
} // namespace RawrXD
