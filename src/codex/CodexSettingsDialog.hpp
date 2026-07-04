// ============================================================================
// RawrXD Codex Settings Dialog
// Win32 settings dialog for Codex configuration
// ============================================================================

#pragma once
#include "CodexSettings.hpp"
#include <windows.h>
#include <string>
#include <functional>

namespace RawrXD {
namespace Codex {

// Settings Dialog for Codex configuration
class CodexSettingsDialog {
public:
    CodexSettingsDialog();
    ~CodexSettingsDialog();

    // Initialize with settings manager
    bool Initialize(std::shared_ptr<CodexSettingsManager> settings);

    // Show the dialog
    // Returns true if user clicked OK, false if cancelled
    bool Show(HWND parentHwnd);

    // Dialog procedure (static)
    static INT_PTR CALLBACK DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);

private:
    std::shared_ptr<CodexSettingsManager> m_settings;
    HWND m_hwndDialog = nullptr;
    bool m_initialized = false;

    // Control IDs
    enum ControlID {
        IDC_MODEL = 100,
        IDC_BASEURL,
        IDC_MAXTOKENS,
        IDC_TEMPERATURE,
        IDC_ENABLE_INLINE,
        IDC_ENABLE_CHAT,
        IDC_ENABLE_CODEACTIONS,
        IDC_ENABLE_HOVER,
        IDC_STREAMING,
        IDC_CONFIDENCE,
        IDC_SYSTEM_PROMPT,
        IDC_TEST_CONNECTION,
        IDC_RESET_DEFAULTS,
        IDC_OK,
        IDC_CANCEL
    };

    // Dialog message handlers
    void OnInitDialog(HWND hwndDlg);
    void OnCommand(HWND hwndDlg, int id, HWND hwndCtl, UINT codeNotify);
    void OnOK(HWND hwndDlg);
    void OnCancel(HWND hwndDlg);
    void OnTestConnection(HWND hwndDlg);
    void OnResetDefaults(HWND hwndDlg);

    // Load settings into controls
    void LoadSettings();

    // Save settings from controls
    bool SaveSettings();

    // Helper methods
    std::string GetWindowTextString(HWND hwnd);
    int GetWindowInt(HWND hwnd);
    float GetWindowFloat(HWND hwnd);
    bool IsCheckboxChecked(HWND hwnd);
    void SetCheckbox(HWND hwnd, bool checked);
};

} // namespace Codex
} // namespace RawrXD
