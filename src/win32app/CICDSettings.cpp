#include "CICDSettings.h"
#include <commctrl.h>

#pragma comment(lib, "comctl32.lib")

CICDSettings::CICDSettings()
    : m_context(nullptr)
    , m_showCallback(nullptr)
    , m_enabled(false)
    , m_hwnd(nullptr)
{
}

CICDSettings::~CICDSettings() {
    if (m_hwnd) {
        DestroyWindow(m_hwnd);
    }
}

void CICDSettings::show() {
    if (m_showCallback) {
        m_showCallback(m_context);
    }
    createDialog();
}

void CICDSettings::setShowCallback(ShowCallback callback, void* context) {
    m_showCallback = callback;
    m_context = context;
}

void CICDSettings::setPipelineConfig(const std::string& config) {
    m_pipelineConfig = config;
}

std::string CICDSettings::getPipelineConfig() const {
    return m_pipelineConfig;
}

void CICDSettings::setBuildServer(const std::string& server) {
    m_buildServer = server;
}

std::string CICDSettings::getBuildServer() const {
    return m_buildServer;
}

void CICDSettings::setDeployTarget(const std::string& target) {
    m_deployTarget = target;
}

std::string CICDSettings::getDeployTarget() const {
    return m_deployTarget;
}

void CICDSettings::setEnabled(bool enabled) {
    m_enabled = enabled;
}

bool CICDSettings::isEnabled() const {
    return m_enabled;
}

void CICDSettings::createDialog() {
    // Dialog creation implementation
    // This is a stub - full implementation would create actual dialog
}

INT_PTR CALLBACK CICDSettings::dialogProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_INITDIALOG:
        return TRUE;
    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL) {
            EndDialog(hwnd, LOWORD(wParam));
            return TRUE;
        }
        break;
    }
    return FALSE;
}
