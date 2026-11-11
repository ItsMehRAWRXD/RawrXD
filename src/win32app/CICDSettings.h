#pragma once

#include <windows.h>
#include <string>
#include <functional>

// CI/CD Settings Panel for RawrXD IDE
class CICDSettings {
public:
    CICDSettings();
    ~CICDSettings();

    // Show the CI/CD settings dialog
    void show();

    // Set callback for when dialog is shown
    using ShowCallback = std::function<void(void*)>;
    void setShowCallback(ShowCallback callback, void* context);

    // Configuration methods
    void setPipelineConfig(const std::string& config);
    std::string getPipelineConfig() const;

    void setBuildServer(const std::string& server);
    std::string getBuildServer() const;

    void setDeployTarget(const std::string& target);
    std::string getDeployTarget() const;

    // Enable/disable CI/CD integration
    void setEnabled(bool enabled);
    bool isEnabled() const;

private:
    void* m_context;
    ShowCallback m_showCallback;
    std::string m_pipelineConfig;
    std::string m_buildServer;
    std::string m_deployTarget;
    bool m_enabled;
    HWND m_hwnd;

    void createDialog();
    static INT_PTR CALLBACK dialogProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
};
