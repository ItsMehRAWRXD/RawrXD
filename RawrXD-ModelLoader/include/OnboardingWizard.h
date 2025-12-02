// OnboardingWizard.h - First-run onboarding wizard header

#pragma once
#include <windows.h>
#include <string>
#include <vector>

namespace RawrXD {

enum class PageType {
    Welcome,
    GitHubAuth,
    CopilotSetup,
    TemplateSelection,
    Completion
};

struct WizardPage {
    std::wstring title;
    std::wstring description;
    PageType type;
};

class OnboardingWizard {
public:
    explicit OnboardingWizard(HWND parent);
    ~OnboardingWizard();
    
    static bool ShouldShow();
    void Show();
    
private:
    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    LRESULT HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam);
    
    void OnCreate();
    void OnPaint();
    void OnCommand(WORD cmdId);
    
    void CreatePages();
    void ShowPage(size_t pageIndex);
    void CreateWelcomePage();
    void CreateGitHubAuthPage();
    void CreateCopilotPage();
    void CreateTemplatePage();
    void CreateCompletionPage();
    
    void UpdateNavigationButtons();
    void DrawPage(HDC hdc);
    bool ValidateCurrentPage();
    
    void StartGitHubAuthentication();
    void CheckCopilotStatus();
    void CompleteWizard();
    
    void LoadConfiguration();
    void SaveConfiguration();
    
    HWND m_hwndParent;
    HWND m_hwnd;
    HWND m_hwndBtnNext = nullptr;
    HWND m_hwndBtnBack = nullptr;
    HWND m_hwndBtnCancel = nullptr;
    HWND m_hwndAuthStatus = nullptr;
    
    std::vector<WizardPage> m_pages;
    std::vector<HWND> m_pageControls;
    size_t m_currentPage;
    
    bool m_gitHubAuthenticated;
    bool m_copilotEnabled;
    int m_selectedTemplate = -1;
    
    // Control IDs
    enum {
        BTN_NEXT = 1001,
        BTN_BACK = 1002,
        BTN_CANCEL = 1003,
        BTN_GITHUB_AUTH = 1004,
        BTN_SKIP_AUTH = 1005,
        BTN_OPEN_COPILOT = 1006,
        LST_TEMPLATES = 1007
    };
};

} // namespace RawrXD
