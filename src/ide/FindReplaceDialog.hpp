/**
 * @file FindReplaceDialog.hpp
 * @brief Find and Replace Dialog for RawrXD IDE
 * @status PRODUCTION - Full search/replace functionality
 */

#pragma once

#include <windows.h>
#include <string>
#include <functional>

namespace RawrXD::IDE {

enum class FindDirection {
    Forward,
    Backward
};

enum class FindScope {
    CurrentDocument,
    AllDocuments,
    Selection
};

struct FindOptions {
    bool caseSensitive = false;
    bool wholeWord = false;
    bool useRegex = false;
    FindDirection direction = FindDirection::Forward;
    FindScope scope = FindScope::CurrentDocument;
    bool wrapAround = true;
};

class FindReplaceDialog {
public:
    FindReplaceDialog();
    ~FindReplaceDialog();
    
    // Creation
    bool Create(HWND hwndParent, bool replaceMode = false);
    void Destroy();
    bool IsVisible() const;
    
    // Set search text from editor selection
    void SetFindText(const std::string& text);
    void SetReplaceText(const std::string& text);
    
    // Callbacks
    void SetFindCallback(std::function<bool(const std::string&, const FindOptions&)> callback);
    void SetReplaceCallback(std::function<bool(const std::string&, const std::string&, const FindOptions&)> callback);
    void SetReplaceAllCallback(std::function<int(const std::string&, const std::string&, const FindOptions&)> callback);
    
    // Get current options
    FindOptions GetOptions() const { return m_options; }
    std::string GetFindText() const { return m_findText; }
    std::string GetReplaceText() const { return m_replaceText; }
    
    // Window procedure
    static INT_PTR CALLBACK DialogProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

private:
    HWND m_hwnd;
    HWND m_hwndParent;
    bool m_replaceMode;
    
    // State
    FindOptions m_options;
    std::string m_findText;
    std::string m_replaceText;
    
    // Callbacks
    std::function<bool(const std::string&, const FindOptions&)> m_findCallback;
    std::function<bool(const std::string&, const std::string&, const FindOptions&)> m_replaceCallback;
    std::function<int(const std::string&, const std::string&, const FindOptions&)> m_replaceAllCallback;
    
    // UI controls
    HWND m_hwndFindEdit;
    HWND m_hwndReplaceEdit;
    HWND m_hwndCaseCheck;
    HWND m_hwndWholeWordCheck;
    HWND m_hwndRegexCheck;
    HWND m_hwndWrapCheck;
    HWND m_hwndUpRadio;
    HWND m_hwndDownRadio;
    
    // Helpers
    void UpdateOptionsFromUI();
    void DoFind();
    void DoReplace();
    void DoReplaceAll();
    INT_PTR HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam);
    void CenterOnParent();
};

/**
 * @brief Quick find bar (like VS Code's Ctrl+F inline search)
 */
class QuickFindBar {
public:
    QuickFindBar();
    ~QuickFindBar();
    
    bool Create(HWND hwndParent);
    void Show();
    void Hide();
    bool IsVisible() const;
    
    void SetFindText(const std::string& text);
    void SetResultCount(int current, int total);
    
    void SetFindCallback(std::function<void(const std::string&, bool forward)> callback);
    void SetCloseCallback(std::function<void()> callback);

private:
    HWND m_hwnd;
    HWND m_hwndParent;
    HWND m_hwndEdit;
    HWND m_hwndResultLabel;
    
    std::function<void(const std::string&, bool forward)> m_findCallback;
    std::function<void()> m_closeCallback;
    
    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    LRESULT HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam);
};

} // namespace RawrXD::IDE
