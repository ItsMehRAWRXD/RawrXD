/**
 * @file error_navigator.h
 * @brief Build Output Parser - Real Error Navigation with F4 Support
 * @status PRODUCTION - MSVC/Clang/GCC error parsing
 */

#pragma once

#include <string>
#include <vector>
#include <functional>
#include <windows.h>

namespace RawrXD::IDE {

enum class ErrorSeverity {
    Error,
    Warning,
    Information,
    Note
};

struct BuildError {
    std::string file;
    uint32_t line;
    uint32_t column;
    ErrorSeverity severity;
    std::string code;
    std::string message;
    std::string originalLine;
    size_t position;  // Position in build output for navigation
};

struct ErrorGroup {
    std::string file;
    std::vector<BuildError> errors;
    size_t errorCount = 0;
    size_t warningCount = 0;
};

class ErrorNavigator {
public:
    ErrorNavigator();
    ~ErrorNavigator();
    
    // Parsing
    void ParseBuildOutput(const std::string& output);
    void ParseBuildOutput(const std::wstring& output);
    void Clear();
    
    // Navigation
    bool CanGoToNextError() const;
    bool CanGoToPreviousError() const;
    bool GoToNextError();
    bool GoToPreviousError();
    bool GoToError(size_t index);
    const BuildError* GetCurrentError() const;
    const BuildError* GetError(size_t index) const;
    
    // Queries
    size_t GetErrorCount() const { return m_errors.size(); }
    size_t GetErrorCount(ErrorSeverity severity) const;
    std::vector<BuildError> GetErrorsBySeverity(ErrorSeverity severity) const;
    std::vector<BuildError> GetErrorsByFile(const std::string& file) const;
    std::vector<ErrorGroup> GetGroupedErrors() const;
    
    // Keyboard shortcuts
    bool HandleF4Key();       // Next error
    bool HandleShiftF4Key();  // Previous error
    
    // Callbacks
    void SetNavigationCallback(std::function<void(const BuildError&)> callback);
    void SetErrorListCallback(std::function<void(const std::vector<BuildError>&)> callback);
    
    // Utilities
    std::string FormatErrorForIDE(const BuildError& error) const;
    bool TryNavigateFromPosition(size_t charPosition);
    
    // Export
    bool ExportToCSV(const std::string& path) const;
    bool ExportToMSBuildFormat(const std::string& path) const;

private:
    std::vector<BuildError> m_errors;
    size_t m_currentIndex;
    
    std::function<void(const BuildError&)> m_navCallback;
    std::function<void(const std::vector<BuildError>&)> m_listCallback;
    
    void ParseMSVCOutput(const std::string& output);
    void ParseClangOutput(const std::string& output);
    void ParseGCCOutput(const std::string& output);
    void NormalizePaths(BuildError& error);
};

// Output window integration
class ErrorOutputWindow {
public:
    ErrorOutputWindow();
    ~ErrorOutputWindow();
    
    void AttachToHWND(HWND hwnd);
    void SetErrorNavigator(ErrorNavigator* navigator);
    
    void AppendBuildOutput(const std::string& text);
    void AppendBuildOutput(const std::wstring& text);
    void Clear();
    
    bool ProcessWindowMessage(UINT msg, WPARAM wParam, LPARAM lParam);

private:
    HWND m_hwnd;
    ErrorNavigator* m_navigator;
    
    void SetupRichEdit();
    void ScrollToEnd();
    void ColorizeErrors();
};

} // namespace RawrXD::IDE
