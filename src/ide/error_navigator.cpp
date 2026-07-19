/**
 * @file error_navigator.cpp
 * @brief Build Output Parser Implementation - Real Error Navigation
 * @status PRODUCTION - MSVC/Clang/GCC error parsing
 */

#include "error_navigator.h"
#include <windows.h>
#include <richedit.h>
#include <regex>
#include <sstream>
#include <fstream>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

namespace RawrXD::IDE {

// Error patterns
// MSVC: file.cpp(123): error C1234: message
static const std::regex MSVC_ERROR_REGEX(
    R"(([^:]+)\((\d+)\)(?:\((\d+)\))?\s*:\s*(error|warning|note)\s+([A-Z]?\d+)?:\s*(.+))");

// Clang: file.cpp:123:5: error: message [-Wflag]
static const std::regex CLANG_ERROR_REGEX(
    R"(([^:]+):(\d+):(\d+):\s*(error|warning|note):\s*(.+?)(?:\s+\[([^\]]+)\])?)");

// GCC: file.cpp:123:5: error: message
static const std::regex GCC_ERROR_REGEX(
    R"(([^:]+):(\d+):(\d+):\s*(error|warning|note):\s*(.+))");

// MSBuild: project.vcxproj(123): error : message
static const std::regex MSBUILD_ERROR_REGEX(
    R"(([^)]+)\((\d+)\)\s*:\s*(error|warning)\s*:?\s*(.+))");

ErrorNavigator::ErrorNavigator() : m_currentIndex(0) {}

ErrorNavigator::~ErrorNavigator() = default;

void ErrorNavigator::ParseBuildOutput(const std::string& output) {
    Clear();
    
    // Detect output format
    if (output.find("cl.exe") != std::string::npos ||
        output.find("Microsoft") != std::string::npos ||
        output.find(".vcxproj") != std::string::npos) {
        ParseMSVCOutput(output);
    } else if (output.find("clang") != std::string::npos) {
        ParseClangOutput(output);
    } else if (output.find("gcc") != std::string::npos ||
               output.find("g++") != std::string::npos) {
        ParseGCCOutput(output);
    } else {
        // Try all parsers
        ParseMSVCOutput(output);
        if (m_errors.empty()) ParseClangOutput(output);
        if (m_errors.empty()) ParseGCCOutput(output);
    }
    
    // Update UI
    if (m_listCallback) {
        m_listCallback(m_errors);
    }
}

void ErrorNavigator::ParseBuildOutput(const std::wstring& output) {
    std::string narrow(output.begin(), output.end());
    ParseBuildOutput(narrow);
}

void ErrorNavigator::Clear() {
    m_errors.clear();
    m_currentIndex = 0;
}

void ErrorNavigator::ParseMSVCOutput(const std::string& output) {
    std::istringstream stream(output);
    std::string line;
    size_t position = 0;
    
    while (std::getline(stream, line)) {
        std::smatch match;
        if (std::regex_match(line, match, MSVC_ERROR_REGEX)) {
            BuildError error;
            error.file = match[1];
            error.line = std::stoul(match[2]);
            error.column = match[3].length() > 0 ? std::stoul(match[3]) : 0;
            
            std::string severityStr = match[4];
            if (severityStr == "error") error.severity = ErrorSeverity::Error;
            else if (severityStr == "warning") error.severity = ErrorSeverity::Warning;
            else error.severity = ErrorSeverity::Note;
            
            error.code = match[5];
            error.message = match[6];
            error.originalLine = line;
            error.position = position;
            
            NormalizePaths(error);
            m_errors.push_back(error);
        }
        position += line.length() + 1;  // +1 for newline
    }
}

void ErrorNavigator::ParseClangOutput(const std::string& output) {
    std::istringstream stream(output);
    std::string line;
    size_t position = 0;
    
    while (std::getline(stream, line)) {
        std::smatch match;
        if (std::regex_match(line, match, CLANG_ERROR_REGEX)) {
            BuildError error;
            error.file = match[1];
            error.line = std::stoul(match[2]);
            error.column = std::stoul(match[3]);
            
            std::string severityStr = match[4];
            if (severityStr == "error") error.severity = ErrorSeverity::Error;
            else if (severityStr == "warning") error.severity = ErrorSeverity::Warning;
            else error.severity = ErrorSeverity::Note;
            
            error.message = match[5];
            error.code = match[6].length() > 0 ? match[6] : "";
            error.originalLine = line;
            error.position = position;
            
            NormalizePaths(error);
            m_errors.push_back(error);
        }
        position += line.length() + 1;
    }
}

void ErrorNavigator::ParseGCCOutput(const std::string& output) {
    std::istringstream stream(output);
    std::string line;
    size_t position = 0;
    
    while (std::getline(stream, line)) {
        std::smatch match;
        if (std::regex_match(line, match, GCC_ERROR_REGEX)) {
            BuildError error;
            error.file = match[1];
            error.line = std::stoul(match[2]);
            error.column = std::stoul(match[3]);
            
            std::string severityStr = match[4];
            if (severityStr == "error") error.severity = ErrorSeverity::Error;
            else if (severityStr == "warning") error.severity = ErrorSeverity::Warning;
            else error.severity = ErrorSeverity::Note;
            
            error.message = match[5];
            error.originalLine = line;
            error.position = position;
            
            NormalizePaths(error);
            m_errors.push_back(error);
        }
        position += line.length() + 1;
    }
}

void ErrorNavigator::NormalizePaths(BuildError& error) {
    // Convert to absolute path if relative
    if (!PathIsRelativeA(error.file.c_str())) return;
    
    char fullPath[MAX_PATH];
    if (GetFullPathNameA(error.file.c_str(), MAX_PATH, fullPath, nullptr)) {
        error.file = fullPath;
    }
}

bool ErrorNavigator::CanGoToNextError() const {
    return m_currentIndex + 1 < m_errors.size();
}

bool ErrorNavigator::CanGoToPreviousError() const {
    return m_currentIndex > 0;
}

bool ErrorNavigator::GoToNextError() {
    if (!CanGoToNextError()) return false;
    
    m_currentIndex++;
    if (m_navCallback) {
        m_navCallback(m_errors[m_currentIndex]);
    }
    return true;
}

bool ErrorNavigator::GoToPreviousError() {
    if (!CanGoToPreviousError()) return false;
    
    m_currentIndex--;
    if (m_navCallback) {
        m_navCallback(m_errors[m_currentIndex]);
    }
    return true;
}

bool ErrorNavigator::GoToError(size_t index) {
    if (index >= m_errors.size()) return false;
    
    m_currentIndex = index;
    if (m_navCallback) {
        m_navCallback(m_errors[m_currentIndex]);
    }
    return true;
}

const BuildError* ErrorNavigator::GetCurrentError() const {
    if (m_currentIndex >= m_errors.size()) return nullptr;
    return &m_errors[m_currentIndex];
}

const BuildError* ErrorNavigator::GetError(size_t index) const {
    if (index >= m_errors.size()) return nullptr;
    return &m_errors[index];
}

std::vector<BuildError> ErrorNavigator::GetErrorsBySeverity(ErrorSeverity severity) const {
    std::vector<BuildError> result;
    for (const auto& error : m_errors) {
        if (error.severity == severity) {
            result.push_back(error);
        }
    }
    return result;
}

std::vector<BuildError> ErrorNavigator::GetErrorsByFile(const std::string& file) const {
    std::vector<BuildError> result;
    for (const auto& error : m_errors) {
        if (error.file == file) {
            result.push_back(error);
        }
    }
    return result;
}

std::vector<ErrorGroup> ErrorNavigator::GetGroupedErrors() const {
    std::map<std::string, ErrorGroup> groups;
    
    for (const auto& error : m_errors) {
        auto& group = groups[error.file];
        group.file = error.file;
        group.errors.push_back(error);
        if (error.severity == ErrorSeverity::Error) group.errorCount++;
        else if (error.severity == ErrorSeverity::Warning) group.warningCount++;
    }
    
    std::vector<ErrorGroup> result;
    for (auto& [file, group] : groups) {
        result.push_back(group);
    }
    return result;
}

size_t ErrorNavigator::GetErrorCount(ErrorSeverity severity) const {
    size_t count = 0;
    for (const auto& error : m_errors) {
        if (error.severity == severity) count++;
    }
    return count;
}

void ErrorNavigator::SetNavigationCallback(std::function<void(const BuildError&)> callback) {
    m_navCallback = callback;
}

void ErrorNavigator::SetErrorListCallback(std::function<void(const std::vector<BuildError&)> callback) {
    m_listCallback = callback;
}

bool ErrorNavigator::HandleF4Key() {
    return GoToNextError();
}

bool ErrorNavigator::HandleShiftF4Key() {
    return GoToPreviousError();
}

std::string ErrorNavigator::FormatErrorForIDE(const BuildError& error) const {
    std::stringstream ss;
    ss << error.file << "(" << error.line << ")";
    if (error.column > 0) {
        ss << "," << error.column;
    }
    ss << ": ";
    
    switch (error.severity) {
        case ErrorSeverity::Error: ss << "error"; break;
        case ErrorSeverity::Warning: ss << "warning"; break;
        case ErrorSeverity::Information: ss << "info"; break;
        case ErrorSeverity::Note: ss << "note"; break;
    }
    
    if (!error.code.empty()) {
        ss << " " << error.code;
    }
    
    ss << ": " << error.message;
    return ss.str();
}

bool ErrorNavigator::TryNavigateFromPosition(size_t charPosition) {
    // Find error closest to position
    for (size_t i = 0; i < m_errors.size(); i++) {
        if (m_errors[i].position <= charPosition &&
            (i + 1 >= m_errors.size() || m_errors[i + 1].position > charPosition)) {
            return GoToError(i);
        }
    }
    return false;
}

bool ErrorNavigator::ExportToCSV(const std::string& path) const {
    std::ofstream file(path);
    if (!file.is_open()) return false;
    
    file << "Severity,File,Line,Column,Code,Message\n";
    
    for (const auto& error : m_errors) {
        file << (error.severity == ErrorSeverity::Error ? "Error" : 
                   error.severity == ErrorSeverity::Warning ? "Warning" : "Note")
            << ",";
        file << "\"" << error.file << "\",";
        file << error.line << ",";
        file << error.column << ",";
        file << "\"" << error.code << "\",";
        file << "\"" << error.message << "\"\n";
    }
    
    return true;
}

bool ErrorNavigator::ExportToMSBuildFormat(const std::string& path) const {
    std::ofstream file(path);
    if (!file.is_open()) return false;
    
    file << "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
    file << "<BuildLog>\n";
    
    for (const auto& error : m_errors) {
        file << "  <Error\n";
        file << "    File=\"" << error.file << "\"\n";
        file << "    Line=\"" << error.line << "\"\n";
        file << "    Column=\"" << error.column << "\"\n";
        file << "    Code=\"" << error.code << "\"\n";
        file << "    Severity=\"" 
            << (error.severity == ErrorSeverity::Error ? "Error" : "Warning")
            << "\"\n";
        file << "    Message=\"" << error.message << "\" /\u003e\n";
    }
    
    file << "</BuildLog>\n";
    return true;
}

// ErrorOutputWindow implementation
ErrorOutputWindow::ErrorOutputWindow() : m_hwnd(nullptr), m_navigator(nullptr) {}

ErrorOutputWindow::~ErrorOutputWindow() = default;

void ErrorOutputWindow::AttachToHWND(HWND hwnd) {
    m_hwnd = hwnd;
    SetupRichEdit();
}

void ErrorOutputWindow::SetErrorNavigator(ErrorNavigator* navigator) {
    m_navigator = navigator;
}

void ErrorOutputWindow::AppendBuildOutput(const std::string& text) {
    if (!m_hwnd) return;
    
    // Convert to wide
    int len = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, nullptr, 0);
    std::wstring wtext(len, 0);
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, &wtext[0], len);
    
    // Append to Rich Edit
    CHARRANGE cr;
    cr.cpMin = -1;
    cr.cpMax = -1;
    SendMessage(m_hwnd, EM_EXSETSEL, 0, (LPARAM)&cr);
    SendMessage(m_hwnd, EM_REPLACESEL, FALSE, (LPARAM)wtext.c_str());
    
    ScrollToEnd();
}

void ErrorOutputWindow::AppendBuildOutput(const std::wstring& text) {
    if (!m_hwnd) return;
    
    CHARRANGE cr;
    cr.cpMin = -1;
    cr.cpMax = -1;
    SendMessage(m_hwnd, EM_EXSETSEL, 0, (LPARAM)&cr);
    SendMessage(m_hwnd, EM_REPLACESEL, FALSE, (LPARAM)text.c_str());
    
    ScrollToEnd();
}

void ErrorOutputWindow::Clear() {
    if (!m_hwnd) return;
    SetWindowText(m_hwnd, L"");
}

void ErrorOutputWindow::SetupRichEdit() {
    if (!m_hwnd) return;
    
    // Set font
    HFONT hFont = CreateFont(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                            DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");
    SendMessage(m_hwnd, WM_SETFONT, (WPARAM)hFont, TRUE);
    
    // Set background color
    SendMessage(m_hwnd, EM_SETBKGNDCOLOR, 0, RGB(30, 30, 30));
}

void ErrorOutputWindow::ScrollToEnd() {
    if (!m_hwnd) return;
    SendMessage(m_hwnd, WM_VSCROLL, SB_BOTTOM, 0);
}

void ErrorOutputWindow::ColorizeErrors() {
    // Colorize error lines in Rich Edit
    // TODO: Implement with EM_SETCHARFORMAT
}

bool ErrorOutputWindow::ProcessWindowMessage(UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_LBUTTONDBLCLK:
            if (m_navigator) {
                // Get cursor position and find error
                POINT pt;
                pt.x = LOWORD(lParam);
                pt.y = HIWORD(lParam);
                
                // Convert to character position
                int charPos = (int)SendMessage(m_hwnd, EM_CHARFROMPOS, 0, MAKELPARAM(pt.x, pt.y));
                return m_navigator->TryNavigateFromPosition(charPos);
            }
            break;
            
        case WM_KEYDOWN:
            if (wParam == VK_F4) {
                if (GetKeyState(VK_SHIFT) < 0) {
                    if (m_navigator) return m_navigator->HandleShiftF4Key();
                } else {
                    if (m_navigator) return m_navigator->HandleF4Key();
                }
            }
            break;
    }
    return false;
}

} // namespace RawrXD::IDE
