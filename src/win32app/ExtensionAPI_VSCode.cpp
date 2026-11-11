// ExtensionAPI_VSCode.cpp — VS Code Extension API Implementation (Batch 5 X02)
#include "ExtensionAPI_VSCode.h"
#include "ExtensionSandboxManager.h"
#include "ExtensionHost.h"
#include "IDELogger.h"
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <regex>
#include <sstream>
#include <windows.h>
#include <Shlobj.h>
#include <shellapi.h>

#pragma comment(lib, "Shell32.lib")

namespace RawrXD::Extensions::VSCodeAPI {

namespace {

std::string normalizePathForMatch(std::string path) {
    std::transform(path.begin(), path.end(), path.begin(), [](unsigned char ch) {
        if (ch == '\\') return '/';
        return static_cast<char>(std::tolower(ch));
    });
    return path;
}

std::regex globToRegex(const std::string& pattern) {
    std::string regexText;
    regexText.reserve(pattern.size() * 2);
    regexText += '^';
    const std::string normalized = normalizePathForMatch(pattern);
    for (size_t index = 0; index < normalized.size(); ++index) {
        const char ch = normalized[index];
        if (ch == '*') {
            const bool isDoubleStar = (index + 1 < normalized.size() && normalized[index + 1] == '*');
            if (isDoubleStar) { regexText += ".*"; ++index; }
            else { regexText += "[^/]*"; }
            continue;
        }
        if (ch == '?') { regexText += '.'; continue; }
        if (std::string(".^$|()[]{}+\\").find(ch) != std::string::npos) {
            regexText += '\\';
        }
        regexText += ch;
    }
    regexText += '$';
    return std::regex(regexText);
}

} // namespace

Uri Uri::File(const std::string& path) { return Uri("file", path); }
Uri Uri::Parse(const std::string& value) { return Uri("file", value); }
std::string Uri::ToString() const { return m_scheme + "://" + m_path; }
Uri::Uri(const std::string& scheme, const std::string& path) : m_scheme(scheme), m_path(path) {}

std::string TextDocument::getText() const { return ""; }

void Window::showInformationMessage(const std::string& message) {
    LOG_INFO("[VSCodeAPI] " + message);
}

void Window::showErrorMessage(const std::string& message) {
    LOG_ERROR("[VSCodeAPI] " + message);
}

void Commands::registerCommand(const std::string& command, std::function<void()> callback) {
    LOG_INFO("[VSCodeAPI] Registered command: " + command);
}

void Commands::executeCommand(const std::string& command) {
    LOG_INFO("[VSCodeAPI] Executing command: " + command);
}

Window window;
Workspace workspace;
Commands commands;

} // namespace RawrXD::Extensions::VSCodeAPI
