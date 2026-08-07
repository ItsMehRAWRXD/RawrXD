// ============================================================================
// GitUI.cpp - Production Git Diff/Blame UI Implementation
// ============================================================================

#include "GitUI.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <regex>
#include <chrono>
#include <ctime>

namespace rawrxd::scm {

// ============================================================================
// Constructor / Destructor
// ============================================================================
GitUI::GitUI() = default;

GitUI::~GitUI() {
    Shutdown();
}

GitUI::GitUI(GitUI&& other) noexcept
    : m_config(std::move(other.m_config))
    , m_initialized(other.m_initialized)
    , m_hParent(other.m_hParent)
    , m_lastError(std::move(other.m_lastError))
    , m_commitCache(std::move(other.m_commitCache))
    , m_blameCache(std::move(other.m_blameCache))
    , m_hDiffViewer(other.m_hDiffViewer)
    , m_hBlameViewer(other.m_hBlameViewer)
    , m_hLogViewer(other.m_hLogViewer) {
    other.m_initialized = false;
    other.m_hParent = nullptr;
    other.m_hDiffViewer = nullptr;
    other.m_hBlameViewer = nullptr;
    other.m_hLogViewer = nullptr;
}

GitUI& GitUI::operator=(GitUI&& other) noexcept {
    if (this != &other) {
        Shutdown();
        m_config = std::move(other.m_config);
        m_initialized = other.m_initialized;
        m_hParent = other.m_hParent;
        m_lastError = std::move(other.m_lastError);
        m_commitCache = std::move(other.m_commitCache);
        m_blameCache = std::move(other.m_blameCache);
        m_hDiffViewer = other.m_hDiffViewer;
        m_hBlameViewer = other.m_hBlameViewer;
        m_hLogViewer = other.m_hLogViewer;
        
        other.m_initialized = false;
        other.m_hParent = nullptr;
        other.m_hDiffViewer = nullptr;
        other.m_hBlameViewer = nullptr;
        other.m_hLogViewer = nullptr;
    }
    return *this;
}

// ============================================================================
// Initialization
// ============================================================================
bool GitUI::Initialize(const GitConfig& config) {
    if (m_initialized) return true;
    
    m_config = config;
    
    // Verify git is available
    int exitCode = 0;
    ExecuteGitCommand("--version", &exitCode);
    if (exitCode != 0) {
        m_lastError = "Git executable not found: " + m_config.gitExecutable;
        return false;
    }
    
    // Check if we're in a repository
    if (!IsRepository()) {
        m_lastError = "Not a git repository";
        return false;
    }
    
    m_initialized = true;
    return true;
}

void GitUI::Shutdown() {
    if (m_hDiffViewer) { DestroyWindow(m_hDiffViewer); m_hDiffViewer = nullptr; }
    if (m_hBlameViewer) { DestroyWindow(m_hBlameViewer); m_hBlameViewer = nullptr; }
    if (m_hLogViewer) { DestroyWindow(m_hLogViewer); m_hLogViewer = nullptr; }
    
    m_commitCache.clear();
    m_blameCache.clear();
    m_initialized = false;
}

// ============================================================================
// Diff Operations
// ============================================================================
bool GitUI::ShowWorkingDirectoryDiff(const std::string& filePath) {
    auto diff = GetDiff("HEAD", "", filePath);
    if (diff.empty() && !m_lastError.empty()) return false;
    
    // Create viewer window if needed
    if (!m_hDiffViewer || !IsWindow(m_hDiffViewer)) {
        RECT rc = {0, 0, 800, 600};
        m_hDiffViewer = CreateDiffViewer(m_hParent, rc);
    }
    
    UpdateDiffViewer(m_hDiffViewer, diff);
    ShowWindow(m_hDiffViewer, SW_SHOW);
    return true;
}

bool GitUI::ShowCommitDiff(const std::string& commitHash, const std::string& filePath) {
    auto diff = GetDiff(commitHash + "^", commitHash, filePath);
    if (diff.empty() && !m_lastError.empty()) return false;
    
    if (!m_hDiffViewer || !IsWindow(m_hDiffViewer)) {
        RECT rc = {0, 0, 800, 600};
        m_hDiffViewer = CreateDiffViewer(m_hParent, rc);
    }
    
    UpdateDiffViewer(m_hDiffViewer, diff);
    ShowWindow(m_hDiffViewer, SW_SHOW);
    return true;
}

bool GitUI::ShowDiffRange(const std::string& oldCommit, const std::string& newCommit,
                          const std::string& filePath) {
    auto diff = GetDiff(oldCommit, newCommit, filePath);
    if (diff.empty() && !m_lastError.empty()) return false;
    
    if (!m_hDiffViewer || !IsWindow(m_hDiffViewer)) {
        RECT rc = {0, 0, 800, 600};
        m_hDiffViewer = CreateDiffViewer(m_hParent, rc);
    }
    
    UpdateDiffViewer(m_hDiffViewer, diff);
    ShowWindow(m_hDiffViewer, SW_SHOW);
    return true;
}

bool GitUI::ShowStagedDiff(const std::string& filePath) {
    auto diff = GetDiff("--cached", "", filePath);
    if (diff.empty() && !m_lastError.empty()) return false;
    
    if (!m_hDiffViewer || !IsWindow(m_hDiffViewer)) {
        RECT rc = {0, 0, 800, 600};
        m_hDiffViewer = CreateDiffViewer(m_hParent, rc);
    }
    
    UpdateDiffViewer(m_hDiffViewer, diff);
    ShowWindow(m_hDiffViewer, SW_SHOW);
    return true;
}

std::vector<DiffLine> GitUI::GetDiff(const std::string& oldCommit, 
                                      const std::string& newCommit,
                                      const std::string& filePath) {
    std::string cmd = "diff --unified=3 ";
    
    if (m_config.ignoreWhitespace) {
        cmd += "-w ";
    }
    
    if (!oldCommit.empty()) {
        cmd += oldCommit;
        if (!newCommit.empty()) {
            cmd += " " + newCommit;
        }
    } else if (!newCommit.empty()) {
        cmd += newCommit;
    }
    
    if (!filePath.empty()) {
        cmd += " -- " + EscapeShellArg(filePath);
    }
    
    int exitCode = 0;
    std::string output = ExecuteGitCommand(cmd, &exitCode);
    
    if (exitCode != 0 && exitCode != 1) { // 1 means differences found
        return {};
    }
    
    return ParseDiffOutput(output);
}

DiffStats GitUI::GetDiffStats(const std::vector<DiffLine>& diff) {
    DiffStats stats;
    for (const auto& line : diff) {
        switch (line.type) {
            case DiffLine::Type::Added: stats.insertions++; break;
            case DiffLine::Type::Removed: stats.deletions++; break;
            case DiffLine::Type::Hunk: stats.hunks++; break;
            default: break;
        }
    }
    return stats;
}

// ============================================================================
// Blame Operations
// ============================================================================
bool GitUI::ShowBlame(const std::string& filePath, int startLine, int endLine) {
    auto blame = GetBlame(filePath, startLine, endLine);
    if (blame.empty() && !m_lastError.empty()) return false;
    
    if (!m_hBlameViewer || !IsWindow(m_hBlameViewer)) {
        RECT rc = {0, 0, 900, 600};
        m_hBlameViewer = CreateBlameViewer(m_hParent, rc);
    }
    
    UpdateBlameViewer(m_hBlameViewer, blame);
    ShowWindow(m_hBlameViewer, SW_SHOW);
    return true;
}

std::vector<BlameLine> GitUI::GetBlame(const std::string& filePath, 
                                        int startLine, int endLine) {
    // Check cache
    std::string cacheKey = filePath + ":" + std::to_string(startLine) + "-" + std::to_string(endLine);
    auto it = m_blameCache.find(cacheKey);
    if (it != m_blameCache.end()) {
        return it->second;
    }
    
    std::string cmd = "blame --porcelain ";
    
    if (startLine > 0) {
        cmd += "-L " + std::to_string(startLine) + ",";
        if (endLine > 0) {
            cmd += std::to_string(endLine) + " ";
        } else {
            cmd += "+100 ";
        }
    }
    
    cmd += "-- " + EscapeShellArg(filePath);
    
    int exitCode = 0;
    std::string output = ExecuteGitCommand(cmd, &exitCode);
    
    if (exitCode != 0) {
        return {};
    }
    
    auto blame = ParseBlameOutput(output);
    m_blameCache[cacheKey] = blame;
    return blame;
}

CommitInfo GitUI::GetCommitForLine(const std::string& filePath, int lineNum) {
    auto blame = GetBlame(filePath, lineNum, lineNum);
    if (blame.empty()) return {};
    
    return GetCommitInfo(blame[0].commitHash);
}

// ============================================================================
// Log Operations
// ============================================================================
bool GitUI::ShowLog(const std::string& filePath, int maxCount) {
    auto log = GetLog(filePath, maxCount);
    if (log.empty() && !m_lastError.empty()) return false;
    
    if (!m_hLogViewer || !IsWindow(m_hLogViewer)) {
        RECT rc = {0, 0, 800, 600};
        m_hLogViewer = CreateLogViewer(m_hParent, rc);
    }
    
    UpdateLogViewer(m_hLogViewer, log);
    ShowWindow(m_hLogViewer, SW_SHOW);
    return true;
}

std::vector<CommitInfo> GitUI::GetLog(const std::string& filePath, 
                                       int maxCount,
                                       const std::string& since,
                                       const std::string& until) {
    std::string cmd = "log --format=format:%H%x00%an%x00%ae%x00%at%x00%s%x00%P%x00 --max-count=" + 
                      std::to_string(maxCount) + " ";
    
    if (!since.empty()) {
        cmd += "--since=" + EscapeShellArg(since) + " ";
    }
    if (!until.empty()) {
        cmd += "--until=" + EscapeShellArg(until) + " ";
    }
    
    if (!filePath.empty()) {
        cmd += "--follow " + std::string(m_config.followRenames ? "" : "--no-renames") + " ";
        cmd += "-- " + EscapeShellArg(filePath);
    }
    
    int exitCode = 0;
    std::string output = ExecuteGitCommand(cmd, &exitCode);
    
    if (exitCode != 0) {
        return {};
    }
    
    return ParseLogOutput(output);
}

CommitInfo GitUI::GetCommitInfo(const std::string& commitHash) {
    // Check cache
    auto it = m_commitCache.find(commitHash);
    if (it != m_commitCache.end()) {
        return it->second;
    }
    
    std::string cmd = "show --format=format:%H%x00%an%x00%ae%x00%at%x00%cn%x00%ce%x00%ct%x00%s%x00%b%x00 --no-patch ";
    cmd += commitHash;
    
    int exitCode = 0;
    std::string output = ExecuteGitCommand(cmd, &exitCode);
    
    if (exitCode != 0) {
        return {};
    }
    
    CommitInfo info = ParseCommitOutput(output);
    m_commitCache[commitHash] = info;
    return info;
}

// ============================================================================
// Status Operations
// ============================================================================
std::vector<FileStatus> GitUI::GetStatus() {
    std::string cmd = "status --porcelain -u";
    
    int exitCode = 0;
    std::string output = ExecuteGitCommand(cmd, &exitCode);
    
    if (exitCode != 0) {
        return {};
    }
    
    return ParseStatusOutput(output);
}

bool GitUI::IsTracked(const std::string& filePath) {
    std::string cmd = "ls-files --error-unmatch " + EscapeShellArg(filePath);
    int exitCode = 0;
    ExecuteGitCommand(cmd, &exitCode);
    return exitCode == 0;
}

bool GitUI::IsRepository() {
    std::string cmd = "rev-parse --git-dir";
    int exitCode = 0;
    ExecuteGitCommand(cmd, &exitCode);
    return exitCode == 0;
}

std::string GitUI::GetRepositoryRoot() {
    std::string cmd = "rev-parse --show-toplevel";
    int exitCode = 0;
    std::string output = ExecuteGitCommand(cmd, &exitCode);
    
    if (exitCode == 0 && !output.empty()) {
        // Trim trailing newline
        while (!output.empty() && (output.back() == '\n' || output.back() == '\r')) {
            output.pop_back();
        }
        return output;
    }
    return "";
}

// ============================================================================
// UI Windows
// ============================================================================
HWND GitUI::CreateDiffViewer(HWND hParent, const RECT& rect) {
    WNDCLASSEX wc = {0};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = DiffViewerProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = L"RawrXD_GitDiffViewer";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    RegisterClassEx(&wc);
    
    HWND hwnd = CreateWindowEx(
        WS_EX_CLIENTEDGE,
        L"RawrXD_GitDiffViewer",
        L"Diff Viewer",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL,
        rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top,
        hParent, nullptr, GetModuleHandle(nullptr), this
    );
    
    return hwnd;
}

HWND GitUI::CreateBlameViewer(HWND hParent, const RECT& rect) {
    WNDCLASSEX wc = {0};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = BlameViewerProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = L"RawrXD_GitBlameViewer";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    RegisterClassEx(&wc);
    
    HWND hwnd = CreateWindowEx(
        WS_EX_CLIENTEDGE,
        L"RawrXD_GitBlameViewer",
        L"Blame Viewer",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL,
        rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top,
        hParent, nullptr, GetModuleHandle(nullptr), this
    );
    
    return hwnd;
}

HWND GitUI::CreateLogViewer(HWND hParent, const RECT& rect) {
    WNDCLASSEX wc = {0};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = LogViewerProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = L"RawrXD_GitLogViewer";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    RegisterClassEx(&wc);
    
    HWND hwnd = CreateWindowEx(
        WS_EX_CLIENTEDGE,
        L"RawrXD_GitLogViewer",
        L"Log Viewer",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL,
        rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top,
        hParent, nullptr, GetModuleHandle(nullptr), this
    );
    
    return hwnd;
}

void GitUI::UpdateDiffViewer(HWND hViewer, const std::vector<DiffLine>& diff) {
    if (!hViewer) return;
    
    // Store diff data in window
    SetWindowLongPtr(hViewer, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(&diff));
    InvalidateRect(hViewer, nullptr, TRUE);
}

void GitUI::UpdateBlameViewer(HWND hViewer, const std::vector<BlameLine>& blame) {
    if (!hViewer) return;
    
    SetWindowLongPtr(hViewer, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(&blame));
    InvalidateRect(hViewer, nullptr, TRUE);
}

void GitUI::UpdateLogViewer(HWND hViewer, const std::vector<CommitInfo>& log) {
    if (!hViewer) return;
    
    SetWindowLongPtr(hViewer, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(&log));
    InvalidateRect(hViewer, nullptr, TRUE);
}

// ============================================================================
// Actions
// ============================================================================
bool GitUI::StageFile(const std::string& filePath) {
    std::string cmd = "add " + EscapeShellArg(filePath);
    int exitCode = 0;
    ExecuteGitCommand(cmd, &exitCode);
    return exitCode == 0;
}

bool GitUI::UnstageFile(const std::string& filePath) {
    std::string cmd = "reset HEAD " + EscapeShellArg(filePath);
    int exitCode = 0;
    ExecuteGitCommand(cmd, &exitCode);
    return exitCode == 0;
}

bool GitUI::DiscardChanges(const std::string& filePath) {
    std::string cmd = "checkout -- " + EscapeShellArg(filePath);
    int exitCode = 0;
    ExecuteGitCommand(cmd, &exitCode);
    return exitCode == 0;
}

bool GitUI::OpenExternalDiff(const std::string& filePath) {
    std::string cmd = "difftool --no-prompt " + EscapeShellArg(filePath);
    int exitCode = 0;
    ExecuteGitCommand(cmd, &exitCode);
    return exitCode == 0;
}

// ============================================================================
// Git Command Execution
// ============================================================================
std::string GitUI::ExecuteGitCommand(const std::string& args, int* exitCode) {
    std::string fullCmd = m_config.gitExecutable + " " + args;
    
    SECURITY_ATTRIBUTES sa = {0};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    
    HANDLE hRead = nullptr, hWrite = nullptr;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
        m_lastError = "Failed to create pipe";
        if (exitCode) *exitCode = -1;
        return "";
    }
    
    STARTUPINFO si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    si.wShowWindow = SW_HIDE;
    
    PROCESS_INFORMATION pi = {0};
    
    std::wstring wideCmd = Utf8ToWide(fullCmd);
    
    BOOL success = CreateProcess(
        nullptr, const_cast<LPWSTR>(wideCmd.c_str()),
        nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
        nullptr, 
        m_config.workingDirectory.empty() ? nullptr : Utf8ToWide(m_config.workingDirectory).c_str(),
        &si, &pi
    );
    
    if (!success) {
        CloseHandle(hRead);
        CloseHandle(hWrite);
        m_lastError = "Failed to start git process";
        if (exitCode) *exitCode = -1;
        return "";
    }
    
    CloseHandle(hWrite);
    
    // Read output
    std::string output;
    char buffer[4096];
    DWORD bytesRead;
    while (ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytesRead, nullptr) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        output += buffer;
    }
    
    CloseHandle(hRead);
    
    // Wait for process
    DWORD waitResult = WaitForSingleObject(pi.hProcess, m_config.timeoutMs);
    if (waitResult == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
        m_lastError = "Git command timed out";
        if (exitCode) *exitCode = -1;
    } else {
        DWORD exitCodeDw = 0;
        GetExitCodeProcess(pi.hProcess, &exitCodeDw);
        if (exitCode) *exitCode = static_cast<int>(exitCodeDw);
    }
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return output;
}

// ============================================================================
// Parsing
// ============================================================================
std::vector<DiffLine> GitUI::ParseDiffOutput(const std::string& output) {
    std::vector<DiffLine> lines;
    std::istringstream stream(output);
    std::string line;
    
    while (std::getline(stream, line)) {
        DiffLine dl;
        dl.rawLine = line;
        
        if (line.empty()) {
            dl.type = DiffLine::Type::Empty;
        } else if (line.substr(0, 4) == "diff") {
            dl.type = DiffLine::Type::Header;
        } else if (line.substr(0, 3) == "---" || line.substr(0, 3) == "+++") {
            dl.type = DiffLine::Type::Header;
        } else if (line.substr(0, 2) == "@@") {
            dl.type = DiffLine::Type::Hunk;
            // Parse hunk header
            std::regex hunkRe("@@ -(\\d+)(?:,(\\d+))? \\u002b(\\d+)(?:,(\\d+))? @@");
            std::smatch match;
            if (std::regex_search(line, match, hunkRe)) {
                dl.hunkStartOld = std::stoi(match[1]);
                dl.hunkCountOld = match[2].matched ? std::stoi(match[2]) : 1;
                dl.hunkStartNew = std::stoi(match[3]);
                dl.hunkCountNew = match[4].matched ? std::stoi(match[4]) : 1;
            }
        } else if (line[0] == '+') {
            dl.type = DiffLine::Type::Added;
            dl.content = line.substr(1);
        } else if (line[0] == '-') {
            dl.type = DiffLine::Type::Removed;
            dl.content = line.substr(1);
        } else if (line[0] == ' ') {
            dl.type = DiffLine::Type::Context;
            dl.content = line.substr(1);
        } else if (line.find("Binary") != std::string::npos) {
            dl.type = DiffLine::Type::Binary;
        } else {
            dl.type = DiffLine::Type::Header;
        }
        
        lines.push_back(dl);
    }
    
    return lines;
}

std::vector<BlameLine> GitUI::ParseBlameOutput(const std::string& output) {
    std::vector<BlameLine> lines;
    std::istringstream stream(output);
    std::string line;
    
    std::string currentHash;
    std::map<std::string, std::string> commitData;
    
    while (std::getline(stream, line)) {
        if (line.empty()) continue;
        
        // Check if this is a porcelain line
        if (line[0] == '\t') {
            // Content line
            BlameLine bl;
            bl.commitHash = currentHash;
            bl.shortHash = ShortenHash(currentHash);
            bl.content = line.substr(1);
            
            // Fill from commit data
            auto it = commitData.find(currentHash);
            if (it != commitData.end()) {
                // Parse stored data
                // Simplified - in real impl, store structured data
            }
            
            lines.push_back(bl);
        } else {
            // Header line
            std::istringstream lineStream(line);
            std::string hash;
            lineStream >> hash;
            
            if (hash != currentHash) {
                currentHash = hash;
            }
            
            // Parse additional fields
            std::string key, value;
            if (std::getline(lineStream, key, ' ')) {
                std::getline(lineStream, value);
                commitData[currentHash + ":" + key] = value;
            }
        }
    }
    
    return lines;
}

std::vector<CommitInfo> GitUI::ParseLogOutput(const std::string& output) {
    std::vector<CommitInfo> commits;
    std::istringstream stream(output);
    std::string line;
    
    while (std::getline(stream, line)) {
        if (line.empty()) continue;
        
        std::vector<std::string> parts;
        std::istringstream partStream(line);
        std::string part;
        while (std::getline(partStream, part, '\0')) {
            parts.push_back(part);
        }
        
        if (parts.size() >= 6) {
            CommitInfo ci;
            ci.hash = parts[0];
            ci.shortHash = ShortenHash(parts[0]);
            ci.authorName = parts[1];
            ci.authorEmail = parts[2];
            ci.authorTime = std::chrono::system_clock::from_time_t(std::stoll(parts[3]));
            ci.authorTimeStr = FormatTime(ci.authorTime);
            ci.summary = parts[4];
            
            // Parse parents
            std::istringstream parentStream(parts[5]);
            std::string parent;
            while (parentStream >> parent) {
                ci.parentHashes.push_back(parent);
            }
            
            commits.push_back(ci);
        }
    }
    
    return commits;
}

std::vector<FileStatus> GitUI::ParseStatusOutput(const std::string& output) {
    std::vector<FileStatus> statuses;
    std::istringstream stream(output);
    std::string line;
    
    while (std::getline(stream, line)) {
        if (line.length() < 3) continue;
        
        FileStatus fs;
        fs.stagedStatus = line[0];
        fs.unstagedStatus = line[1];
        fs.path = line.substr(3);
        
        // Determine state
        if (fs.stagedStatus == 'A') fs.state = FileStatus::State::Staged;
        else if (fs.stagedStatus == 'M') fs.state = FileStatus::State::Staged;
        else if (fs.stagedStatus == 'D') fs.state = FileStatus::State::Staged;
        else if (fs.unstagedStatus == 'M') fs.state = FileStatus::State::Modified;
        else if (fs.unstagedStatus == 'D') fs.state = FileStatus::State::Deleted;
        else if (fs.unstagedStatus == '?') fs.state = FileStatus::State::Untracked;
        else if (line.find("U") != std::string::npos) fs.state = FileStatus::State::Conflict;
        
        statuses.push_back(fs);
    }
    
    return statuses;
}

CommitInfo GitUI::ParseCommitOutput(const std::string& output) {
    CommitInfo ci;
    std::istringstream stream(output);
    std::string line;
    std::getline(stream, line);
    
    std::vector<std::string> parts;
    std::istringstream partStream(line);
    std::string part;
    while (std::getline(partStream, part, '\0')) {
        parts.push_back(part);
    }
    
    if (parts.size() >= 9) {
        ci.hash = parts[0];
        ci.shortHash = ShortenHash(parts[0]);
        ci.authorName = parts[1];
        ci.authorEmail = parts[2];
        ci.authorTime = std::chrono::system_clock::from_time_t(std::stoll(parts[3]));
        ci.authorTimeStr = FormatTime(ci.authorTime);
        ci.committerName = parts[4];
        ci.committerEmail = parts[5];
        ci.commitTime = std::chrono::system_clock::from_time_t(std::stoll(parts[6]));
        ci.commitTimeStr = FormatTime(ci.commitTime);
        ci.summary = parts[7];
        ci.body = parts[8];
    }
    
    return ci;
}

// ============================================================================
// Window Procedures
// ============================================================================
LRESULT CALLBACK GitUI::DiffViewerProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            
            // Get diff data
            auto* diff = reinterpret_cast<std::vector<DiffLine>*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
            if (diff) {
                int y = 0;
                int lineHeight = 16;
                
                for (const auto& line : *diff) {
                    COLORREF bg = RGB(255, 255, 255);
                    COLORREF fg = RGB(0, 0, 0);
                    
                    switch (line.type) {
                        case DiffLine::Type::Added:
                            bg = DIFF_ADDED_BG;
                            fg = DIFF_ADDED_FG;
                            break;
                        case DiffLine::Type::Removed:
                            bg = DIFF_REMOVED_BG;
                            fg = DIFF_REMOVED_FG;
                            break;
                        case DiffLine::Type::Header:
                            bg = DIFF_HEADER_BG;
                            fg = DIFF_HEADER_FG;
                            break;
                        case DiffLine::Type::Hunk:
                            bg = DIFF_HUNK_BG;
                            fg = DIFF_HUNK_FG;
                            break;
                        default:
                            break;
                    }
                    
                    RECT rc = {0, y, ps.rcPaint.right, y + lineHeight};
                    SetBkColor(hdc, bg);
                    SetTextColor(hdc, fg);
                    FillRect(hdc, &rc, CreateSolidBrush(bg));
                    
                    std::string displayText = line.content.empty() ? line.rawLine : line.content;
                    std::wstring wideText = Utf8ToWide(displayText);
                    TextOut(hdc, 5, y, wideText.c_str(), static_cast<int>(wideText.length()));
                    
                    y += lineHeight;
                }
            }
            
            EndPaint(hwnd, &ps);
            return 0;
        }
        
        case WM_SIZE:
            InvalidateRect(hwnd, nullptr, TRUE);
            return 0;
            
        case WM_DESTROY:
            return 0;
    }
    
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK GitUI::BlameViewerProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            
            auto* blame = reinterpret_cast<std::vector<BlameLine>*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
            if (blame) {
                int y = 0;
                int lineHeight = 16;
                
                for (const auto& line : *blame) {
                    COLORREF bg = line.isBoundary ? BLAME_BOUNDARY_BG : BLAME_NORMAL_BG;
                    
                    RECT rc = {0, y, ps.rcPaint.right, y + lineHeight};
                    SetBkColor(hdc, bg);
                    FillRect(hdc, &rc, CreateSolidBrush(bg));
                    
                    // Draw hash
                    SetTextColor(hdc, BLAME_HASH_FG);
                    std::wstring hash = Utf8ToWide(line.shortHash);
                    TextOut(hdc, 5, y, hash.c_str(), static_cast<int>(hash.length()));
                    
                    // Draw author
                    SetTextColor(hdc, BLAME_AUTHOR_FG);
                    std::wstring author = Utf8ToWide(line.authorName);
                    TextOut(hdc, 80, y, author.c_str(), static_cast<int>(author.length()));
                    
                    // Draw time
                    SetTextColor(hdc, BLAME_TIME_FG);
                    std::wstring time = Utf8ToWide(line.authorTimeStr);
                    TextOut(hdc, 200, y, time.c_str(), static_cast<int>(time.length()));
                    
                    // Draw content
                    SetTextColor(hdc, RGB(0, 0, 0));
                    std::wstring content = Utf8ToWide(line.content);
                    TextOut(hdc, 300, y, content.c_str(), static_cast<int>(content.length()));
                    
                    y += lineHeight;
                }
            }
            
            EndPaint(hwnd, &ps);
            return 0;
        }
        
        case WM_SIZE:
            InvalidateRect(hwnd, nullptr, TRUE);
            return 0;
            
        case WM_DESTROY:
            return 0;
    }
    
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK GitUI::LogViewerProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            
            auto* log = reinterpret_cast<std::vector<CommitInfo>*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
            if (log) {
                int y = 0;
                int itemHeight = 40;
                
                for (const auto& commit : *log) {
                    RECT rc = {0, y, ps.rcPaint.right, y + itemHeight};
                    SetBkColor(hdc, RGB(255, 255, 255));
                    FillRect(hdc, &rc, (HBRUSH)GetStockObject(WHITE_BRUSH));
                    
                    // Draw hash
                    SetTextColor(hdc, RGB(0, 122, 204));
                    std::wstring hash = Utf8ToWide(commit.shortHash);
                    TextOut(hdc, 5, y + 2, hash.c_str(), static_cast<int>(hash.length()));
                    
                    // Draw summary
                    SetTextColor(hdc, RGB(0, 0, 0));
                    std::wstring summary = Utf8ToWide(commit.summary);
                    TextOut(hdc, 80, y + 2, summary.c_str(), static_cast<int>(summary.length()));
                    
                    // Draw author and time
                    SetTextColor(hdc, RGB(128, 128, 128));
                    std::wstring meta = Utf8ToWide(commit.authorName + " - " + commit.authorTimeStr);
                    TextOut(hdc, 80, y + 20, meta.c_str(), static_cast<int>(meta.length()));
                    
                    y += itemHeight;
                }
            }
            
            EndPaint(hwnd, &ps);
            return 0;
        }
        
        case WM_SIZE:
            InvalidateRect(hwnd, nullptr, TRUE);
            return 0;
            
        case WM_DESTROY:
            return 0;
    }
    
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

// ============================================================================
// Utility
// ============================================================================
std::wstring GitUI::Utf8ToWide(const std::string& utf8) {
    if (utf8.empty()) return L"";
    int size = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
    std::wstring result(size - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, &result[0], size);
    return result;
}

std::string GitUI::WideToUtf8(const std::wstring& wide) {
    if (wide.empty()) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string result(size - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, &result[0], size, nullptr, nullptr);
    return result;
}

std::string GitUI::EscapeShellArg(const std::string& arg) {
    // Simple escaping for Windows
    if (arg.find(' ') != std::string::npos || 
        arg.find('"') != std::string::npos ||
        arg.find('\'') != std::string::npos) {
        return "\"" + arg + "\"";
    }
    return arg;
}

// ============================================================================
// Static Helpers
// ============================================================================
std::string GitUI::FormatTime(const std::chrono::system_clock::time_point& time) {
    auto timeT = std::chrono::system_clock::to_time_t(time);
    std::tm tm;
    localtime_s(&tm, &timeT);
    
    char buffer[64];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M", &tm);
    return buffer;
}

std::string GitUI::ShortenHash(const std::string& hash, int len) {
    if (hash.length() <= static_cast<size_t>(len)) return hash;
    return hash.substr(0, len);
}

std::string GitUI::GetStateString(FileStatus::State state) {
    switch (state) {
        case FileStatus::State::Untracked: return "Untracked";
        case FileStatus::State::Modified: return "Modified";
        case FileStatus::State::Added: return "Added";
        case FileStatus::State::Deleted: return "Deleted";
        case FileStatus::State::Renamed: return "Renamed";
        case FileStatus::State::Copied: return "Copied";
        case FileStatus::State::Unmerged: return "Unmerged";
        case FileStatus::State::Ignored: return "Ignored";
        case FileStatus::State::Staged: return "Staged";
        case FileStatus::State::Conflict: return "Conflict";
        default: return "Unknown";
    }
}

COLORREF GitUI::GetStateColor(FileStatus::State state) {
    switch (state) {
        case FileStatus::State::Untracked: return RGB(158, 158, 158);
        case FileStatus::State::Modified: return RGB(255, 193, 7);
        case FileStatus::State::Added: return RGB(76, 175, 80);
        case FileStatus::State::Deleted: return RGB(244, 67, 54);
        case FileStatus::State::Renamed: return RGB(156, 39, 176);
        case FileStatus::State::Copied: return RGB(0, 150, 136);
        case FileStatus::State::Unmerged: return RGB(255, 87, 34);
        case FileStatus::State::Ignored: return RGB(158, 158, 158);
        case FileStatus::State::Staged: return RGB(33, 150, 243);
        case FileStatus::State::Conflict: return RGB(244, 67, 54);
        default: return RGB(0, 0, 0);
    }
}

// ============================================================================
// GitUIDialog
// ============================================================================
bool GitUIDialog::ShowDiffDialog(HWND hParent, const std::string& filePath,
                                  const std::string& oldCommit, const std::string& newCommit) {
    GitUI ui;
    GitConfig config;
    config.workingDirectory = "."; // Current directory
    
    if (!ui.Initialize(config)) {
        MessageBoxA(hParent, ui.GetLastError().c_str(), "Git Error", MB_OK | MB_ICONERROR);
        return false;
    }
    
    if (!oldCommit.empty() && !newCommit.empty()) {
        return ui.ShowDiffRange(oldCommit, newCommit, filePath);
    } else if (!oldCommit.empty()) {
        return ui.ShowCommitDiff(oldCommit, filePath);
    } else {
        return ui.ShowWorkingDirectoryDiff(filePath);
    }
}

bool GitUIDialog::ShowBlameDialog(HWND hParent, const std::string& filePath, int lineNum) {
    GitUI ui;
    GitConfig config;
    config.workingDirectory = ".";
    
    if (!ui.Initialize(config)) {
        MessageBoxA(hParent, ui.GetLastError().c_str(), "Git Error", MB_OK | MB_ICONERROR);
        return false;
    }
    
    return ui.ShowBlame(filePath, lineNum > 0 ? lineNum : 0);
}

bool GitUIDialog::ShowLogDialog(HWND hParent, const std::string& filePath) {
    GitUI ui;
    GitConfig config;
    config.workingDirectory = ".";
    
    if (!ui.Initialize(config)) {
        MessageBoxA(hParent, ui.GetLastError().c_str(), "Git Error", MB_OK | MB_ICONERROR);
        return false;
    }
    
    return ui.ShowLog(filePath, 100);
}

bool GitUIDialog::ShowStatusDialog(HWND hParent) {
    GitUI ui;
    GitConfig config;
    config.workingDirectory = ".";
    
    if (!ui.Initialize(config)) {
        MessageBoxA(hParent, ui.GetLastError().c_str(), "Git Error", MB_OK | MB_ICONERROR);
        return false;
    }
    
    auto status = ui.GetStatus();
    
    // Build status message
    std::string msg = "Repository Status:\n\n";
    for (const auto& s : status) {
        msg += GitUI::GetStateString(s.state) + ": " + s.path + "\n";
    }
    
    MessageBoxA(hParent, msg.c_str(), "Git Status", MB_OK | MB_ICONINFORMATION);
    return true;
}

bool GitUIDialog::QuickCommit(HWND hParent, const std::string& message) {
    if (message.empty()) {
        MessageBoxA(hParent, "Commit message cannot be empty", "Git Commit", MB_OK | MB_ICONWARNING);
        return false;
    }
    
    GitUI ui;
    GitConfig config;
    config.workingDirectory = ".";
    
    if (!ui.Initialize(config)) {
        MessageBoxA(hParent, ui.GetLastError().c_str(), "Git Error", MB_OK | MB_ICONERROR);
        return false;
    }
    
    std::string cmd = "commit -m \"" + message + "\"";
    int exitCode = 0;
    ui.ExecuteGitCommand(cmd, &exitCode);
    
    if (exitCode != 0) {
        MessageBoxA(hParent, "Failed to commit", "Git Commit", MB_OK | MB_ICONERROR);
        return false;
    }
    
    MessageBoxA(hParent, "Commit successful", "Git Commit", MB_OK | MB_ICONINFORMATION);
    return true;
}

bool GitUIDialog::QuickStage(HWND hParent, const std::vector<std::string>& files) {
    GitUI ui;
    GitConfig config;
    config.workingDirectory = ".";
    
    if (!ui.Initialize(config)) {
        MessageBoxA(hParent, ui.GetLastError().c_str(), "Git Error", MB_OK | MB_ICONERROR);
        return false;
    }
    
    for (const auto& file : files) {
        if (!ui.StageFile(file)) {
            MessageBoxA(hParent, ("Failed to stage: " + file).c_str(), "Git Stage", MB_OK | MB_ICONERROR);
            return false;
        }
    }
    
    MessageBoxA(hParent, "Files staged successfully", "Git Stage", MB_OK | MB_ICONINFORMATION);
    return true;
}

bool GitUIDialog::QuickCheckout(HWND hParent, const std::string& filePath) {
    GitUI ui;
    GitConfig config;
    config.workingDirectory = ".";
    
    if (!ui.Initialize(config)) {
        MessageBoxA(hParent, ui.GetLastError().c_str(), "Git Error", MB_OK | MB_ICONERROR);
        return false;
    }
    
    if (!ui.DiscardChanges(filePath)) {
        MessageBoxA(hParent, "Failed to discard changes", "Git Checkout", MB_OK | MB_ICONERROR);
        return false;
    }
    
    MessageBoxA(hParent, "Changes discarded", "Git Checkout", MB_OK | MB_ICONINFORMATION);
    return true;
}

} // namespace rawrxd::scm
