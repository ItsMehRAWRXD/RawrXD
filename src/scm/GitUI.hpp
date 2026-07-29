// ============================================================================
// GitUI.hpp - Production Git Diff/Blame UI for RawrXD
// ============================================================================
// Provides diff viewing, blame annotations, and commit history in a
// professional IDE-style interface. Fully production-ready.
// ============================================================================

#pragma once
#include <Windows.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <map>
#include <chrono>

namespace rawrxd::scm {

// ============================================================================
// DiffLine - Single line in a diff
// ============================================================================
struct DiffLine {
    enum class Type { Context, Added, Removed, Header, Hunk, Binary, Empty };
    Type type = Type::Context;
    int oldLineNum = -1;      // Line number in old file (-1 for added)
    int newLineNum = -1;      // Line number in new file (-1 for removed)
    std::string content;      // Line content (without prefix)
    std::string rawLine;      // Original line with prefix
    
    // For unified diff parsing
    int hunkStartOld = -1;
    int hunkStartNew = -1;
    int hunkCountOld = 0;
    int hunkCountNew = 0;
};

// ============================================================================
// BlameLine - Single line of blame annotation
// ============================================================================
struct BlameLine {
    std::string commitHash;           // Full commit hash
    std::string shortHash;            // Short (8-char) hash
    std::string authorName;
    std::string authorEmail;
    std::chrono::system_clock::time_point authorTime;
    std::string authorTimeStr;        // Formatted time string
    std::string summary;              // Commit summary
    int lineNum = 0;                  // Line number in file
    std::string content;              // Line content
    bool isBoundary = false;          // Is this a boundary commit?
    
    // For grouping consecutive same-commit lines
    bool showAnnotation = true;       // Show annotation for this line?
};

// ============================================================================
// CommitInfo - Commit metadata
// ============================================================================
struct CommitInfo {
    std::string hash;
    std::string shortHash;
    std::string authorName;
    std::string authorEmail;
    std::chrono::system_clock::time_point authorTime;
    std::string authorTimeStr;
    std::string committerName;
    std::string committerEmail;
    std::chrono::system_clock::time_point commitTime;
    std::string commitTimeStr;
    std::string summary;
    std::string body;
    std::vector<std::string> parentHashes;
    int insertions = 0;
    int deletions = 0;
    int filesChanged = 0;
};

// ============================================================================
// FileStatus - Git file status
// ============================================================================
struct FileStatus {
    enum class State { Untracked, Modified, Added, Deleted, Renamed, Copied, 
                       Unmerged, Ignored, Staged, Conflict };
    State state = State::Untracked;
    std::string path;
    std::string originalPath;  // For renames
    int stagedStatus = 0;      // X in XY
    int unstagedStatus = 0;    // Y in XY
};

// ============================================================================
// DiffStats - Statistics for a diff
// ============================================================================
struct DiffStats {
    int filesChanged = 0;
    int insertions = 0;
    int deletions = 0;
    int hunks = 0;
    std::string oldPath;
    std::string newPath;
    bool isBinary = false;
    bool isNewFile = false;
    bool isDeleted = false;
    bool isRename = false;
    float similarity = 0.0f;  // For renames
};

// ============================================================================
// GitConfig - Configuration for Git operations
// ============================================================================
struct GitConfig {
    std::string gitExecutable = "git";
    std::string workingDirectory;
    int timeoutMs = 30000;           // Command timeout
    int maxDiffLines = 10000;        // Max lines to load
    int maxLogEntries = 1000;        // Max log entries
    bool followRenames = true;
    bool detectCopies = false;
    bool ignoreWhitespace = false;
};

// ============================================================================
// GitUI - Production Git UI component
// ============================================================================
class GitUI {
public:
    GitUI();
    ~GitUI();

    // Disable copy, enable move
    GitUI(const GitUI&) = delete;
    GitUI& operator=(const GitUI&) = delete;
    GitUI(GitUI&&) noexcept;
    GitUI& operator=(GitUI&&) noexcept;

    // ── Initialization ──
    bool Initialize(const GitConfig& config);
    void Shutdown();
    bool IsInitialized() const { return m_initialized; }
    
    // Set parent window for dialogs
    void SetParentWindow(HWND hParent) { m_hParent = hParent; }
    HWND GetParentWindow() const { return m_hParent; }

    // ── Diff Operations ──
    // Show diff for working directory changes
    bool ShowWorkingDirectoryDiff(const std::string& filePath);
    
    // Show diff between commits
    bool ShowCommitDiff(const std::string& commitHash, const std::string& filePath = "");
    
    // Show diff between two commits
    bool ShowDiffRange(const std::string& oldCommit, const std::string& newCommit, 
                       const std::string& filePath = "");
    
    // Show staged diff
    bool ShowStagedDiff(const std::string& filePath = "");
    
    // Get diff data (for custom rendering)
    std::vector<DiffLine> GetDiff(const std::string& oldCommit, 
                                     const std::string& newCommit,
                                     const std::string& filePath = "");
    DiffStats GetDiffStats(const std::vector<DiffLine>& diff);

    // ── Blame Operations ──
    // Show blame for file
    bool ShowBlame(const std::string& filePath, int startLine = 0, int endLine = -1);
    
    // Get blame data
    std::vector<BlameLine> GetBlame(const std::string& filePath, 
                                      int startLine = 0, int endLine = -1);
    
    // Get commit for line
    CommitInfo GetCommitForLine(const std::string& filePath, int lineNum);

    // ── Log Operations ──
    // Show commit log
    bool ShowLog(const std::string& filePath = "", int maxCount = 100);
    
    // Get commit log
    std::vector<CommitInfo> GetLog(const std::string& filePath = "", 
                                     int maxCount = 100,
                                     const std::string& since = "",
                                     const std::string& until = "");
    
    // Get single commit info
    CommitInfo GetCommitInfo(const std::string& commitHash);

    // ── Status Operations ──
    // Get repository status
    std::vector<FileStatus> GetStatus();
    
    // Check if file is tracked
    bool IsTracked(const std::string& filePath);
    
    // Check if repository
    bool IsRepository();
    
    // Get repository root
    std::string GetRepositoryRoot();

    // ── UI Windows ──
    // Create diff viewer window
    HWND CreateDiffViewer(HWND hParent, const RECT& rect);
    
    // Create blame viewer window
    HWND CreateBlameViewer(HWND hParent, const RECT& rect);
    
    // Create log viewer window
    HWND CreateLogViewer(HWND hParent, const RECT& rect);
    
    // Update viewer content
    void UpdateDiffViewer(HWND hViewer, const std::vector<DiffLine>& diff);
    void UpdateBlameViewer(HWND hViewer, const std::vector<BlameLine>& blame);
    void UpdateLogViewer(HWND hViewer, const std::vector<CommitInfo>& log);

    // ── Actions ──
    // Stage file
    bool StageFile(const std::string& filePath);
    
    // Unstage file
    bool UnstageFile(const std::string& filePath);
    
    // Discard changes
    bool DiscardChanges(const std::string& filePath);
    
    // Open external diff tool
    bool OpenExternalDiff(const std::string& filePath);

    // ── Callbacks ──
    using CommitSelectedCallback = std::function<void(const std::string& hash)>;
    using LineSelectedCallback = std::function<void(int lineNum)>;
    using DiffActionCallback = std::function<void(const std::string& action, const std::string& file)>;
    
    void SetCommitSelectedCallback(CommitSelectedCallback cb) { m_commitSelectedCallback = std::move(cb); }
    void SetLineSelectedCallback(LineSelectedCallback cb) { m_lineSelectedCallback = std::move(cb); }
    void SetDiffActionCallback(DiffActionCallback cb) { m_diffActionCallback = std::move(cb); }

    // ── Configuration ──
    void SetConfig(const GitConfig& config) { m_config = config; }
    const GitConfig& GetConfig() const { return m_config; }

    // ── Error Handling ──
    std::string GetLastError() const { return m_lastError; }
    void ClearError() { m_lastError.clear(); }

    // ── Static Helpers ──
    static std::string FormatTime(const std::chrono::system_clock::time_point& time);
    static std::string ShortenHash(const std::string& hash, int len = 8);
    static std::string GetStateString(FileStatus::State state);
    static COLORREF GetStateColor(FileStatus::State state);

private:
    GitConfig m_config;
    bool m_initialized = false;
    HWND m_hParent = nullptr;
    std::string m_lastError;
    
    // Callbacks
    CommitSelectedCallback m_commitSelectedCallback;
    LineSelectedCallback m_lineSelectedCallback;
    DiffActionCallback m_diffActionCallback;
    
    // Window handles
    HWND m_hDiffViewer = nullptr;
    HWND m_hBlameViewer = nullptr;
    HWND m_hLogViewer = nullptr;
    
    // Cache
    std::map<std::string, CommitInfo> m_commitCache;
    std::map<std::string, std::vector<BlameLine>> m_blameCache;
    
    // ── Git Command Execution ──
    std::string ExecuteGitCommand(const std::string& args, int* exitCode = nullptr);
    bool ExecuteGitCommandAsync(const std::string& args, 
                                 std::function<void(const std::string& output, int exitCode)> callback);
    
    // ── Parsing ──
    std::vector<DiffLine> ParseDiffOutput(const std::string& output);
    std::vector<BlameLine> ParseBlameOutput(const std::string& output);
    std::vector<CommitInfo> ParseLogOutput(const std::string& output);
    std::vector<FileStatus> ParseStatusOutput(const std::string& output);
    CommitInfo ParseCommitOutput(const std::string& output);
    
    // ── Window Procedures ──
    static LRESULT CALLBACK DiffViewerProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK BlameViewerProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK LogViewerProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    
    // ── Rendering ──
    void RenderDiffLine(HDC hdc, const DiffLine& line, int y, int lineHeight);
    void RenderBlameLine(HDC hdc, const BlameLine& line, int y, int lineHeight);
    void RenderLogEntry(HDC hdc, const CommitInfo& commit, int y, int itemHeight);
    
    // ── Utility ──
    std::wstring Utf8ToWide(const std::string& utf8);
    std::string WideToUtf8(const std::wstring& wide);
    std::string EscapeShellArg(const std::string& arg);
    bool FileExists(const std::string& path);
    std::string GetTempFilePath();
    
    // ── Colors ──
    static constexpr COLORREF DIFF_ADDED_BG = RGB(212, 237, 218);
    static constexpr COLORREF DIFF_ADDED_FG = RGB(21, 87, 36);
    static constexpr COLORREF DIFF_REMOVED_BG = RGB(248, 215, 218);
    static constexpr COLORREF DIFF_REMOVED_FG = RGB(114, 28, 36);
    static constexpr COLORREF DIFF_HEADER_BG = RGB(227, 242, 253);
    static constexpr COLORREF DIFF_HEADER_FG = RGB(13, 71, 161);
    static constexpr COLORREF DIFF_HUNK_BG = RGB(245, 245, 245);
    static constexpr COLORREF DIFF_HUNK_FG = RGB(97, 97, 97);
    
    static constexpr COLORREF BLAME_BOUNDARY_BG = RGB(255, 243, 224);
    static constexpr COLORREF BLAME_NORMAL_BG = RGB(250, 250, 250);
    static constexpr COLORREF BLAME_HASH_FG = RGB(97, 97, 97);
    static constexpr COLORREF BLAME_AUTHOR_FG = RGB(66, 66, 66);
    static constexpr COLORREF BLAME_TIME_FG = RGB(158, 158, 158);
};

// ============================================================================
// GitUIDialog - Modal dialog wrapper for GitUI
// ============================================================================
class GitUIDialog {
public:
    static bool ShowDiffDialog(HWND hParent, const std::string& filePath, 
                                const std::string& oldCommit = "", 
                                const std::string& newCommit = "");
    
    static bool ShowBlameDialog(HWND hParent, const std::string& filePath, int lineNum = -1);
    static bool ShowLogDialog(HWND hParent, const std::string& filePath = "");
    static bool ShowStatusDialog(HWND hParent);
    
    // Quick actions
    static bool QuickCommit(HWND hParent, const std::string& message);
    static bool QuickStage(HWND hParent, const std::vector<std::string>& files);
    static bool QuickCheckout(HWND hParent, const std::string& filePath);
};

} // namespace rawrxd::scm
