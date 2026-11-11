/**
 * @file GitCommitDialog.hpp
 * @brief Git Commit Dialog for RawrXD IDE
 * @status PRODUCTION - Full commit functionality with diff preview
 */

#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <functional>

namespace RawrXD::IDE {

/**
 * @brief Git file status for commit dialog
 */
struct GitFileStatus {
    std::string path;
    char status;  // 'M'=modified, 'A'=added, 'D'=deleted, 'R'=renamed, '?'=untracked
    bool staged;
    bool selected;
};

/**
 * @brief Commit dialog result
 */
struct CommitResult {
    bool confirmed = false;
    std::string message;
    std::vector<std::string> stagedFiles;
    bool amend = false;
    bool signOff = false;
};

/**
 * @brief Git Commit Dialog
 * 
 * Features:
 * - Staged/unstaged file lists
 * - Diff preview for selected file
 * - Commit message editor with spell check
 * - Amend previous commit option
 * - Sign-off option
 */
class GitCommitDialog {
public:
    GitCommitDialog();
    ~GitCommitDialog();
    
    // Creation
    bool Create(HWND hwndParent);
    void Destroy();
    bool IsVisible() const;
    
    // Set data
    void SetFiles(const std::vector<GitFileStatus>& files);
    void SetLastCommitMessage(const std::string& msg);
    void SetBranchName(const std::string& branch);
    
    // Get result after dialog closes
    CommitResult GetResult() const { return m_result; }
    
    // Modal show
    bool ShowModal();
    
    // Callbacks
    void SetStageFileCallback(std::function<void(const std::string&, bool)> callback);
    void SetUnstageFileCallback(std::function<void(const std::string&, bool)> callback);
    void SetGetDiffCallback(std::function<std::string(const std::string&)> callback);
    void SetCommitCallback(std::function<bool(const CommitResult&)> callback);

private:
    HWND m_hwnd;
    HWND m_hwndParent;
    
    // Controls
    HWND m_hwndStagedList;
    HWND m_hwndUnstagedList;
    HWND m_hwndDiffView;
    HWND m_hwndMessageEdit;
    HWND m_hwndAmendCheck;
    HWND m_hwndSignOffCheck;
    HWND m_hwndStatusLabel;
    
    // Data
    std::vector<GitFileStatus> m_files;
    CommitResult m_result;
    std::string m_branchName;
    
    // Callbacks
    std::function<void(const std::string&, bool)> m_stageCallback;
    std::function<void(const std::string&, bool)> m_unstageCallback;
    std::function<std::string(const std::string&)> m_getDiffCallback;
    std::function<bool(const CommitResult&)> m_commitCallback;
    
    // Window procedure
    static INT_PTR CALLBACK DialogProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    INT_PTR HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam);
    
    // UI helpers
    void CreateControls();
    void PopulateFileLists();
    void UpdateDiffView();
    void UpdateStatus();
    void DoCommit();
    void StageSelected();
    void UnstageSelected();
    void CenterOnParent();
    
    // Resource IDs
    static constexpr int IDC_STAGED_LIST = 1001;
    static constexpr int IDC_UNSTAGED_LIST = 1002;
    static constexpr int IDC_DIFF_VIEW = 1003;
    static constexpr int IDC_MESSAGE_EDIT = 1004;
    static constexpr int IDC_AMEND_CHECK = 1005;
    static constexpr int IDC_SIGNOFF_CHECK = 1006;
    static constexpr int IDC_STAGE_BTN = 1007;
    static constexpr int IDC_UNSTAGE_BTN = 1008;
    static constexpr int IDC_COMMIT_BTN = 1009;
    static constexpr int IDC_STATUS_LABEL = 1010;
};

/**
 * @brief Simple wrapper for quick commit
 */
class QuickCommitDialog {
public:
    static bool Show(HWND hwndParent, std::string& outMessage);
};

} // namespace RawrXD::IDE
