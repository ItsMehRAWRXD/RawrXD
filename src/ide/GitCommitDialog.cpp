/**
 * @file GitCommitDialog.cpp
 * @brief Git Commit Dialog Implementation
 */

#include "GitCommitDialog.hpp"
#include "ANSIColorParser.hpp"
#include <richedit.h>
#include <commctrl.h>
#include <commdlg.h>

#pragma comment(lib, "comctl32.lib")

namespace RawrXD::IDE {

GitCommitDialog::GitCommitDialog()
    : m_hwnd(nullptr)
    , m_hwndParent(nullptr)
    , m_hwndStagedList(nullptr)
    , m_hwndUnstagedList(nullptr)
    , m_hwndDiffView(nullptr)
    , m_hwndMessageEdit(nullptr)
    , m_hwndAmendCheck(nullptr)
    , m_hwndSignOffCheck(nullptr)
    , m_hwndStatusLabel(nullptr)
{
}

GitCommitDialog::~GitCommitDialog() {
    Destroy();
}

bool GitCommitDialog::Create(HWND hwndParent) {
    if (m_hwnd) return true;
    
    m_hwndParent = hwndParent;
    
    // Register dialog class
    WNDCLASSEXW wcx = {};
    wcx.cbSize = sizeof(wcx);
    wcx.lpfnWndProc = DefWindowProcW;
    wcx.hInstance = GetModuleHandle(nullptr);
    wcx.lpszClassName = L"RawrXD_GitCommitDialog";
    wcx.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    RegisterClassExW(&wcx);
    
    // Create dialog window
    m_hwnd = CreateWindowExW(
        WS_EX_DLGMODALFRAME | WS_EX_CONTEXTHELP,
        L"RawrXD_GitCommitDialog",
        L"Git Commit",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME,
        CW_USEDEFAULT, CW_USEDEFAULT,
        800, 600,
        hwndParent,
        nullptr,
        GetModuleHandle(nullptr),
        this
    );
    
    if (!m_hwnd) return false;
    
    SetWindowLongPtr(m_hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));
    
    // Load RichEdit
    LoadLibraryW(L"msftedit.dll");
    
    CreateControls();
    PopulateFileLists();
    
    return true;
}

void GitCommitDialog::CreateControls() {
    HINSTANCE hInst = GetModuleHandle(nullptr);
    
    // Unstaged files group
    CreateWindowW(L"BUTTON", L"Unstaged Changes",
        WS_VISIBLE | WS_CHILD | BS_GROUPBOX,
        10, 10, 250, 200, m_hwnd, nullptr, hInst, nullptr);
    
    m_hwndUnstagedList = CreateWindowW(L"LISTBOX", L"",
        WS_VISIBLE | WS_CHILD | WS_BORDER | WS_VSCROLL | LBS_NOTIFY | LBS_EXTENDEDSEL,
        20, 30, 230, 140, m_hwnd, (HMENU)IDC_UNSTAGED_LIST, hInst, nullptr);
    
    // Stage button
    CreateWindowW(L"BUTTON", L"Stage ▶",
        WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        270, 80, 80, 25, m_hwnd, (HMENU)IDC_STAGE_BTN, hInst, nullptr);
    
    // Unstage button
    CreateWindowW(L"BUTTON", L"◀ Unstage",
        WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        270, 115, 80, 25, m_hwnd, (HMENU)IDC_UNSTAGE_BTN, hInst, nullptr);
    
    // Staged files group
    CreateWindowW(L"BUTTON", L"Staged Changes",
        WS_VISIBLE | WS_CHILD | BS_GROUPBOX,
        360, 10, 250, 200, m_hwnd, nullptr, hInst, nullptr);
    
    m_hwndStagedList = CreateWindowW(L"LISTBOX", L"",
        WS_VISIBLE | WS_CHILD | WS_BORDER | WS_VSCROLL | LBS_NOTIFY | LBS_EXTENDEDSEL,
        370, 30, 230, 140, m_hwnd, (HMENU)IDC_STAGED_LIST, hInst, nullptr);
    
    // Diff view group
    CreateWindowW(L"BUTTON", L"Diff Preview",
        WS_VISIBLE | WS_CHILD | BS_GROUPBOX,
        10, 220, 600, 250, m_hwnd, nullptr, hInst, nullptr);
    
    m_hwndDiffView = CreateWindowExW(WS_EX_CLIENTEDGE, MSFTEDIT_CLASS, L"",
        WS_VISIBLE | WS_CHILD | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_READONLY,
        20, 240, 580, 220, m_hwnd, (HMENU)IDC_DIFF_VIEW, hInst, nullptr);
    
    // Set diff view font
    HFONT hFont = CreateFontW(12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                            DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");
    SendMessage(m_hwndDiffView, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(m_hwndDiffView, EM_SETBKGNDCOLOR, 0, RGB(30, 30, 30));
    
    // Commit message group
    CreateWindowW(L"BUTTON", L"Commit Message",
        WS_VISIBLE | WS_CHILD | BS_GROUPBOX,
        10, 480, 600, 80, m_hwnd, nullptr, hInst, nullptr);
    
    m_hwndMessageEdit = CreateWindowW(L"EDIT", L"",
        WS_VISIBLE | WS_CHILD | WS_BORDER | ES_MULTILINE | ES_AUTOVSCROLL,
        20, 500, 580, 50, m_hwnd, (HMENU)IDC_MESSAGE_EDIT, hInst, nullptr);
    
    // Options
    m_hwndAmendCheck = CreateWindowW(L"BUTTON", L"Amend previous commit",
        WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
        620, 30, 160, 20, m_hwnd, (HMENU)IDC_AMEND_CHECK, hInst, nullptr);
    
    m_hwndSignOffCheck = CreateWindowW(L"BUTTON", L"Sign-off",
        WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
        620, 55, 100, 20, m_hwnd, (HMENU)IDC_SIGNOFF_CHECK, hInst, nullptr);
    
    // Status label
    m_hwndStatusLabel = CreateWindowW(L"STATIC", L"Ready",
        WS_VISIBLE | WS_CHILD | SS_LEFT,
        620, 90, 160, 60, m_hwnd, (HMENU)IDC_STATUS_LABEL, hInst, nullptr);
    
    // Buttons
    CreateWindowW(L"BUTTON", L"&Commit",
        WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
        620, 480, 80, 25, m_hwnd, (HMENU)IDC_COMMIT_BTN, hInst, nullptr);
    
    CreateWindowW(L"BUTTON", L"Cancel",
        WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        620, 515, 80, 25, m_hwnd, (HMENU)IDCANCEL, hInst, nullptr);
}

void GitCommitDialog::PopulateFileLists() {
    if (!m_hwnd) return;
    
    // Clear lists
    SendMessage(m_hwndStagedList, LB_RESETCONTENT, 0, 0);
    SendMessage(m_hwndUnstagedList, LB_RESETCONTENT, 0, 0);
    
    // Populate
    for (const auto& file : m_files) {
        std::wstring display = std::wstring(1, file.status) + L" " + 
                              std::wstring(file.path.begin(), file.path.end());
        
        if (file.staged) {
            SendMessage(m_hwndStagedList, LB_ADDSTRING, 0, (LPARAM)display.c_str());
        } else {
            SendMessage(m_hwndUnstagedList, LB_ADDSTRING, 0, (LPARAM)display.c_str());
        }
    }
    
    UpdateStatus();
}

void GitCommitDialog::UpdateStatus() {
    if (!m_hwndStatusLabel) return;
    
    int staged = 0, unstaged = 0;
    for (const auto& f : m_files) {
        if (f.staged) staged++;
        else unstaged++;
    }
    
    std::wstring status = L"Branch: " + std::wstring(m_branchName.begin(), m_branchName.end()) + L"\n" +
                          L"Staged: " + std::to_wstring(staged) + L"\n" +
                          L"Unstaged: " + std::to_wstring(unstaged);
    
    SetWindowTextW(m_hwndStatusLabel, status.c_str());
}

void GitCommitDialog::UpdateDiffView() {
    if (!m_hwndDiffView) return;
    
    // Get selected file from either list
    int sel = (int)SendMessage(m_hwndUnstagedList, LB_GETCURSEL, 0, 0);
    if (sel == LB_ERR) {
        sel = (int)SendMessage(m_hwndStagedList, LB_GETCURSEL, 0, 0);
    }
    
    if (sel == LB_ERR || !m_getDiffCallback) {
        SetWindowText(m_hwndDiffView, L"");
        return;
    }
    
    // Get file path
    std::string path = m_files[sel].path;
    std::string diff = m_getDiffCallback(path);
    
    // Convert and display
    int len = MultiByteToWideChar(CP_UTF8, 0, diff.c_str(), -1, nullptr, 0);
    std::wstring wdiff(len, 0);
    MultiByteToWideChar(CP_UTF8, 0, diff.c_str(), -1, &wdiff[0], len);
    
    SetWindowText(m_hwndDiffView, wdiff.c_str());
}

void GitCommitDialog::DoCommit() {
    // Get message
    wchar_t msg[4096];
    GetWindowTextW(m_hwndMessageEdit, msg, sizeof(msg)/sizeof(msg[0]));
    
    if (wcslen(msg) == 0) {
        MessageBoxW(m_hwnd, L"Please enter a commit message.", L"Git Commit", 
                    MB_OK | MB_ICONWARNING);
        return;
    }
    
    // Convert to UTF-8 for git
    int utf8Len = WideCharToMultiByte(CP_UTF8, 0, msg, -1, nullptr, 0, nullptr, nullptr);
    std::string utf8msg;
    if (utf8Len > 0) {
        utf8msg.resize(utf8Len - 1);
        WideCharToMultiByte(CP_UTF8, 0, msg, -1, &utf8msg[0], utf8Len, nullptr, nullptr);
    }
    
    // Build result
    m_result.confirmed = true;
    m_result.message = utf8msg;
    m_result.amend = IsDlgButtonChecked(m_hwnd, IDC_AMEND_CHECK) == BST_CHECKED;
    m_result.signOff = IsDlgButtonChecked(m_hwnd, IDC_SIGNOFF_CHECK) == BST_CHECKED;
    
    // Get staged files
    for (const auto& f : m_files) {
        if (f.staged) {
            m_result.stagedFiles.push_back(f.path);
        }
    }
    
    if (m_result.stagedFiles.empty() && !m_result.amend) {
        MessageBoxA(m_hwnd, "No files staged for commit.", "Git Commit",
                    MB_OK | MB_ICONWARNING);
        return;
    }
    
    // Execute commit
    if (m_commitCallback) {
        if (m_commitCallback(m_result)) {
            Destroy();
        }
    } else {
        Destroy();
    }
}

void GitCommitDialog::StageSelected() {
    int sel = (int)SendMessage(m_hwndUnstagedList, LB_GETCURSEL, 0, 0);
    if (sel == LB_ERR) return;
    
    // Find file in unstaged list
    int unstagedIdx = 0;
    for (auto& f : m_files) {
        if (!f.staged) {
            if (unstagedIdx == sel) {
                if (m_stageCallback) {
                    m_stageCallback(f.path, true);
                }
                f.staged = true;
                break;
            }
            unstagedIdx++;
        }
    }
    
    PopulateFileLists();
}

void GitCommitDialog::UnstageSelected() {
    int sel = (int)SendMessage(m_hwndStagedList, LB_GETCURSEL, 0, 0);
    if (sel == LB_ERR) return;
    
    // Find file in staged list
    int stagedIdx = 0;
    for (auto& f : m_files) {
        if (f.staged) {
            if (stagedIdx == sel) {
                if (m_unstageCallback) {
                    m_unstageCallback(f.path, false);
                }
                f.staged = false;
                break;
            }
            stagedIdx++;
        }
    }
    
    PopulateFileLists();
}

void GitCommitDialog::Destroy() {
    if (m_hwnd) {
        DestroyWindow(m_hwnd);
        m_hwnd = nullptr;
    }
}

bool GitCommitDialog::IsVisible() const {
    return m_hwnd && IsWindowVisible(m_hwnd);
}

void GitCommitDialog::SetFiles(const std::vector<GitFileStatus>& files) {
    m_files = files;
    if (m_hwnd) {
        PopulateFileLists();
    }
}

void GitCommitDialog::SetLastCommitMessage(const std::string& msg) {
    if (m_hwndMessageEdit) {
        std::wstring wmsg(msg.begin(), msg.end());
        SetWindowTextW(m_hwndMessageEdit, wmsg.c_str());
    }
}

void GitCommitDialog::SetBranchName(const std::string& branch) {
    m_branchName = branch;
    if (m_hwnd) {
        UpdateStatus();
    }
}

bool GitCommitDialog::ShowModal() {
    if (!m_hwnd) return false;
    
    CenterOnParent();
    ShowWindow(m_hwnd, SW_SHOW);
    SetFocus(m_hwndMessageEdit);
    
    // Modal message loop
    MSG msg;
    while (IsVisible()) {
        if (GetMessage(&msg, nullptr, 0, 0)) {
            if (!IsDialogMessage(m_hwnd, &msg)) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
        }
    }
    
    return m_result.confirmed;
}

void GitCommitDialog::CenterOnParent() {
    if (!m_hwnd || !m_hwndParent) return;
    
    RECT rcParent, rcDialog;
    GetWindowRect(m_hwndParent, &rcParent);
    GetWindowRect(m_hwnd, &rcDialog);
    
    int width = rcDialog.right - rcDialog.left;
    int height = rcDialog.bottom - rcDialog.top;
    int parentWidth = rcParent.right - rcParent.left;
    int parentHeight = rcParent.bottom - rcParent.top;
    
    int x = rcParent.left + (parentWidth - width) / 2;
    int y = rcParent.top + (parentHeight - height) / 2;
    
    SetWindowPos(m_hwnd, nullptr, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
}

void GitCommitDialog::SetStageFileCallback(std::function<void(const std::string&, bool)> callback) {
    m_stageCallback = callback;
}

void GitCommitDialog::SetUnstageFileCallback(std::function<void(const std::string&, bool)> callback) {
    m_unstageCallback = callback;
}

void GitCommitDialog::SetGetDiffCallback(std::function<std::string(const std::string&)> callback) {
    m_getDiffCallback = callback;
}

void GitCommitDialog::SetCommitCallback(std::function<bool(const CommitResult&)> callback) {
    m_commitCallback = callback;
}

INT_PTR CALLBACK GitCommitDialog::DialogProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    GitCommitDialog* dlg = reinterpret_cast<GitCommitDialog*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    
    if (!dlg && msg == WM_INITDIALOG) {
        dlg = reinterpret_cast<GitCommitDialog*>(lParam);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(dlg));
    }
    
    if (dlg) {
        return dlg->HandleMessage(msg, wParam, lParam);
    }
    
    return FALSE;
}

INT_PTR GitCommitDialog::HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_INITDIALOG:
            return TRUE;
            
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case IDC_STAGE_BTN:
                    StageSelected();
                    return TRUE;
                    
                case IDC_UNSTAGE_BTN:
                    UnstageSelected();
                    return TRUE;
                    
                case IDC_COMMIT_BTN:
                    DoCommit();
                    return TRUE;
                    
                case IDCANCEL:
                case IDCLOSE:
                    Destroy();
                    return TRUE;
                    
                case IDC_UNSTAGED_LIST:
                case IDC_STAGED_LIST:
                    if (HIWORD(wParam) == LBN_SELCHANGE) {
                        UpdateDiffView();
                    }
                    return TRUE;
            }
            break;
            
        case WM_CLOSE:
            Destroy();
            return TRUE;
    }
    
    return FALSE;
}

// ============================================================================
// QuickCommitDialog Implementation
// ============================================================================

bool QuickCommitDialog::Show(HWND hwndParent, std::string& outMessage) {
    // Simple input dialog
    wchar_t buffer[1024] = {};
    
    // Create simple input box
    HWND hwndDlg = CreateWindowExW(
        WS_EX_DLGMODALFRAME,
        L"#32770",
        L"Git Commit",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT,
        400, 150,
        hwndParent,
        nullptr,
        GetModuleHandle(nullptr),
        nullptr
    );
    
    if (!hwndDlg) return false;
    
    // Create controls
    CreateWindowW(L"STATIC", L"Commit message:",
        WS_VISIBLE | WS_CHILD | SS_LEFT,
        10, 10, 380, 20, hwndDlg, nullptr, GetModuleHandle(nullptr), nullptr);
    
    HWND hwndEdit = CreateWindowW(L"EDIT", L"",
        WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL,
        10, 35, 370, 25, hwndDlg, nullptr, GetModuleHandle(nullptr), nullptr);
    
    CreateWindowW(L"BUTTON", L"Commit",
        WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
        210, 75, 80, 25, hwndDlg, (HMENU)IDOK, GetModuleHandle(nullptr), nullptr);
    
    CreateWindowW(L"BUTTON", L"Cancel",
        WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        300, 75, 80, 25, hwndDlg, (HMENU)IDCANCEL, GetModuleHandle(nullptr), nullptr);
    
    // Center
    RECT rcParent;
    GetWindowRect(hwndParent, &rcParent);
    SetWindowPos(hwndDlg, nullptr, 
        rcParent.left + (rcParent.right - rcParent.left - 400) / 2,
        rcParent.top + (rcParent.bottom - rcParent.top - 150) / 2,
        0, 0, SWP_NOSIZE | SWP_NOZORDER);
    
    ShowWindow(hwndDlg, SW_SHOW);
    SetFocus(hwndEdit);
    
    // Modal loop
    bool confirmed = false;
    MSG msg;
    while (IsWindow(hwndDlg)) {
        if (GetMessage(&msg, nullptr, 0, 0)) {
            if (msg.hwnd == hwndDlg || IsChild(hwndDlg, msg.hwnd)) {
                if (msg.message == WM_COMMAND) {
                    if (LOWORD(msg.wParam) == IDOK) {
                        GetWindowTextW(hwndEdit, buffer, 1024);
                        confirmed = true;
                        DestroyWindow(hwndDlg);
                        continue;
                    } else if (LOWORD(msg.wParam) == IDCANCEL) {
                        DestroyWindow(hwndDlg);
                        continue;
                    }
                }
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            } else {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
        }
    }
    
    if (confirmed && wcslen(buffer) > 0) {
        int len = WideCharToMultiByte(CP_UTF8, 0, buffer, -1, nullptr, 0, nullptr, nullptr);
        outMessage.resize(len);
        WideCharToMultiByte(CP_UTF8, 0, buffer, -1, &outMessage[0], len, nullptr, nullptr);
        outMessage.resize(len - 1);  // Remove null terminator
        return true;
    }
    
    return false;
}

} // namespace RawrXD::IDE
