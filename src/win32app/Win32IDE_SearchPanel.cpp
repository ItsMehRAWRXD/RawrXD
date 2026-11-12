// Win32IDE_SearchPanel.cpp — Production Find-in-Files with regex, replace, filters
// VS Code parity: Ctrl+Shift+F workspace search with:
//   - Plain text and regex modes
//   - Case-sensitive toggle
//   - Whole-word toggle
//   - Replace / Replace All
//   - Include/Exclude glob patterns
//   - Result count + file grouping
//   - Double-click navigate to file:line
// ============================================================================

#include "Win32IDE.h"
#include <commctrl.h>
#include <fstream>
#include <string>
#include <vector>
#include <regex>
#include <sstream>
#include <algorithm>
#include <thread>
#include <atomic>

// ── Control IDs ────────────────────────────────────────────────────────────
#define IDC_SEARCH_INPUT       10901
#define IDC_SEARCH_REPLACE     10902
#define IDC_SEARCH_INCLUDE     10903
#define IDC_SEARCH_EXCLUDE     10904
#define IDC_SEARCH_BTN_FIND    10905
#define IDC_SEARCH_BTN_REPLACE 10906
#define IDC_SEARCH_BTN_REPLALL 10907
#define IDC_SEARCH_CHK_CASE    10908
#define IDC_SEARCH_CHK_REGEX   10909
#define IDC_SEARCH_CHK_WORD    10910
#define IDC_SEARCH_STATUS      10911

// ── State ──────────────────────────────────────────────────────────────────
namespace {
    static std::atomic<bool> s_searchRunning{false};
    static std::atomic<int>  s_searchResultCount{0};
    static std::atomic<int>  s_searchFileCount{0};
}

// ── Helpers ────────────────────────────────────────────────────────────────

static bool matchesGlob(const std::string& filename, const std::string& globPattern) {
    if (globPattern.empty() || globPattern == "*") return true;

    std::istringstream iss(globPattern);
    std::string pat;
    while (std::getline(iss, pat, ',')) {
        while (!pat.empty() && pat.front() == ' ') pat.erase(pat.begin());
        while (!pat.empty() && pat.back() == ' ') pat.pop_back();
        if (pat.empty()) continue;

        if (pat.size() >= 2 && pat[0] == '*' && pat[1] == '.') {
            std::string ext = pat.substr(1);
            if (filename.size() >= ext.size() &&
                _stricmp(filename.c_str() + filename.size() - ext.size(), ext.c_str()) == 0) {
                return true;
            }
        } else if (pat == "*.*") {
            if (filename.find('.') != std::string::npos) return true;
        } else {
            if (_stricmp(filename.c_str(), pat.c_str()) == 0) return true;
        }
    }
    return false;
}

static bool isSearchableFile(const std::string& name) {
    static const char* exts[] = {
        ".cpp", ".h", ".c", ".hpp", ".cxx", ".cc",
        ".asm", ".inc", ".s",
        ".py", ".js", ".ts", ".jsx", ".tsx",
        ".json", ".xml", ".yaml", ".yml", ".toml",
        ".md", ".txt", ".rst", ".log",
        ".cmake", ".bat", ".ps1", ".sh",
        ".css", ".html", ".htm", ".svg",
        ".rs", ".go", ".java", ".cs", ".rb",
        ".zig", ".nim", ".lua", ".r",
        ".gitignore", ".editorconfig", nullptr
    };
    for (int i = 0; exts[i]; ++i) {
        if (name.size() >= strlen(exts[i]) &&
            _stricmp(name.c_str() + name.size() - strlen(exts[i]), exts[i]) == 0)
            return true;
    }
    if (name.find('.') == std::string::npos && name.size() < 32) return true;
    return false;
}

// ============================================================================
// CREATE SEARCH PANEL
// ============================================================================

void Win32IDE::createSearchPanel() {
    if (!m_hwndSidebar) return;

    int w = m_sidebarWidth - 10;
    int y = 5;

    CreateWindowExA(0, "STATIC", "Search:", WS_CHILD | WS_VISIBLE | SS_LEFT,
        5, y + 2, 50, 16, m_hwndSidebar, nullptr, m_hInstance, nullptr);
    m_hwndSearchInput = CreateWindowExA(
        WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | WS_TABSTOP,
        58, y, w - 118, 22, m_hwndSidebar,
        (HMENU)(UINT_PTR)IDC_SEARCH_INPUT, m_hInstance, nullptr);
    CreateWindowExA(0, "BUTTON", "Find", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        w - 55, y, 55, 22, m_hwndSidebar,
        (HMENU)(UINT_PTR)IDC_SEARCH_BTN_FIND, m_hInstance, nullptr);
    y += 26;

    CreateWindowExA(0, "STATIC", "Replace:", WS_CHILD | WS_VISIBLE | SS_LEFT,
        5, y + 2, 50, 16, m_hwndSidebar, nullptr, m_hInstance, nullptr);
    m_hwndSearchReplace = CreateWindowExA(
        WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | WS_TABSTOP,
        58, y, w - 178, 22, m_hwndSidebar,
        (HMENU)(UINT_PTR)IDC_SEARCH_REPLACE, m_hInstance, nullptr);
    CreateWindowExA(0, "BUTTON", "Repl", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        w - 115, y, 52, 22, m_hwndSidebar,
        (HMENU)(UINT_PTR)IDC_SEARCH_BTN_REPLACE, m_hInstance, nullptr);
    CreateWindowExA(0, "BUTTON", "All", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        w - 57, y, 52, 22, m_hwndSidebar,
        (HMENU)(UINT_PTR)IDC_SEARCH_BTN_REPLALL, m_hInstance, nullptr);
    y += 26;

    CreateWindowExA(0, "BUTTON", "Aa", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        5, y, 36, 18, m_hwndSidebar,
        (HMENU)(UINT_PTR)IDC_SEARCH_CHK_CASE, m_hInstance, nullptr);
    CreateWindowExA(0, "BUTTON", ".*", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        44, y, 36, 18, m_hwndSidebar,
        (HMENU)(UINT_PTR)IDC_SEARCH_CHK_REGEX, m_hInstance, nullptr);
    CreateWindowExA(0, "BUTTON", "\\b", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        83, y, 36, 18, m_hwndSidebar,
        (HMENU)(UINT_PTR)IDC_SEARCH_CHK_WORD, m_hInstance, nullptr);
    y += 20;

    CreateWindowExA(0, "STATIC", "Include:", WS_CHILD | WS_VISIBLE | SS_LEFT,
        5, y + 2, 50, 14, m_hwndSidebar, nullptr, m_hInstance, nullptr);
    m_hwndSearchInclude = CreateWindowExA(
        WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | WS_TABSTOP,
        58, y, w - 58, 20, m_hwndSidebar,
        (HMENU)(UINT_PTR)IDC_SEARCH_INCLUDE, m_hInstance, nullptr);
    y += 22;

    CreateWindowExA(0, "STATIC", "Exclude:", WS_CHILD | WS_VISIBLE | SS_LEFT,
        5, y + 2, 50, 14, m_hwndSidebar, nullptr, m_hInstance, nullptr);
    m_hwndSearchExclude = CreateWindowExA(
        WS_EX_CLIENTEDGE, "EDIT", "node_modules, .git, build, bin, obj",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | WS_TABSTOP,
        58, y, w - 58, 20, m_hwndSidebar,
        (HMENU)(UINT_PTR)IDC_SEARCH_EXCLUDE, m_hInstance, nullptr);
    y += 24;

    m_hwndSearchStatus = CreateWindowExA(0, "STATIC", "Ready",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        5, y, w, 16, m_hwndSidebar,
        (HMENU)(UINT_PTR)IDC_SEARCH_STATUS, m_hInstance, nullptr);
    y += 18;

    m_hwndSearchResults = CreateWindowExA(
        WS_EX_CLIENTEDGE, WC_LISTVIEWA, "",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
        5, y, w, 500 - y - 5,
        m_hwndSidebar, nullptr, m_hInstance, nullptr);

    ListView_SetExtendedListViewStyle(m_hwndSearchResults,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);

    LVCOLUMNA col = {};
    col.mask = LVCF_TEXT | LVCF_WIDTH;

    col.pszText = (LPSTR)"File";
    col.cx = 160;
    ListView_InsertColumn(m_hwndSearchResults, 0, &col);

    col.pszText = (LPSTR)"Ln";
    col.cx = 40;
    ListView_InsertColumn(m_hwndSearchResults, 1, &col);

    col.pszText = (LPSTR)"Match";
    col.cx = 220;
    ListView_InsertColumn(m_hwndSearchResults, 2, &col);
}

// ============================================================================
// PERFORM SEARCH
// ============================================================================

void Win32IDE::performSearch() {
    {
        std::ofstream crumb("F:\\rawrxd\\evidence\\TOP25_C30_SEARCH_INVOKE.log",
                            std::ios::trunc);
        if (crumb) {
            crumb << "enter input=" << (m_hwndSearchInput ? 1 : 0)
                  << " results=" << (m_hwndSearchResults ? 1 : 0)
                  << " status=" << (m_hwndSearchStatus ? 1 : 0) << "\n";
        }
    }
    if (!m_hwndSearchResults) return;
    if (s_searchRunning.load()) return;

    // Prefer GetDlgItem under sidebar — EnumChild FindId(10901) can hit a
    // different control before the real search edit; member HWND can also drift.
    HWND input = nullptr;
    if (m_hwndSidebar) input = GetDlgItem(m_hwndSidebar, IDC_SEARCH_INPUT);
    if (!input || !IsWindow(input)) input = m_hwndSearchInput;
    if (input && IsWindow(input)) m_hwndSearchInput = input;
    if (!input || !IsWindow(input)) return;

    char query[1024] = {};
    // Prefer WM_GETTEXT — cross-process SetWindowTextA can leave GetWindowTextA
    // empty on some Edit builds while WM_GETTEXT still sees the buffer.
    const LRESULT n = SendMessageA(input, WM_GETTEXT, (WPARAM)sizeof(query),
                                   reinterpret_cast<LPARAM>(query));
    if (n <= 0) {
        GetWindowTextA(input, query, sizeof(query));
    }
    {
        std::ofstream crumb("F:\\rawrxd\\evidence\\TOP25_C30_SEARCH_INVOKE.log",
                            std::ios::app);
        if (crumb) {
            crumb << "query_len=" << strlen(query) << " q=" << query
                  << " input_hwnd=" << reinterpret_cast<uintptr_t>(input)
                  << " wm_gettext_n=" << static_cast<long long>(n) << "\n";
        }
    }
    if (strlen(query) == 0) return;

    bool caseSensitive = (SendDlgItemMessageA(m_hwndSidebar, IDC_SEARCH_CHK_CASE, BM_GETCHECK, 0, 0) == BST_CHECKED);
    bool useRegex      = (SendDlgItemMessageA(m_hwndSidebar, IDC_SEARCH_CHK_REGEX, BM_GETCHECK, 0, 0) == BST_CHECKED);
    bool wholeWord     = (SendDlgItemMessageA(m_hwndSidebar, IDC_SEARCH_CHK_WORD, BM_GETCHECK, 0, 0) == BST_CHECKED);

    char includeBuf[512] = {};
    char excludeBuf[512] = {};
    if (m_hwndSearchInclude)
        GetWindowTextA(m_hwndSearchInclude, includeBuf, sizeof(includeBuf));
    if (m_hwndSearchExclude)
        GetWindowTextA(m_hwndSearchExclude, excludeBuf, sizeof(excludeBuf));

    ListView_DeleteAllItems(m_hwndSearchResults);
    s_searchResultCount = 0;
    s_searchFileCount = 0;

    if (m_hwndSearchStatus)
        SetWindowTextA(m_hwndSearchStatus, "Searching...");

    std::string searchRoot = m_explorerRootPath;
    if (searchRoot.empty() && !m_currentExplorerPath.empty())
        searchRoot = m_currentExplorerPath;
    if (searchRoot.empty()) {
        char cwd[MAX_PATH] = {};
        GetCurrentDirectoryA(MAX_PATH, cwd);
        searchRoot = cwd;
    }

    std::string queryStr(query);
    std::string includeStr(includeBuf);
    std::string excludeStr(excludeBuf);

    searchDirectory(searchRoot, queryStr.c_str(), 0,
                    caseSensitive, useRegex, wholeWord,
                    includeStr, excludeStr);

    if (m_hwndSearchStatus) {
        char statusBuf[256];
        sprintf_s(statusBuf, "%d results in %d files",
                  s_searchResultCount.load(), s_searchFileCount.load());
        SetWindowTextA(m_hwndSearchStatus, statusBuf);
    }
}

// ============================================================================
// RECURSIVE DIRECTORY SEARCH
// ============================================================================

void Win32IDE::searchDirectory(const std::string& dir, const char* query, int depth,
                                bool caseSensitive, bool useRegex, bool wholeWord,
                                const std::string& includeFilter,
                                const std::string& excludeFilter) {
    if (depth > 8) return;

    WIN32_FIND_DATAA findData;
    std::string pattern = dir + "\\*";
    HANDLE hFind = FindFirstFileA(pattern.c_str(), &findData);

    if (hFind == INVALID_HANDLE_VALUE) return;

    std::vector<std::string> excludeDirs = {
        ".git", ".vs", "node_modules", "CMakeFiles", "build", "build_ide",
        "build_win32ide", "evidence", "crash_dumps", "bin", "bin-msvc",
        "_pre_merge_backup", ".swarm_runs"
    };
    {
        std::istringstream iss(excludeFilter);
        std::string tok;
        while (std::getline(iss, tok, ',')) {
            while (!tok.empty() && tok.front() == ' ') tok.erase(tok.begin());
            while (!tok.empty() && tok.back() == ' ') tok.pop_back();
            if (!tok.empty()) excludeDirs.push_back(tok);
        }
    }

    std::regex rxPattern;
    bool regexValid = false;
    if (useRegex) {
        try {
            auto flags = std::regex::ECMAScript | std::regex::optimize;
            if (!caseSensitive) flags |= std::regex::icase;
            rxPattern = std::regex(query, flags);
            regexValid = true;
        } catch (...) {}
    }

    do {
        std::string name = findData.cFileName;
        if (name == "." || name == "..") continue;

        std::string fullPath = dir + "\\" + name;

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            bool skip = false;
            for (const auto& ex : excludeDirs) {
                if (_stricmp(name.c_str(), ex.c_str()) == 0) { skip = true; break; }
            }
            if (!skip) {
                searchDirectory(fullPath, query, depth + 1,
                                caseSensitive, useRegex, wholeWord,
                                includeFilter, excludeFilter);
            }
        } else {
            if (!includeFilter.empty() && !matchesGlob(name, includeFilter)) continue;
            if (includeFilter.empty() && !isSearchableFile(name)) continue;

            std::ifstream file(fullPath);
            if (!file.is_open()) continue;

            std::string line;
            int lineNum = 0;
            bool fileHasMatch = false;

            while (std::getline(file, line)) {
                lineNum++;
                bool matched = false;

                if (useRegex && regexValid) {
                    matched = std::regex_search(line, rxPattern);
                } else {
                    std::string haystack = line;
                    std::string needle = query;
                    if (!caseSensitive) {
                        std::transform(haystack.begin(), haystack.end(), haystack.begin(), ::tolower);
                        std::transform(needle.begin(), needle.end(), needle.begin(), ::tolower);
                    }

                    size_t pos = haystack.find(needle);
                    if (pos != std::string::npos) {
                        if (wholeWord) {
                            bool leftOk  = (pos == 0 || !isalnum((unsigned char)haystack[pos - 1]));
                            bool rightOk = (pos + needle.size() >= haystack.size() ||
                                            !isalnum((unsigned char)haystack[pos + needle.size()]));
                            matched = leftOk && rightOk;
                        } else {
                            matched = true;
                        }
                    }
                }

                if (matched) {
                    if (!fileHasMatch) {
                        s_searchFileCount++;
                        fileHasMatch = true;
                    }
                    s_searchResultCount++;

                    std::string display = fullPath;
                    for (char& c : display) { if (c == '\\') c = '/'; }

                    LVITEMA item = {};
                    item.mask = LVIF_TEXT;
                    item.iItem = ListView_GetItemCount(m_hwndSearchResults);
                    item.pszText = (LPSTR)display.c_str();
                    int idx = SendMessageA(m_hwndSearchResults, LVM_INSERTITEMA, 0, (LPARAM)&item);

                    char lineStr[16];
                    sprintf_s(lineStr, "%d", lineNum);
                    LVITEMA lvItemA1 = {};
                    lvItemA1.iSubItem = 1;
                    lvItemA1.pszText = lineStr;
                    SendMessageA(m_hwndSearchResults, LVM_SETITEMTEXTA, (WPARAM)idx, (LPARAM)&lvItemA1);

                    std::string trimmed = line;
                    size_t firstNonSpace = trimmed.find_first_not_of(" \t");
                    if (firstNonSpace != std::string::npos && firstNonSpace > 0)
                        trimmed = trimmed.substr(firstNonSpace);
                    if (trimmed.length() > 120)
                        trimmed = trimmed.substr(0, 117) + "...";
                    LVITEMA lvItemA2 = {};
                    lvItemA2.iSubItem = 2;
                    lvItemA2.pszText = (LPSTR)trimmed.c_str();
                    SendMessageA(m_hwndSearchResults, LVM_SETITEMTEXTA, (WPARAM)idx, (LPARAM)&lvItemA2);

                    if (s_searchResultCount >= 5000) {
                        FindClose(hFind);
                        return;
                    }
                }
            }
        }
    } while (FindNextFileA(hFind, &findData));

    FindClose(hFind);
}

// ============================================================================
// REPLACE IN FILES
// ============================================================================

void Win32IDE::performSearchReplace(bool replaceAll) {
    if (!m_hwndSearchInput || !m_hwndSearchResults) return;

    char query[1024] = {};
    char replacement[1024] = {};
    GetWindowTextA(m_hwndSearchInput, query, sizeof(query));
    if (m_hwndSearchReplace)
        GetWindowTextA(m_hwndSearchReplace, replacement, sizeof(replacement));

    if (strlen(query) == 0) return;
    if (strlen(replacement) == 0) {
        int confirm = MessageBoxA(m_hwndMain,
            "Replace with empty string (delete matches)?",
            "Replace", MB_YESNO | MB_ICONQUESTION);
        if (confirm != IDYES) return;
    }

    bool caseSensitive = (SendDlgItemMessageA(m_hwndSidebar, IDC_SEARCH_CHK_CASE, BM_GETCHECK, 0, 0) == BST_CHECKED);

    int count = ListView_GetItemCount(m_hwndSearchResults);
    if (count == 0) {
        MessageBoxA(m_hwndMain, "No search results to replace in. Run search first.", "Replace", MB_OK);
        return;
    }

    std::vector<std::string> files;
    for (int i = 0; i < count; ++i) {
        char fileBuf[MAX_PATH] = {};
        LVITEMA lvItemA = {};
        lvItemA.iItem = i;
        lvItemA.iSubItem = 0;
        lvItemA.pszText = fileBuf;
        lvItemA.cchTextMax = sizeof(fileBuf);
        SendMessageA(m_hwndSearchResults, LVM_GETITEMA, 0, (LPARAM)&lvItemA);
        std::string path(fileBuf);
        for (char& c : path) { if (c == '/') c = '\\'; }
        if (std::find(files.begin(), files.end(), path) == files.end())
            files.push_back(path);
    }

    int totalReplacements = 0;
    std::string queryStr(query);
    std::string replStr(replacement);

    for (const auto& filePath : files) {
        std::ifstream inFile(filePath);
        if (!inFile.is_open()) continue;

        std::string content((std::istreambuf_iterator<char>(inFile)),
                             std::istreambuf_iterator<char>());
        inFile.close();

        std::string modified;
        size_t pos = 0;
        std::string searchContent = content;
        std::string searchQuery = queryStr;
        if (!caseSensitive) {
            std::transform(searchContent.begin(), searchContent.end(), searchContent.begin(), ::tolower);
            std::transform(searchQuery.begin(), searchQuery.end(), searchQuery.begin(), ::tolower);
        }

        size_t lastPos = 0;
        bool anyReplaced = false;
        while ((pos = searchContent.find(searchQuery, lastPos)) != std::string::npos) {
            modified += content.substr(lastPos, pos - lastPos);
            modified += replStr;
            lastPos = pos + queryStr.size();
            totalReplacements++;
            anyReplaced = true;
            if (!replaceAll) break;
        }
        modified += content.substr(lastPos);

        if (anyReplaced) {
            std::ofstream outFile(filePath, std::ios::trunc);
            if (outFile.is_open()) {
                outFile << modified;
            }
        }
    }

    char msg[256];
    sprintf_s(msg, "Replaced %d occurrence(s) in %d file(s).",
              totalReplacements, (int)files.size());
    appendToOutput(std::string("[Search] ") + msg, "Search", OutputSeverity::Info);

    if (m_hwndSearchStatus)
        SetWindowTextA(m_hwndSearchStatus, msg);

    performSearch();
}
