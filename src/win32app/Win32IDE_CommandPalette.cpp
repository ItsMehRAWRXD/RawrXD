// ============================================================================
// Win32IDE_CommandPalette.cpp — Command Palette Implementation
// ============================================================================

#include "Win32IDE_CommandPalette.hpp"
#include "../core/command_registry.hpp"
#include "Win32IDE.h"
#include <commctrl.h>
#include <algorithm>
#include <chrono>

#pragma comment(lib, "comctl32.lib")

namespace Win32IDE {

// ============================================================================
// SINGLETON INSTANCE
// ============================================================================

CommandPalette* CommandPalette::s_instance = nullptr;

CommandPalette* CommandPalette::GetInstance() {
    return s_instance;
}

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

CommandPalette::CommandPalette() = default;

CommandPalette::~CommandPalette() {
    Shutdown();
}

// ============================================================================
// INITIALIZATION
// ============================================================================

bool CommandPalette::Initialize(HINSTANCE hInstance, HWND hwndParent) {
    if (m_hwnd) return true;  // Already initialized
    
    m_hInstance = hInstance;
    m_hwndParent = hwndParent;
    
    // Register providers
    auto cmdProvider = std::make_unique<CommandProvider>();
    m_commandProvider = cmdProvider.get();
    cmdProvider->Initialize();
    RegisterProvider(std::move(cmdProvider));
    
    auto fileProvider = std::make_unique<FileProvider>();
    m_fileProvider = fileProvider.get();
    fileProvider->Initialize();
    RegisterProvider(std::move(fileProvider));
    
    // Set singleton
    s_instance = this;
    
    return true;
}

void CommandPalette::Shutdown() {
    Hide();
    
    if (m_font) { DeleteObject(m_font); m_font = nullptr; }
    if (m_fontBold) { DeleteObject(m_fontBold); m_fontBold = nullptr; }
    
    m_providers.clear();
    m_commandProvider = nullptr;
    m_fileProvider = nullptr;
    
    if (s_instance == this) s_instance = nullptr;
}

void CommandPalette::RegisterProvider(std::unique_ptr<ISearchProvider> provider) {
    m_providers.push_back(std::move(provider));
}

ISearchProvider* CommandPalette::GetProvider(const wchar_t* name) {
    for (auto& p : m_providers) {
        if (wcscmp(p->GetName(), name) == 0) {
            return p.get();
        }
    }
    return nullptr;
}

// ============================================================================
// WINDOW CREATION
// ============================================================================

bool CommandPalette::CreateWindowInternal() {
    if (m_hwnd) return true;
    
    // Register window class
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = m_hInstance;
    wc.lpszClassName = L"RawrXD_CommandPalette";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    
    RegisterClassExW(&wc);
    
    // Create popup window
    m_hwnd = CreateWindowExW(
        WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE | WS_EX_TOPMOST,
        L"RawrXD_CommandPalette",
        L"Command Palette",
        WS_POPUP | WS_BORDER,
        CW_USEDEFAULT, CW_USEDEFAULT,
        m_width, m_inputHeight + (m_maxVisibleItems * m_lineHeight) + (m_padding * 2),
        m_hwndParent,
        nullptr,
        m_hInstance,
        this
    );
    
    if (!m_hwnd) return false;
    
    // Create search edit control
    m_hwndEdit = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        L"EDIT",
        L"",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        m_padding, m_padding,
        m_width - (m_padding * 2), m_inputHeight - (m_padding * 2),
        m_hwnd,
        (HMENU)1,
        m_hInstance,
        nullptr
    );
    
    // Set font
    m_font = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                        DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    m_fontBold = CreateFontW(16, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                             DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                             DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    
    SendMessageW(m_hwndEdit, WM_SETFONT, (WPARAM)m_font, TRUE);
    
    return true;
}

// ============================================================================
// SHOW / HIDE
// ============================================================================

void CommandPalette::Show(ISearchProvider* provider) {
    if (!m_hwnd) {
        if (!CreateWindowInternal()) return;
    }
    
    if (provider) {
        m_activeProvider = provider;
    } else if (!m_activeProvider && !m_providers.empty()) {
        m_activeProvider = m_providers[0].get();
    }
    
    // Reset state
    m_query.clear();
    m_selectedIndex = 0;
    m_results.clear();
    
    SetWindowTextW(m_hwndEdit, L"");
    PositionWindow();
    
    ShowWindow(m_hwnd, SW_SHOW);
    SetFocus(m_hwndEdit);
    m_visible = true;
    
    // Initial results if provider supports empty query
    if (m_activeProvider && m_activeProvider->SupportsEmptyQuery()) {
        UpdateResults();
    }
}

void CommandPalette::Hide() {
    if (m_hwnd) {
        ShowWindow(m_hwnd, SW_HIDE);
    }
    m_visible = false;
}

bool CommandPalette::IsVisible() const {
    return m_visible;
}

void CommandPalette::ShowCommands() {
    Show(m_commandProvider);
}

void CommandPalette::ShowFiles() {
    Show(m_fileProvider);
}

void CommandPalette::ShowSymbols() {
    // Future: Symbol provider
    Show();
}

// ============================================================================
// POSITIONING
// ============================================================================

void CommandPalette::PositionWindow() {
    if (!m_hwndParent) return;
    
    RECT rcParent;
    GetWindowRect(m_hwndParent, &rcParent);
    
    int parentWidth = rcParent.right - rcParent.left;
    int parentHeight = rcParent.bottom - rcParent.top;
    
    int x = rcParent.left + (parentWidth - m_width) / 2;
    int y = rcParent.top + (parentHeight / 4);  // Position at 1/4 down
    
    int height = m_inputHeight + (m_maxVisibleItems * m_lineHeight) + (m_padding * 4);
    
    SetWindowPos(m_hwnd, nullptr, x, y, m_width, height,
                 SWP_NOZORDER | SWP_FRAMECHANGED);
}

// ============================================================================
// QUERY HANDLING
// ============================================================================

void CommandPalette::SetQuery(const std::wstring& query) {
    m_query = query;
    UpdateResults();
}

void CommandPalette::UpdateResults() {
    if (!m_activeProvider) return;
    
    m_results = m_activeProvider->Query(m_query, m_maxVisibleItems * 2);
    
    // Ensure selection is valid
    if (m_results.empty()) {
        m_selectedIndex = -1;
    } else if (m_selectedIndex >= (int)m_results.size()) {
        m_selectedIndex = (int)m_results.size() - 1;
    } else if (m_selectedIndex < 0) {
        m_selectedIndex = 0;
    }
    
    // Update selection state
    for (size_t i = 0; i < m_results.size(); ++i) {
        m_results[i].isHighlighted = (i == (size_t)m_selectedIndex);
    }
    
    InvalidateRect(m_hwnd, nullptr, FALSE);
}

std::wstring CommandPalette::GetInputText() {
    if (!m_hwndEdit) return L"";
    
    int len = GetWindowTextLengthW(m_hwndEdit);
    std::wstring text;
    text.resize(len + 1);
    GetWindowTextW(m_hwndEdit, text.data(), len + 1);
    text.resize(len);
    return text;
}

// ============================================================================
// NAVIGATION
// ============================================================================

void CommandPalette::MoveSelection(int delta) {
    if (m_results.empty()) return;
    
    int newIndex = m_selectedIndex + delta;
    if (newIndex < 0) newIndex = 0;
    if (newIndex >= (int)m_results.size()) newIndex = (int)m_results.size() - 1;
    
    if (newIndex != m_selectedIndex) {
        m_selectedIndex = newIndex;
        UpdateSelection();
    }
}

void CommandPalette::UpdateSelection() {
    for (size_t i = 0; i < m_results.size(); ++i) {
        m_results[i].isHighlighted = (i == (size_t)m_selectedIndex);
    }
    InvalidateRect(m_hwnd, nullptr, FALSE);
}

void CommandPalette::AcceptSelection() {
    if (m_selectedIndex >= 0 && m_selectedIndex < (int)m_results.size()) {
        auto& result = m_results[m_selectedIndex];
        if (result.onAccept) {
            result.onAccept();
        }
    }
    Hide();
}

void CommandPalette::Cancel() {
    Hide();
    if (m_hwndParent) {
        SetFocus(m_hwndParent);
    }
}

// ============================================================================
// WINDOW PROCEDURE
// ============================================================================

LRESULT CALLBACK CommandPalette::WindowProc(HWND hwnd, UINT msg, 
                                           WPARAM wParam, LPARAM lParam) {
    CommandPalette* self = nullptr;
    
    if (msg == WM_CREATE) {
        auto* cs = reinterpret_cast<CREATESTRUCT*>(lParam);
        self = static_cast<CommandPalette*>(cs->lpCreateParams);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
    } else {
        self = reinterpret_cast<CommandPalette*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    }
    
    if (self) {
        return self->HandleMessage(msg, wParam, lParam);
    }
    
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

LRESULT CommandPalette::HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_PAINT:
            OnPaint();
            return 0;
            
        case WM_SIZE:
            OnSize(LOWORD(lParam), HIWORD(lParam));
            return 0;
            
        case WM_KEYDOWN:
            OnKeyDown((UINT)wParam);
            return 0;
            
        case WM_CHAR:
            OnChar((wchar_t)wParam);
            return 0;
            
        case WM_MOUSEWHEEL:
            OnMouseWheel(GET_WHEEL_DELTA_WPARAM(wParam));
            return 0;
            
        case WM_LBUTTONDOWN:
            OnLButtonDown(GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam));
            return 0;
            
        case WM_ACTIVATE:
            if (LOWORD(wParam) == WA_INACTIVE) {
                Hide();
            }
            return 0;
            
        case WM_DESTROY:
            m_hwnd = nullptr;
            return 0;
    }
    
    return DefWindowProc(m_hwnd, msg, wParam, lParam);
}

// ============================================================================
// MESSAGE HANDLERS
// ============================================================================

void CommandPalette::OnPaint() {
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(m_hwnd, &ps);
    Render(hdc);
    EndPaint(m_hwnd, &ps);
}

void CommandPalette::OnSize(int width, int height) {
    if (m_hwndEdit) {
        SetWindowPos(m_hwndEdit, nullptr, 
                     m_padding, m_padding,
                     width - (m_padding * 2), m_inputHeight - (m_padding * 2),
                     SWP_NOZORDER);
    }
}

void CommandPalette::OnKeyDown(UINT vk) {
    switch (vk) {
        case VK_ESCAPE:
            Cancel();
            break;
        case VK_RETURN:
            AcceptSelection();
            break;
        case VK_UP:
            MoveSelection(-1);
            break;
        case VK_DOWN:
            MoveSelection(1);
            break;
        case VK_PRIOR:  // Page Up
            MoveSelection(-m_maxVisibleItems);
            break;
        case VK_NEXT:   // Page Down
            MoveSelection(m_maxVisibleItems);
            break;
        case VK_HOME:
            m_selectedIndex = 0;
            UpdateSelection();
            break;
        case VK_END:
            m_selectedIndex = (int)m_results.size() - 1;
            UpdateSelection();
            break;
    }
}

void CommandPalette::OnChar(wchar_t ch) {
    // Edit control handles text input
    // Update results when text changes
    auto newQuery = GetInputText();
    if (newQuery != m_query) {
        SetQuery(newQuery);
    }
}

void CommandPalette::OnMouseWheel(int delta) {
    int lines = delta / WHEEL_DELTA;
    MoveSelection(-lines);
}

void CommandPalette::OnLButtonDown(int x, int y) {
    // Calculate which item was clicked
    int itemY = y - m_inputHeight - m_padding;
    if (itemY >= 0) {
        int index = itemY / m_lineHeight;
        if (index >= 0 && index < (int)m_results.size()) {
            m_selectedIndex = index;
            UpdateSelection();
            AcceptSelection();
        }
    }
}

// ============================================================================
// RENDERING
// ============================================================================

void CommandPalette::Render(HDC hdc) {
    RECT rc;
    GetClientRect(m_hwnd, &rc);
    
    // Fill background
    HBRUSH hbrBg = CreateSolidBrush(RGB(30, 30, 30));  // Dark background
    FillRect(hdc, &rc, hbrBg);
    DeleteObject(hbrBg);
    
    // Draw results area background
    RECT rcResults = { m_padding, m_inputHeight, rc.right - m_padding, rc.bottom - m_padding };
    HBRUSH hbrResults = CreateSolidBrush(RGB(37, 37, 38));  // VS Code dark
    FillRect(hdc, &rcResults, hbrResults);
    DeleteObject(hbrResults);
    
    // Draw results
    int y = m_inputHeight + m_padding;
    for (size_t i = 0; i < m_results.size() && i < (size_t)m_maxVisibleItems; ++i) {
        auto& result = m_results[i];
        
        RECT rcItem = { m_padding, y, rc.right - m_padding, y + m_lineHeight };
        
        // Selection highlight
        if (result.isHighlighted) {
            HBRUSH hbrSel = CreateSolidBrush(RGB(0, 97, 212));  // Blue selection
            FillRect(hdc, &rcItem, hbrSel);
            DeleteObject(hbrSel);
        }
        
        // Draw text
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, result.isHighlighted ? RGB(255, 255, 255) : RGB(204, 204, 204));
        
        // Display name
        rcItem.left += 8;
        DrawTextW(hdc, result.display.c_str(), -1, &rcItem, 
                  DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        
        // Category (right-aligned)
        if (!result.category.empty()) {
            SetTextColor(hdc, RGB(128, 128, 128));
            RECT rcCat = rcItem;
            rcCat.right -= 8;
            DrawTextW(hdc, result.category.c_str(), -1, &rcCat,
                      DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
        }
        
        y += m_lineHeight;
    }
}

// ============================================================================
// FUZZY MATCHER IMPLEMENTATION
// ============================================================================

int FuzzyMatcher::Score(const std::wstring& pattern,
                        const std::wstring& target,
                        std::vector<int>* matchPositions) {
    if (pattern.empty()) return 0;
    if (target.empty()) return -1;
    
    // Convert both to lowercase for matching
    std::wstring patLower, tgtLower;
    patLower.reserve(pattern.size());
    tgtLower.reserve(target.size());
    
    for (wchar_t c : pattern) patLower.push_back(towlower(c));
    for (wchar_t c : target) tgtLower.push_back(towlower(c));
    
    // Check if pattern could match at all
    size_t patIdx = 0;
    int score = 0;
    int consecutiveBonus = 0;
    bool atStartOfWord = true;
    
    for (size_t i = 0; i < tgtLower.size() && patIdx < patLower.size(); ++i) {
        if (tgtLower[i] == patLower[patIdx]) {
            if (matchPositions) matchPositions->push_back((int)i);
            
            // Base match score
            score += SCORE_MATCH;
            
            // Start of word bonus
            if (atStartOfWord || IsWordBoundary(i > 0 ? tgtLower[i-1] : 0, tgtLower[i])) {
                score += SCORE_START_OF_WORD;
            }
            
            // Consecutive match bonus
            if (i > 0 && patIdx > 0 && 
                matchPositions && !matchPositions->empty() &&
                (*matchPositions)[matchPositions->size()-1] == (int)i - 1) {
                consecutiveBonus += SCORE_CONSECUTIVE;
            }
            
            // Exact case match bonus
            if (pattern[patIdx] == target[i]) {
                score += 2;
            }
            
            ++patIdx;
            atStartOfWord = false;
        } else {
            // Gap penalty
            score += SCORE_GAP;
            atStartOfWord = IsWordBoundary(i > 0 ? tgtLower[i-1] : 0, tgtLower[i]);
        }
    }
    
    score += consecutiveBonus;
    
    // Did we match all characters?
    if (patIdx < patLower.size()) return -1;
    
    // Exact match bonus
    if (patLower == tgtLower) {
        score += SCORE_EXACT;
    } else if (tgtLower.find(patLower) == 0) {
        score += SCORE_PREFIX;
    }
    
    return score;
}

bool FuzzyMatcher::CouldMatch(const std::wstring& pattern,
                              const std::wstring& target) {
    if (pattern.empty()) return true;
    
    std::wstring patLower, tgtLower;
    for (wchar_t c : pattern) patLower.push_back(towlower(c));
    for (wchar_t c : target) tgtLower.push_back(towlower(c));
    
    size_t patIdx = 0;
    for (wchar_t c : tgtLower) {
        if (patIdx < patLower.size() && c == patLower[patIdx]) {
            ++patIdx;
        }
    }
    
    return patIdx == patLower.size();
}

bool FuzzyMatcher::IsWordBoundary(wchar_t prev, wchar_t curr) {
    // Word boundaries: start of string, after separator, camelCase
    if (prev == 0) return true;
    if (prev == L' ' || prev == L'\t' || prev == L'-' || prev == L'_' || 
        prev == L'.' || prev == L':' || prev == L'/') return true;
    if (islower(prev) && isupper(curr)) return true;  // camelCase
    return false;
}

// ============================================================================
// COMMAND PROVIDER IMPLEMENTATION
// ============================================================================

CommandProvider::CommandProvider() = default;

void CommandProvider::Initialize() {
    BuildIndex();
    m_initialized = true;
}

void CommandProvider::BuildIndex() {
    m_commands.clear();
    
    // Iterate COMMAND_TABLE using the X-macro
    #define EXTRACT_COMMAND(id, symbol, canonical, cli, exposure, category, handler, flags) \
        do { \
            if (static_cast<uint8_t>(exposure) & 0x01) { /* GUI_ONLY or BOTH */ \
                CommandEntry entry; \
                entry.id = id; \
                entry.canonical = CanonicalToDisplay(canonical); \
                entry.category = category; \
                \
                /* Parse canonical name into display name */ \
                size_t dotPos = entry.canonical.find(L'.'); \
                if (dotPos != std::wstring::npos) { \
                    std::wstring action = entry.canonical.substr(dotPos + 1); \
                    /* Convert camelCase to Title Case */ \
                    entry.name = action; \
                    if (!entry.name.empty()) { \
                        entry.name[0] = towupper(entry.name[0]); \
                    } \
                } else { \
                    entry.name = entry.canonical; \
                } \
                \
                /* Capitalize category */ \
                if (!entry.category.empty()) { \
                    entry.category[0] = towupper(entry.category[0]); \
                } \
                \
                /* Set icon based on category */ \
                if (entry.category == L"File") entry.icon = ResultIcon::File; \
                else if (entry.category == L"Edit") entry.icon = ResultIcon::Command; \
                else if (entry.category == L"View") entry.icon = ResultIcon::Command; \
                else if (entry.category == L"Theme") entry.icon = ResultIcon::Theme; \
                else if (entry.category == L"Git") entry.icon = ResultIcon::Git; \
                else if (entry.category == L"Terminal") entry.icon = ResultIcon::Terminal; \
                else if (entry.category == L"Agent") entry.icon = ResultIcon::Agent; \
                else entry.icon = ResultIcon::Command; \
                \
                m_commands.push_back(std::move(entry)); \
            } \
        } while(0)
    
    COMMAND_TABLE(EXTRACT_COMMAND)
    #undef EXTRACT_COMMAND
}

std::wstring CommandProvider::CanonicalToDisplay(const std::string& canonical) {
    std::wstring result;
    result.reserve(canonical.size());
    for (char c : canonical) {
        result.push_back(static_cast<wchar_t>(c));
    }
    return result;
}

std::vector<SearchResult> CommandProvider::Query(const std::wstring& input, 
                                                  size_t maxResults) {
    std::vector<SearchResult> results;
    
    if (input.empty()) {
        // Show recent/popular commands
        for (const auto& cmd : m_commands) {
            SearchResult result;
            result.display = cmd.name;
            result.detail = cmd.canonical;
            result.category = cmd.category;
            result.icon = cmd.icon;
            result.commandId = cmd.id;
            result.providerId = GetName();
            result.score = 0;
            result.onAccept = [cmd]() {
                // Post WM_COMMAND to execute
                HWND hwndMain = GetActiveWindow();
                if (hwndMain) {
                    PostMessageW(hwndMain, WM_COMMAND, MAKEWPARAM(cmd.id, 0), 0);
                }
            };
            results.push_back(std::move(result));
            if (results.size() >= maxResults) break;
        }
    } else {
        // Fuzzy search
        for (const auto& cmd : m_commands) {
            int score = CalculateScore(input, cmd);
            if (score > 0) {
                SearchResult result;
                result.display = cmd.name;
                result.detail = cmd.canonical;
                result.category = cmd.category;
                result.icon = cmd.icon;
                result.commandId = cmd.id;
                result.providerId = GetName();
                result.score = score;
                result.onAccept = [cmd]() {
                    HWND hwndMain = GetActiveWindow();
                    if (hwndMain) {
                        PostMessageW(hwndMain, WM_COMMAND, MAKEWPARAM(cmd.id, 0), 0);
                    }
                };
                results.push_back(std::move(result));
            }
        }
        
        // Sort by score descending
        std::sort(results.begin(), results.end(),
                  [](const SearchResult& a, const SearchResult& b) {
                      return a.score > b.score;
                  });
        
        if (results.size() > maxResults) {
            results.resize(maxResults);
        }
    }
    
    return results;
}

int CommandProvider::CalculateScore(const std::wstring& query, const CommandEntry& cmd) {
    // Try matching against name first
    int nameScore = FuzzyMatcher::Score(query, cmd.name);
    if (nameScore > 0) return nameScore + 10;  // Bonus for name match
    
    // Try canonical name
    int canonScore = FuzzyMatcher::Score(query, cmd.canonical);
    if (canonScore > 0) return canonScore;
    
    // Try category
    int catScore = FuzzyMatcher::Score(query, cmd.category);
    if (catScore > 0) return catScore - 5;  // Slight penalty for category-only match
    
    return -1;
}

// ============================================================================
// FILE PROVIDER IMPLEMENTATION
// ============================================================================

FileProvider::FileProvider() = default;

void FileProvider::Initialize() {
    // Will build index when workspace is set
    m_initialized = true;
}

void FileProvider::SetWorkspaceRoot(const std::wstring& path) {
    m_workspaceRoot = path;
    Refresh();
}

void FileProvider::Refresh() {
    BuildIndex();
}

void FileProvider::BuildIndex() {
    m_files.clear();
    
    if (m_workspaceRoot.empty()) return;
    
    // Simple recursive directory walk
    // In production, this should use a file watcher and async indexing
    std::function<void(const std::wstring&)> walkDir = [&](const std::wstring& dir) {
        WIN32_FIND_DATAW findData;
        std::wstring searchPath = dir + L"\\*";
        
        HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);
        if (hFind == INVALID_HANDLE_VALUE) return;
        
        do {
            std::wstring name = findData.cFileName;
            if (name == L"." || name == L"..") continue;
            
            std::wstring fullPath = dir + L"\\" + name;
            bool isDir = (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            
            // Skip hidden/system directories
            if (isDir && (findData.dwFileAttributes & 
                (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM))) {
                continue;
            }
            
            FileEntry entry;
            entry.path = fullPath;
            entry.name = name;
            
            size_t dotPos = name.find_last_of(L'.');
            if (dotPos != std::wstring::npos) {
                entry.ext = name.substr(dotPos + 1);
            }
            
            entry.isDirectory = isDir;
            m_files.push_back(std::move(entry));
            
            // Recurse into directories (with depth limit)
            if (isDir && m_files.size() < 10000) {
                walkDir(fullPath);
            }
        } while (FindNextFileW(hFind, &findData));
        
        FindClose(hFind);
    };
    
    walkDir(m_workspaceRoot);
}

std::vector<SearchResult> FileProvider::Query(const std::wstring& input, 
                                             size_t maxResults) {
    std::vector<SearchResult> results;
    
    if (input.empty() || m_files.empty()) return results;
    
    for (const auto& file : m_files) {
        int score = CalculateScore(input, file);
        if (score > 0) {
            SearchResult result;
            result.display = file.name;
            result.detail = file.path;
            result.category = file.isDirectory ? L"Folder" : L"File";
            result.icon = file.isDirectory ? ResultIcon::Folder : ResultIcon::File;
            result.resourcePath = file.path;
            result.providerId = GetName();
            result.score = score;
            result.onAccept = [file]() {
                // Open file in editor
                HWND hwndMain = GetActiveWindow();
                if (hwndMain) {
                    // Post message to open file
                    // TODO: Implement file open message
                }
            };
            results.push_back(std::move(result));
        }
    }
    
    // Sort by score
    std::sort(results.begin(), results.end(),
              [](const SearchResult& a, const SearchResult& b) {
                  return a.score > b.score;
              });
    
    if (results.size() > maxResults) {
        results.resize(maxResults);
    }
    
    return results;
}

int FileProvider::CalculateScore(const std::wstring& query, const FileEntry& file) {
    // Prioritize filename matches
    int nameScore = FuzzyMatcher::Score(query, file.name);
    if (nameScore > 0) {
        // Bonus for exact filename match
        return nameScore + (file.isDirectory ? 5 : 10);
    }
    
    // Try full path
    int pathScore = FuzzyMatcher::Score(query, file.path);
    if (pathScore > 0) return pathScore - 5;
    
    return -1;
}

// ============================================================================
// GLOBAL FUNCTIONS
// ============================================================================

static std::unique_ptr<CommandPalette> g_palette;

bool InitializeCommandPalette(HINSTANCE hInstance, HWND hwndMain) {
    g_palette = std::make_unique<CommandPalette>();
    return g_palette->Initialize(hInstance, hwndMain);
}

void ShutdownCommandPalette() {
    g_palette.reset();
}

void ShowCommandPalette() {
    if (g_palette) {
        g_palette->ShowCommands();
    }
}

void ShowQuickOpen() {
    if (g_palette) {
        g_palette->ShowFiles();
    }
}

bool CommandPaletteHandleKey(UINT vk, bool ctrl, bool shift) {
    if (!g_palette) return false;
    
    // Ctrl+Shift+P = Command Palette
    if (ctrl && shift && vk == 'P') {
        ShowCommandPalette();
        return true;
    }
    
    // Ctrl+P = Quick Open
    if (ctrl && !shift && vk == 'P') {
        ShowQuickOpen();
        return true;
    }
    
    // If palette is visible, let it handle navigation keys
    if (g_palette->IsVisible()) {
        switch (vk) {
            case VK_ESCAPE:
            case VK_RETURN:
            case VK_UP:
            case VK_DOWN:
            case VK_PRIOR:
            case VK_NEXT:
            case VK_HOME:
            case VK_END:
                // These are handled by the palette
                return true;
        }
    }
    
    return false;
}

bool RegisterCommandPaletteHotkeys(HWND hwnd) {
    // Register global hotkeys
    // Note: In a real implementation, you might want to use RegisterHotKey
    // For now, we handle it in the message loop via CommandPaletteHandleKey
    return true;
}

} // namespace Win32IDE
