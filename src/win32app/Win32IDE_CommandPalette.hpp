// ============================================================================
// Win32IDE_CommandPalette.hpp — Command Palette & Quick Open Search Overlay
// ============================================================================
// Architecture: C++20, Win32, no Qt, no exceptions
//
// Provides a unified search overlay for:
//   - Command Palette (Ctrl+Shift+P) — searches COMMAND_TABLE
//   - Quick Open (Ctrl+P) — searches workspace files
//   - Symbol Search (Ctrl+T) — searches LSP workspace symbols
//
// Design: Provider-based architecture where each data source implements
//         a common interface. The overlay renders generic SearchResult items.
//
// Phase 20: Command Palette & Quick Open
// Copyright (c) 2024-2026 RawrXD IDE Project
// ============================================================================

#pragma once

#ifndef RAWRXD_WIN32IDE_COMMAND_PALETTE_HPP
#define RAWRXD_WIN32IDE_COMMAND_PALETTE_HPP

#include <windows.h>
#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <cstdint>

// Forward declarations
namespace Win32IDE {
    struct SearchResult;
    class ISearchProvider;
    class CommandPalette;
}

namespace RawrXD {
    struct ThemeColors;  // From theme system
}

// ============================================================================
// SEARCH RESULT — Universal result type for all providers
// ============================================================================

namespace Win32IDE {

enum class ResultIcon : int {
    None = -1,
    File = 0,
    Folder = 1,
    Command = 2,
    Symbol = 3,
    Agent = 4,
    Recent = 5,
    Setting = 6,
    Theme = 7,
    Git = 8,
    Debug = 9,
    Terminal = 10,
};

enum class MatchType : uint8_t {
    None = 0,
    Exact = 1,
    Prefix = 2,
    Substring = 3,
    Fuzzy = 4,
};

struct SearchResult {
    // Display
    std::wstring display;           // Primary text (e.g., "File: New")
    std::wstring detail;            // Secondary text (e.g., "Create a new file")
    std::wstring category;          // Group/category (e.g., "File", "Edit")
    
    // Scoring & sorting
    int score = 0;                  // Higher = better match
    MatchType match = MatchType::None;
    std::wstring sortKey;           // For stable sorting
    
    // Visual
    ResultIcon icon = ResultIcon::None;
    bool isHighlighted = false;     // Current selection
    
    // Action
    std::function<void()> onAccept;   // Called on Enter
    std::function<void()> onPreview;    // Called on selection change (optional)
    
    // Source & identity
    uint32_t commandId = 0;         // For commands: the WM_COMMAND ID
    std::wstring providerId;        // Which provider emitted this
    std::wstring resourcePath;      // For files: full path
    
    // Comparison for deduplication
    bool operator==(const SearchResult& other) const {
        return commandId == other.commandId && 
               resourcePath == other.resourcePath &&
               display == other.display;
    }
};

// ============================================================================
// SEARCH PROVIDER INTERFACE
// ============================================================================

class ISearchProvider {
public:
    virtual ~ISearchProvider() = default;
    
    // Provider identity
    virtual const wchar_t* GetName() const = 0;
    virtual const wchar_t* GetShortcut() const = 0;  // e.g., L"Ctrl+Shift+P"
    
    // Query handling
    virtual std::vector<SearchResult> Query(const std::wstring& input, 
                                             size_t maxResults = 50) = 0;
    
    // Lifecycle
    virtual void Initialize() {}
    virtual void Refresh() {}  // Rebuild index if needed
    virtual void Shutdown() {}
    
    // Capabilities
    virtual bool SupportsRealtime() const { return false; }  // Can update while open
    virtual bool SupportsEmptyQuery() const { return true; }   // Show results for ""
};

// ============================================================================
// COMMAND PROVIDER — Searches COMMAND_TABLE
// ============================================================================

class CommandProvider : public ISearchProvider {
public:
    CommandProvider();
    ~CommandProvider() override = default;
    
    const wchar_t* GetName() const override { return L"Commands"; }
    const wchar_t* GetShortcut() const override { return L"Ctrl+Shift+P"; }
    
    void Initialize() override;
    std::vector<SearchResult> Query(const std::wstring& input, 
                                   size_t maxResults = 50) override;
    bool SupportsEmptyQuery() const override { return true; }
    
private:
    struct CommandEntry {
        uint32_t id;
        std::wstring name;          // Display name
        std::wstring canonical;     // e.g., "file.new"
        std::wstring category;
        std::wstring description;
        ResultIcon icon;
    };
    
    std::vector<CommandEntry> m_commands;
    bool m_initialized = false;
    
    void BuildIndex();
    int CalculateScore(const std::wstring& query, const CommandEntry& cmd);
    std::wstring CanonicalToDisplay(const std::string& canonical);
};

// ============================================================================
// FILE PROVIDER — Searches workspace files (for Quick Open)
// ============================================================================

class FileProvider : public ISearchProvider {
public:
    FileProvider();
    ~FileProvider() override = default;
    
    const wchar_t* GetName() const override { return L"Files"; }
    const wchar_t* GetShortcut() const override { return L"Ctrl+P"; }
    
    void Initialize() override;
    void Refresh() override;  // Rebuild file index
    std::vector<SearchResult> Query(const std::wstring& input, 
                                   size_t maxResults = 50) override;
    bool SupportsEmptyQuery() const override { return false; }  // Need at least 1 char
    
    void SetWorkspaceRoot(const std::wstring& path);
    
private:
    struct FileEntry {
        std::wstring path;
        std::wstring name;
        std::wstring ext;
        bool isDirectory;
    };
    
    std::wstring m_workspaceRoot;
    std::vector<FileEntry> m_files;
    bool m_initialized = false;
    
    void BuildIndex();
    int CalculateScore(const std::wstring& query, const FileEntry& file);
};

// ============================================================================
// FUZZY MATCHER — Scoring algorithm
// ============================================================================

class FuzzyMatcher {
public:
    // Score a match between pattern and target
    // Returns: score >= 0, higher = better match
    //          matchPositions filled with indices of matched chars
    static int Score(const std::wstring& pattern,
                     const std::wstring& target,
                     std::vector<int>* matchPositions = nullptr);
    
    // Quick check if pattern could match target at all
    static bool CouldMatch(const std::wstring& pattern,
                           const std::wstring& target);
    
private:
    static constexpr int SCORE_EXACT = 100;
    static constexpr int SCORE_START_OF_WORD = 50;
    static constexpr int SCORE_CONSECUTIVE = 20;
    static constexpr int SCORE_MATCH = 10;
    static constexpr int SCORE_GAP = -3;
    
    static bool IsWordBoundary(wchar_t prev, wchar_t curr);
};

// ============================================================================
// COMMAND PALETTE — Main overlay window
// ============================================================================

class CommandPalette {
public:
    CommandPalette();
    ~CommandPalette();
    
    // Initialization
    bool Initialize(HINSTANCE hInstance, HWND hwndParent);
    void Shutdown();
    
    // Show/hide
    void Show(ISearchProvider* provider = nullptr);  // nullptr = use last provider
    void Hide();
    bool IsVisible() const;
    
    // Mode switching
    void ShowCommands();   // Ctrl+Shift+P
    void ShowFiles();      // Ctrl+P
    void ShowSymbols();    // Ctrl+T (future)
    
    // Input handling
    void SetQuery(const std::wstring& query);
    void MoveSelection(int delta);  // -1 = up, +1 = down
    void AcceptSelection();         // Execute selected item
    void Cancel();                  // Close without action
    
    // Window procedure
    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, 
                                       WPARAM wParam, LPARAM lParam);
    LRESULT HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam);
    
    // Provider management
    void RegisterProvider(std::unique_ptr<ISearchProvider> provider);
    ISearchProvider* GetProvider(const wchar_t* name);
    
    // Access to singleton for global hotkey handling
    static CommandPalette* GetInstance();
    
private:
    // Window handles
    HWND m_hwnd = nullptr;
    HWND m_hwndParent = nullptr;
    HWND m_hwndEdit = nullptr;      // Search input
    HWND m_hwndList = nullptr;      // Results list
    HINSTANCE m_hInstance = nullptr;
    
    // State
    bool m_visible = false;
    std::wstring m_query;
    int m_selectedIndex = -1;
    std::vector<SearchResult> m_results;
    
    // Providers
    std::vector<std::unique_ptr<ISearchProvider>> m_providers;
    ISearchProvider* m_activeProvider = nullptr;
    CommandProvider* m_commandProvider = nullptr;
    FileProvider* m_fileProvider = nullptr;
    
    // Theme
    RawrXD::ThemeColors* m_theme = nullptr;
    HFONT m_font = nullptr;
    HFONT m_fontBold = nullptr;
    int m_lineHeight = 24;
    int m_maxVisibleItems = 10;
    
    // Layout
    int m_width = 600;
    int m_inputHeight = 40;
    int m_padding = 8;
    
    // Singleton instance (for static WindowProc)
    static CommandPalette* s_instance;
    
    // Internal methods
    bool CreateWindowInternal();
    void UpdateResults();
    void Render(HDC hdc);
    void PositionWindow();
    void UpdateSelection();
    std::wstring GetInputText();
    
    // Message handlers
    void OnPaint();
    void OnSize(int width, int height);
    void OnKeyDown(UINT vk);
    void OnChar(wchar_t ch);
    void OnMouseWheel(int delta);
    void OnLButtonDown(int x, int y);
};

// ============================================================================
// GLOBAL FUNCTIONS — Integration with main Win32IDE
// ============================================================================

// Initialize the command palette system
bool InitializeCommandPalette(HINSTANCE hInstance, HWND hwndMain);

// Shutdown and cleanup
void ShutdownCommandPalette();

// Show command palette (called from WM_KEYDOWN handler)
void ShowCommandPalette();
void ShowQuickOpen();

// Check if palette should handle this key (call before normal dispatch)
// Returns true if key was consumed
bool CommandPaletteHandleKey(UINT vk, bool ctrl, bool shift);

// Global hotkey registration
bool RegisterCommandPaletteHotkeys(HWND hwnd);

} // namespace Win32IDE

#endif // RAWRXD_WIN32IDE_COMMAND_PALETTE_HPP
