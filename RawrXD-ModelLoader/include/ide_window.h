#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <commctrl.h>
#include <exdisp.h>
// #include <mshtml.h> // Disabled (not required; missing in current SDK environment)

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "uuid.lib")

class IDEWindow {
public:
    IDEWindow();
    ~IDEWindow();

    bool Initialize(HINSTANCE hInstance);
    void Run();
    void Shutdown();
    
    // Extension marketplace structure (must be declared before use in methods)
    struct ExtensionInfo {
        std::wstring id;
        std::wstring name;
        std::wstring publisher;
        std::wstring version;
        std::wstring description;
        std::wstring downloadUrl;
        std::wstring iconUrl;
        int downloads;
        float rating;
        bool installed;
        std::wstring installPath;
    };

private:
    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK EditorProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    
    void CreateMainWindow(HINSTANCE hInstance);
    void CreateMenuBar();
    void CreateToolBar();
    void CreateStatusBar();
    void CreateEditorControl();
    void CreateFileExplorer();
    void CreateTerminalPanel();
    void CreateOutputPanel();
    void CreateWebBrowser();
    void CreateTabControl();
    void PopulateFileTree(const std::wstring& rootPath);
    
    void OnNewFile();
    void OnOpenFile();
    void OnOpenFolder();
    void OnSaveFile();
    void OnRunScript();
    void OnTabChanged();
    void OnFileTreeSelection();
    void OnWebNavigate(const std::wstring& url);
    void OnCloseTab(int tabIndex);
    void OnSwitchTab(int tabIndex);
    void CreateNewTab(const std::wstring& title, const std::wstring& filePath);
    void SaveCurrentTab();
    void LoadTabContent(int tabId);
    int GetCurrentTabId();
    void OnFind();
    void OnReplace();
    void FindNext(const std::wstring& searchText, bool caseSensitive, bool regex);
    void ReplaceNext(const std::wstring& findText, const std::wstring& replaceText, bool caseSensitive, bool regex);
    void ReplaceAll(const std::wstring& findText, const std::wstring& replaceText, bool caseSensitive, bool regex);
    void HighlightSearchResults(const std::wstring& searchText, bool caseSensitive);
    void UpdateStatusBar();
    void LoadFileIntoEditor(const std::wstring& filePath);
    void ExecutePowerShellCommand(const std::wstring& command);
    void SaveSession();
    void LoadSession();
    void UpdateTabTitle(int tabId, const std::wstring& newTitle);
    void ToggleCommandPalette();
    void ExecutePaletteSelection();
    void PopulateCommandPalette();
    void FormatTrimTrailingWhitespace();
    void ListFunctions();
    void ToggleLineComment();
    void DuplicateLine();
    void DeleteLine();
    void SortSelectedLines();
    std::wstring DetectLanguage();
    
    // Marketplace functionality
    void CreateMarketplaceWindow();
    void ShowMarketplace();
    void HideMarketplace();
    void SearchMarketplace(const std::wstring& query);
    void PopulateMarketplaceList(const std::vector<ExtensionInfo>& extensions);
    void ShowExtensionDetails(const ExtensionInfo& ext);
    void InstallExtension(const ExtensionInfo& ext);
    void UninstallExtension(const ExtensionInfo& ext);
    void LoadInstalledExtensions();
    std::vector<ExtensionInfo> QueryVSCodeMarketplace(const std::wstring& query);
    std::vector<ExtensionInfo> QueryVSMarketplace(const std::wstring& query);
    bool DownloadFile(const std::wstring& url, const std::wstring& destPath);
    bool ExtractVSIX(const std::wstring& vsixPath, const std::wstring& destPath);
    
    void ApplySyntaxHighlighting();
    void HighlightPowerShellSyntax(HDC hdc, const std::wstring& text, RECT& rect);
    
    // Code Intelligence & IntelliSense
    void ShowAutocompleteList(const std::wstring& partialText);
    void HideAutocompleteList();
    void UpdateAutocompletePosition();
    void SelectAutocompleteItem(int index);
    void InsertAutocompleteSelection();
    void PopulatePowerShellCmdlets();
    void ShowParameterHint(const std::wstring& cmdlet);
    void HideParameterHint();
    std::wstring GetCurrentWord();
    std::wstring GetCurrentLine();
    void ParsePowerShellVariables();
    
    HWND hwnd_;
    HWND hEditor_;
    HWND hFileTree_;
    HWND hTerminal_;
    HWND hOutput_;
    HWND hStatusBar_;
    HWND hToolBar_;
    HWND hTabControl_;
    HWND hWebBrowser_;
    HWND hAutocompleteList_;
    HWND hParameterHint_;
    HWND hFindDialog_;
    HWND hReplaceDialog_;
    HWND hCommandPalette_;
    HWND hMarketplaceWindow_;
    HWND hMarketplaceSearch_;
    HWND hMarketplaceList_;
    HWND hMarketplaceDetails_;
    HWND hMarketplaceInstallBtn_;
    
    // Web browser interface
    IWebBrowser2* pWebBrowser_;
    
    // Tab management
    struct TabInfo {
        std::wstring filePath;
        std::wstring content;
        bool modified;
    };
    std::map<int, TabInfo> openTabs_;
    int nextTabId_;
    int activeTabId_;
    std::wstring sessionPath_;
    
    std::vector<ExtensionInfo> marketplaceExtensions_;
    std::vector<ExtensionInfo> installedExtensions_;
    std::wstring extensionsPath_;
    
    HINSTANCE hInstance_;
    WNDPROC originalEditorProc_;
    
    std::wstring currentFilePath_;
    std::wstring currentFolderPath_;
    bool isModified_;
    
    // Code Intelligence
    std::vector<std::wstring> cmdletList_;
    std::vector<std::wstring> variableList_;
    std::vector<std::wstring> keywordList_;
    int selectedAutocompleteIndex_;
    bool autocompleteVisible_;
    
    // Search & Replace
    std::wstring lastSearchText_;
    int lastSearchPos_;
    bool lastSearchCaseSensitive_;
    bool lastSearchRegex_;
    
    // PowerShell syntax highlighting colors
    COLORREF keywordColor_;
    COLORREF cmdletColor_;
    COLORREF stringColor_;
    COLORREF commentColor_;
    COLORREF variableColor_;
    COLORREF backgroundColor_;
    COLORREF textColor_;
};
