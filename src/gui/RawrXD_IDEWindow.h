#pragma once
#include <windows.h>
#include <string>
#include <memory>
#include "RawrXD_ChatWindow.h"
#include "RawrXD_FileBrowser.h"
#include "../backend/ollama_client.h"

namespace RawrXD {
namespace GUI {

// Main IDE window with integrated panels
class IDEWindow {
public:
    IDEWindow();
    ~IDEWindow();

    // Create and show the IDE
    bool Create(HINSTANCE hInstance, int nCmdShow);
    
    // Run the message loop
    int Run();
    
    // Getters for panels
    ChatWindow* GetChatWindow() { return m_chatWindow.get(); }
    FileBrowser* GetFileBrowser() { return m_fileBrowser.get(); }
    
    // Set Ollama client
    void SetOllamaClient(std::shared_ptr<RawrXD::Backend::OllamaClient> client);

private:
    // Window procedure
    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    LRESULT HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam);
    
    // Message handlers
    void OnCreate();
    void OnSize(int width, int height);
    void OnCommand(WPARAM wParam, LPARAM lParam);
    void OnDestroy();
    void OnFileSelected(const std::string& path);
    
    // Layout
    void LayoutPanels(int width, int height);
    void CreateMenuBar();
    
    // Window handles
    HWND m_hwnd = nullptr;
    HWND m_hwndStatusBar = nullptr;
    HWND m_hwndEditor = nullptr;  // Simple editor for now
    
    // Panels
    std::unique_ptr<ChatWindow> m_chatWindow;
    std::unique_ptr<FileBrowser> m_fileBrowser;
    
    // Ollama client
    std::shared_ptr<RawrXD::Backend::OllamaClient> m_ollamaClient;
    
    // Layout state
    bool m_showChat = true;
    bool m_showFileBrowser = true;
    int m_fileBrowserWidth = 250;
    int m_chatWidth = 350;
    int m_statusHeight = 24;
    
    // Current file
    std::string m_currentFile;
    bool m_fileModified = false;
    
    // Constants
    static constexpr int MIN_WIDTH = 1024;
    static constexpr int MIN_HEIGHT = 768;
    static constexpr int SPLITTER_WIDTH = 4;
};

} // namespace GUI
} // namespace RawrXD
