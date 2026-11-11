#pragma once
#include "CodexCLI.hpp"
#include <windows.h>
#include <string>
#include <functional>
#include <thread>
#include <atomic>

namespace RawrXD {
namespace Codex {

// Custom window messages for cross-thread streaming
#define WM_CODEX_STREAM_CHUNK  (WM_USER + 0x0100)
#define WM_CODEX_STREAM_DONE   (WM_USER + 0x0101)
#define WM_CODEX_STREAM_ERROR  (WM_USER + 0x0102)

// GPT/Codex GUI Interface
class CodexGUI {
public:
    CodexGUI();
    ~CodexGUI();
    
    // Initialize GUI
    bool Initialize(HINSTANCE hInstance, int nCmdShow);
    
    // Run message loop
    int Run();
    
    // Set CLI backend
    void SetCLI(std::shared_ptr<CodexCLI> cli) { m_cli = cli; }
    
    // Window procedure
    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    
    // Show/hide window
    void Show() { ShowWindow(m_hwnd, SW_SHOW); }
    void Hide() { ShowWindow(m_hwnd, SW_HIDE); }
    
    // Check if running
    bool IsRunning() const { return m_running; }
    
    // Handle streaming messages (called from WndProc)
    void OnStreamChunk(const std::wstring& chunk);
    void OnStreamDone();
    void OnStreamError(const std::wstring& error);
    
private:
    // Window handles
    HWND m_hwnd = nullptr;
    HWND m_hwndInput = nullptr;
    HWND m_hwndOutput = nullptr;
    HWND m_hwndSendBtn = nullptr;
    HWND m_hwndStatus = nullptr;
    
    // Instance
    HINSTANCE m_hInstance = nullptr;
    
    // CLI backend
    std::shared_ptr<CodexCLI> m_cli;
    
    // State
    bool m_running = false;
    bool m_processing = false;
    
    // Window class
    static constexpr const wchar_t* CLASS_NAME = L"RawrXDCodexGUI";
    
    // Create window layout
    bool CreateLayout();
    
    // Handle commands
    void OnSend();
    void OnClear();
    void OnSettings();
    void AppendOutput(const std::string& text);
    void SetStatus(const std::string& status);
    
    // Process response
    void ProcessResponse(const std::string& prompt);
    static DWORD WINAPI ProcessThread(LPVOID param);
};

} // namespace Codex
} // namespace RawrXD
