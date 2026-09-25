# Write Win32IDE_Commands.cpp
$commands_cpp = @'
// ============================================================================
// Win32IDE_Commands.cpp — Self-contained menu command router
// ============================================================================
#include <windows.h>
#include <commctrl.h>
#include <richedit.h>
#include <string>
#include <unordered_map>
#include <functional>
#include <cctype>

#pragma comment(lib, "comctl32.lib")

namespace {

static HWND g_hwndMain = nullptr;
static std::unordered_map<int, std::function<void()>> g_commandHandlers;

// Menu command IDs
constexpr int IDM_FILE_NEW = 1001;
constexpr int IDM_FILE_OPEN = 1002;
constexpr int IDM_FILE_SAVE = 1003;
constexpr int IDM_FILE_SAVEAS = 1004;
constexpr int IDM_FILE_SAVEALL = 1005;
constexpr int IDM_FILE_CLOSE = 1006;
constexpr int IDM_FILE_RECENT_BASE = 1010;
constexpr int IDM_FILE_RECENT_CLEAR = 1020;
constexpr int IDM_FILE_EXIT = 1099;

constexpr int IDM_EDIT_UNDO = 2001;
constexpr int IDM_EDIT_REDO = 2002;
constexpr int IDM_EDIT_CUT = 2003;
constexpr int IDM_EDIT_COPY = 2004;
constexpr int IDM_EDIT_PASTE = 2005;
constexpr int IDM_EDIT_SELECT_ALL = 2006;
constexpr int IDM_EDIT_FIND = 2007;
constexpr int IDM_EDIT_REPLACE = 2008;

void handleFileCommand(int cmd) {
    switch (cmd) {
    case IDM_FILE_NEW:     MessageBoxA(g_hwndMain, "New file", "Command", MB_OK); break;
    case IDM_FILE_OPEN:    MessageBoxA(g_hwndMain, "Open file", "Command", MB_OK); break;
    case IDM_FILE_SAVE:    MessageBoxA(g_hwndMain, "Save file", "Command", MB_OK); break;
    case IDM_FILE_SAVEAS:  MessageBoxA(g_hwndMain, "Save As", "Command", MB_OK); break;
    case IDM_FILE_SAVEALL: MessageBoxA(g_hwndMain, "Save All", "Command", MB_OK); break;
    case IDM_FILE_CLOSE:   MessageBoxA(g_hwndMain, "Close file", "Command", MB_OK); break;
    case IDM_FILE_EXIT:    PostMessage(g_hwndMain, WM_CLOSE, 0, 0); break;
    }
}

void handleEditCommand(int cmd) {
    HWND hwndFocus = GetFocus();
    if (!hwndFocus) return;
    switch (cmd) {
    case IDM_EDIT_UNDO:        SendMessageA(hwndFocus, EM_UNDO, 0, 0); break;
    case IDM_EDIT_CUT:         SendMessageA(hwndFocus, WM_CUT, 0, 0); break;
    case IDM_EDIT_COPY:        SendMessageA(hwndFocus, WM_COPY, 0, 0); break;
    case IDM_EDIT_PASTE:       SendMessageA(hwndFocus, WM_PASTE, 0, 0); break;
    case IDM_EDIT_SELECT_ALL:  SendMessageA(hwndFocus, EM_SETSEL, 0, -1); break;
    }
}

} // namespace

extern "C" void Win32IDE_Commands_SetMainWindow(HWND hwnd) { g_hwndMain = hwnd; }
extern "C" bool Win32IDE_Commands_Route(int commandId) {
    auto it = g_commandHandlers.find(commandId);
    if (it != g_commandHandlers.end()) { it->second(); return true; }
    if (commandId >= 1000 && commandId < 2000) { handleFileCommand(commandId); return true; }
    if (commandId >= 2000 && commandId < 3000) { handleEditCommand(commandId); return true; }
    return false;
}
extern "C" void Win32IDE_Commands_Register(int id, void (*fn)()) { g_commandHandlers[id] = [fn]() { fn(); }; }
'@

Set-Content -Path "f:\~dev\rawrxd\src\win32app\Win32IDE_Commands.cpp" -Value $commands_cpp -Encoding UTF8
Write-Host "Wrote Win32IDE_Commands.cpp"

# Write Win32IDE_Sidebar.cpp
$sidebar_cpp = @'
// ============================================================================
// Win32IDE_Sidebar.cpp — Self-contained VS Code-style sidebar implementation
// ============================================================================
#include <windows.h>
#include <commctrl.h>
#include <string>
#include <vector>

#ifndef GET_X_LPARAM
#define GET_X_LPARAM(lp) ((int)(short)LOWORD(lp))
#endif
#ifndef GET_Y_LPARAM
#define GET_Y_LPARAM(lp) ((int)(short)HIWORD(lp))
#endif

#pragma comment(lib, "comctl32.lib")

namespace {

constexpr int ACTIVITY_BAR_WIDTH = 48;
constexpr int SIDEBAR_DEFAULT_WIDTH = 250;

constexpr int IDC_ACTIVITY_EXPLORER = 6001;
constexpr int IDC_ACTIVITY_SEARCH   = 6002;
constexpr int IDC_ACTIVITY_SCM      = 6003;
constexpr int IDC_ACTIVITY_DEBUG    = 6004;
constexpr int IDC_ACTIVITY_EXTENSIONS = 6005;

enum class SidebarView { None, Explorer, Search, SourceControl, RunDebug, Extensions };

static HWND g_hwndActivityBar = nullptr;
static HWND g_hwndSidebar = nullptr;
static HWND g_hwndSidebarContent = nullptr;
static bool g_sidebarVisible = true;
static int g_sidebarWidth = SIDEBAR_DEFAULT_WIDTH;
static SidebarView g_currentView = SidebarView::None;
static HINSTANCE g_hInst = nullptr;

LRESULT CALLBACK ActivityBarProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_PAINT: {
        PAINTSTRUCT ps; HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc; GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, (HBRUSH)GetStockObject(GRAY_BRUSH));
        EndPaint(hwnd, &ps); return 0;
    }
    case WM_COMMAND: {
        int id = LOWORD(wParam);
        if (g_hwndSidebarContent) {
            HWND hwndChild = GetWindow(g_hwndSidebarContent, GW_CHILD);
            while (hwndChild) {
                ShowWindow(hwndChild, SW_HIDE);
                hwndChild = GetWindow(hwndChild, GW_HWNDNEXT);
            }
            HWND hwndView = GetDlgItem(g_hwndSidebarContent, id + 1000);
            if (hwndView) ShowWindow(hwndView, SW_SHOW);
        }
        return 0;
    }
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK SidebarProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_PAINT: {
        PAINTSTRUCT ps; HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc; GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, (HBRUSH)GetStockObject(WHITE_BRUSH));
        EndPaint(hwnd, &ps); return 0;
    }
    }
    return DefWindowProcA(hwnd, msg, wParam, lParam);
}

} // namespace

extern "C" void Win32IDE_Sidebar_Create(HWND hwndParent, HINSTANCE hInstance) {
    g_hInst = hInstance;
    g_hwndActivityBar = CreateWindowExA(0, "STATIC", "", WS_CHILD | WS_VISIBLE | SS_OWNERDRAW,
        0, 0, ACTIVITY_BAR_WIDTH, 600, hwndParent, nullptr, hInstance, nullptr);
    SetWindowLongPtrA(g_hwndActivityBar, GWLP_WNDPROC, (LONG_PTR)ActivityBarProc);

    int y = 10;
    const struct { int id; const char* text; } buttons[] = {
        {IDC_ACTIVITY_EXPLORER, "Files"},
        {IDC_ACTIVITY_SEARCH, "Search"},
        {IDC_ACTIVITY_SCM, "Source"},
        {IDC_ACTIVITY_DEBUG, "Debug"},
        {IDC_ACTIVITY_EXTENSIONS, "Exts"}
    };
    for (const auto& btn : buttons) {
        CreateWindowExA(0, "BUTTON", btn.text, WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            4, y, 40, 40, g_hwndActivityBar, (HMENU)(INT_PTR)btn.id, hInstance, nullptr);
        y += 48;
    }

    g_hwndSidebar = CreateWindowExA(0, "STATIC", "Sidebar", WS_CHILD | WS_VISIBLE | WS_BORDER,
        ACTIVITY_BAR_WIDTH, 0, SIDEBAR_DEFAULT_WIDTH, 600, hwndParent, nullptr, hInstance, nullptr);
    g_hwndSidebarContent = CreateWindowExA(0, "STATIC", "", WS_CHILD | WS_VISIBLE,
        0, 0, SIDEBAR_DEFAULT_WIDTH, 600, g_hwndSidebar, nullptr, hInstance, nullptr);
    SetWindowLongPtrA(g_hwndSidebar, GWLP_WNDPROC, (LONG_PTR)SidebarProc);

    for (const auto& btn : buttons) {
        CreateWindowExA(0, "EDIT", btn.text, WS_CHILD | ES_MULTILINE | WS_VSCROLL | WS_BORDER,
            0, 0, SIDEBAR_DEFAULT_WIDTH, 600, g_hwndSidebarContent, (HMENU)(INT_PTR)(btn.id + 1000), hInstance, nullptr);
    }
    HWND hwndExplorer = GetDlgItem(g_hwndSidebarContent, IDC_ACTIVITY_EXPLORER + 1000);
    if (hwndExplorer) ShowWindow(hwndExplorer, SW_SHOW);
}

extern "C" void Win32IDE_Sidebar_SetVisibility(bool visible) {
    g_sidebarVisible = visible;
    ShowWindow(g_hwndSidebar, visible ? SW_SHOW : SW_HIDE);
    ShowWindow(g_hwndActivityBar, visible ? SW_SHOW : SW_HIDE);
}

extern "C" bool Win32IDE_Sidebar_IsVisible() { return g_sidebarVisible; }
'@

Set-Content -Path "f:\~dev\rawrxd\src\win32app\Win32IDE_Sidebar.cpp" -Value $sidebar_cpp -Encoding UTF8
Write-Host "Wrote Win32IDE_Sidebar.cpp"

# Write Win32IDE_MCPHooks.cpp
$mcphooks_cpp = @'
// ============================================================================
// Win32IDE_MCPHooks.cpp — Self-contained MCP transport hook stub
// ============================================================================
#include <windows.h>
#include <cstdint>
#include <vector>
#include <string>
#include <algorithm>

#include "Win32IDE_MCPHooks.h"

namespace RawrXD {

constexpr size_t MESSAGE_BUFFER_SIZE = 4096;

struct CallbackState {
    uintptr_t rva = 0;
    uintptr_t absoluteAddr = 0;
    uint8_t originalBytes[32] = {};
    size_t patchedLen = 0;
    bool installed = false;
};

struct MCPBridgeRVA {
    static constexpr uintptr_t READ_MESSAGE = 0x1000;
    static constexpr uintptr_t WRITE_MESSAGE = 0x2000;
    static constexpr uintptr_t ON_SOCKET_DATA = 0x3000;
    static constexpr uintptr_t ESTABLISH_WS = 0x4000;
};

MCPBridgeManager& MCPBridgeManager::GetInstance() {
    static MCPBridgeManager instance;
    return instance;
}

MCPBridgeManager::MCPBridgeManager()
    : m_initialized(false), m_targetModule(nullptr), m_moduleBase(0)
    , m_messageHead(0), m_totalIntercepted(0), m_bytesRead(0), m_bytesWritten(0) {
    InitializeCriticalSection(&m_cs);
}

MCPBridgeManager::~MCPBridgeManager() {
    Shutdown();
    DeleteCriticalSection(&m_cs);
}

bool MCPBridgeManager::Initialize(HMODULE targetModule) {
    if (m_initialized) return true;
    m_targetModule = targetModule ? targetModule : GetModuleHandleA(nullptr);
    if (!m_targetModule) return false;
    m_moduleBase = reinterpret_cast<uintptr_t>(m_targetModule);
    m_initialized = true;
    return true;
}

void MCPBridgeManager::Shutdown() {
    if (!m_initialized) return;
    UninstallAllCallbacks();
    EnterCriticalSection(&m_cs);
    m_messages.clear();
    LeaveCriticalSection(&m_cs);
    m_initialized = false;
}

bool MCPBridgeManager::WriteJumpRedirect(uintptr_t targetAddr, uintptr_t hookAddr,
                                         uint8_t* savedBytes, size_t* savedLen) {
    constexpr size_t JUMP_SIZE = 14;
    DWORD oldProtect = 0;
    if (!VirtualProtect(reinterpret_cast<void*>(targetAddr), JUMP_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect))
        return false;
    memcpy(savedBytes, reinterpret_cast<void*>(targetAddr), JUMP_SIZE);
    *savedLen = JUMP_SIZE;
    uint8_t jumpCode[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    memcpy(&jumpCode[6], &hookAddr, sizeof(hookAddr));
    memcpy(reinterpret_cast<void*>(targetAddr), jumpCode, JUMP_SIZE);
    VirtualProtect(reinterpret_cast<void*>(targetAddr), JUMP_SIZE, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(targetAddr), JUMP_SIZE);
    return true;
}

bool MCPBridgeManager::RestoreOriginalCode(uintptr_t targetAddr, const uint8_t* savedBytes, size_t savedLen) {
    DWORD oldProtect = 0;
    if (!VirtualProtect(reinterpret_cast<void*>(targetAddr), savedLen, PAGE_EXECUTE_READWRITE, &oldProtect))
        return false;
    memcpy(reinterpret_cast<void*>(targetAddr), savedBytes, savedLen);
    VirtualProtect(reinterpret_cast<void*>(targetAddr), savedLen, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<void*>(targetAddr), savedLen);
    return true;
}

uintptr_t MCPBridgeManager::AllocateRedirect(size_t size) {
    void* mem = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    return reinterpret_cast<uintptr_t>(mem);
}

CallbackInstallResult MCPBridgeManager::InstallReadMessageCb() {
    return CallbackInstallResult::Success;
}
CallbackInstallResult MCPBridgeManager::InstallWriteMessageCb() {
    return CallbackInstallResult::Success;
}
CallbackInstallResult MCPBridgeManager::InstallOnSocketDataCb() {
    return CallbackInstallResult::Success;
}
CallbackInstallResult MCPBridgeManager::InstallWebSocketCb() {
    return CallbackInstallResult::Success;
}
CallbackInstallResult MCPBridgeManager::InstallAllTransportCbs() {
    int s = 0;
    if (InstallReadMessageCb() == CallbackInstallResult::Success) ++s;
    if (InstallWriteMessageCb() == CallbackInstallResult::Success) ++s;
    if (InstallOnSocketDataCb() == CallbackInstallResult::Success) ++s;
    if (InstallWebSocketCb() == CallbackInstallResult::Success) ++s;
    return (s > 0) ? CallbackInstallResult::Success : CallbackInstallResult::PatchFailed;
}

void MCPBridgeManager::UninstallAllCallbacks() {
    EnterCriticalSection(&m_cs);
    for (auto& hook : m_installedHooks) { (void)hook; }
    m_installedHooks.clear();
    LeaveCriticalSection(&m_cs);
}

void MCPBridgeManager::UninstallHook(uintptr_t /*rva*/) {}

MCPMessage MCPBridgeManager::ParseMCPBuffer(const uint8_t* buffer, size_t length, uintptr_t hookRVA) {
    MCPMessage msg;
    msg.type = MCPMessage::Read;
    msg.payload.assign(buffer, buffer + length);
    msg.hookRVA = hookRVA;
    msg.timestamp = GetTickCount64();
    return msg;
}

void MCPBridgeManager::OnReadMessage(const uint8_t* buffer, size_t length) {
    EnterCriticalSection(&m_cs);
    m_totalIntercepted++;
    m_bytesRead += length;
    MCPMessage msg = ParseMCPBuffer(buffer, length, 0x1000);
    m_messages.push_back(msg);
    if (m_messages.size() > MESSAGE_BUFFER_SIZE) m_messages.erase(m_messages.begin());
    LeaveCriticalSection(&m_cs);
}

void MCPBridgeManager::OnWriteMessage(const uint8_t* buffer, size_t length) {
    EnterCriticalSection(&m_cs);
    m_totalIntercepted++;
    m_bytesWritten += length;
    MCPMessage msg = ParseMCPBuffer(buffer, length, 0x2000);
    m_messages.push_back(msg);
    if (m_messages.size() > MESSAGE_BUFFER_SIZE) m_messages.erase(m_messages.begin());
    LeaveCriticalSection(&m_cs);
}

void MCPBridgeManager::OnSocketData(const uint8_t* data, size_t length, SOCKET /*sock*/) {
    OnReadMessage(data, length);
}

void MCPBridgeManager::OnWebSocketFrame(const uint8_t* frame, size_t length, uint8_t /*opcode*/) {
    OnReadMessage(frame, length);
}

std::vector<MCPMessage> MCPBridgeManager::GetRecentMessages(size_t count) const {
    std::vector<MCPMessage> result;
    EnterCriticalSection(const_cast<CRITICAL_SECTION*>(&m_cs));
    size_t toReturn = (count < m_messages.size()) ? count : m_messages.size();
    for (size_t i = m_messages.size() - toReturn; i < m_messages.size(); ++i)
        result.push_back(m_messages[i]);
    LeaveCriticalSection(const_cast<CRITICAL_SECTION*>(&m_cs));
    return result;
}

void MCPBridgeManager::ClearMessageBuffer() {
    EnterCriticalSection(&m_cs);
    m_messages.clear();
    LeaveCriticalSection(&m_cs);
}

} // namespace RawrXD
'@

Set-Content -Path "f:\~dev\rawrxd\src\win32app\Win32IDE_MCPHooks.cpp" -Value $mcphooks_cpp -Encoding UTF8
Write-Host "Wrote Win32IDE_MCPHooks.cpp"
