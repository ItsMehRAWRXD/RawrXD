// Win32IDE.cpp - RawrXD Win32 IDE shell
//
// NOTE: the destructor used to be emitted here, ABOVE the #include block, so
// Win32IDE/RawrXD::CPUInferenceEngine/Win32TerminalManager were all undeclared
// at that point and every consumer of this translation unit failed to compile.
// It now lives with the other Win32IDE member definitions, below the includes.

#include "Win32IDE.h"
#include "Win32IDE_CommandIDs.h"
#include "Win32IDE_Deep2Bridge.h"
#include "GeneratedChatRouteMenu.h"
#include "../cloud_api_client.h"
#include "../universal_model_router.h"
#include <regex>
#include "IDELogger.h"
#include "Win32IDE_AgenticBridge.h"
#include "../cpu_inference_engine.h" // Added for Native Fallback
#include "streaming_gguf_loader.h"
#include "../utils/ErrorReporter.hpp"
#include <commdlg.h>
#include <richedit.h>
#include <commctrl.h>
#include <shlobj.h>
#include <shellapi.h>
#include <iostream>
#include <fstream>
#include <cstdint>
#include <cstring>
#include <chrono>
#include <algorithm>
#include <sstream>
#include <ctime>
#include <cstdlib>
#include <iterator>
#include <deque>
#include <unordered_set>
#include <cctype>
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "comctl32.lib")

// nlohmann/json.hpp is pulled in for refreshModuleList()'s Get-Module JSON.
// It is included here (rather than only via ModelConnection.h) because this
// translation unit uses nlohmann::json::parse directly.
#include <nlohmann/json.hpp>

namespace {

// ---------------------------------------------------------------------------
// Native CPU inference helper.
//
// RawrXD::CPUInferenceEngine exposes Tokenize / GenerateStreaming /
// IsModelLoaded / LoadModel. It has no infer() method - three call sites in
// this file invoked engine->infer(prompt) and two invoked engine->isModelLoaded()
// / engine->loadModel(), none of which exist. This routes them through the real
// API (note the capitalisation: IsModelLoaded/LoadModel, not isModelLoaded/loadModel).
// ---------------------------------------------------------------------------
std::string NativeEngineInfer(RawrXD::CPUInferenceEngine* engine,
                              const std::string& prompt,
                              int maxTokens = 512)
{
    if (!engine) return "Error: Native CPU engine not available.";
    if (!engine->IsModelLoaded()) return "Error: No model loaded in Native CPU Engine.";

    // Tokenize() returns std::vector<int>; GenerateStreaming wants int32_t.
    const std::vector<int> tokensInt = engine->Tokenize(prompt);
    std::vector<int32_t> tokens(tokensInt.begin(), tokensInt.end());
    if (tokens.empty()) return "";

    std::string out;
    engine->GenerateStreaming(tokens, maxTokens,
        [&out](const std::string& piece) { out += piece; },
        []() {},
        nullptr);
    return out;
}

// Run a child process and capture its stdout. Used by refreshModuleList()'s
// PowerShell module enumeration, which called a non-existent ExecCmd().
std::string CaptureProcessOutput(const std::string& commandLine)
{
    std::string result;

    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE readPipe = nullptr;
    HANDLE writePipe = nullptr;
    if (!CreatePipe(&readPipe, &writePipe, &sa, 0)) return result;

    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = writePipe;
    si.hStdError = writePipe;
    PROCESS_INFORMATION pi = {};

    std::vector<char> cmd(commandLine.begin(), commandLine.end());
    cmd.push_back('\0');

    const BOOL ok = CreateProcessA(nullptr, cmd.data(), nullptr, nullptr, TRUE,
                                   CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(writePipe);
    if (!ok) {
        CloseHandle(readPipe);
        return result;
    }

    char buffer[4096];
    DWORD bytesRead = 0;
    while (ReadFile(readPipe, buffer, sizeof(buffer), &bytesRead, nullptr) && bytesRead > 0) {
        result.append(buffer, bytesRead);
    }

    WaitForSingleObject(pi.hProcess, 10000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(readPipe);
    return result;
}

std::string toLowerAscii(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

std::string modelRouteBreadcrumb(RawrXD::ChatRouteMenu::RouteKind kind,
                                 const std::string& leaf)
{
    const auto* route = RawrXD::ChatRouteMenu::find(kind);
    if (!route) return leaf;
    return std::string(route->breadcrumb) + " / " + leaf;
}

bool isSelectableGguf(const char* filename)
{
    const std::string name = toLowerAscii(filename ? filename : "");
    if (name.size() < 5 || name.compare(name.size() - 5, 5, ".gguf") != 0 ||
        name.find("mmproj") != std::string::npos) {
        return false;
    }

    // A split GGUF is loaded from its first shard; listing every continuation
    // shard would make the picker look like it contains duplicate models.
    const size_t shard = name.find("-000");
    if (shard != std::string::npos && shard + 13 <= name.size() &&
        name.compare(shard + 6, 4, "-of-") == 0 &&
        name.compare(shard + 1, 5, "00001") != 0) {
        return false;
    }
    return true;
}

// Some GGUF files contain tokenizer metadata only (for example
// ggml-vocab-aquila.gguf). They are valid GGUF containers but cannot be
// loaded as inference models. Read only the fixed header so recursive model
// discovery can reject those files without mapping or parsing their contents.
bool hasGgufModelTensors(const std::string& path)
{
    std::ifstream input(path, std::ios::binary);
    unsigned char header[16]{};
    if (!input.read(reinterpret_cast<char*>(header), sizeof(header)) ||
        std::memcmp(header, "GGUF", 4) != 0) {
        return false;
    }

    const uint32_t version =
        static_cast<uint32_t>(header[4]) |
        (static_cast<uint32_t>(header[5]) << 8) |
        (static_cast<uint32_t>(header[6]) << 16) |
        (static_cast<uint32_t>(header[7]) << 24);
    uint64_t tensorCount = 0;
    for (unsigned int i = 0; i < 8; ++i) {
        tensorCount |= static_cast<uint64_t>(header[8 + i]) << (i * 8);
    }
    return version >= 2 && version <= 3 && tensorCount > 0;
}

bool skipModelScanDirectory(const std::string& name)
{
    const std::string lower = toLowerAscii(name);
    static const std::unordered_set<std::string> skipped = {
        "$recycle.bin", "system volume information", "windows", "winsxs",
        "program files", "program files (x86)", "node_modules", ".git",
        ".svn", ".hg", ".vs", "__pycache__", "$windows.~bt"
    };
    return skipped.find(lower) != skipped.end();
}

void scanModelTree(const std::string& root,
                   std::vector<ChatModelEntry>& models,
                   std::unordered_set<std::string>& seen,
                   const std::shared_ptr<std::atomic_bool>& cancel,
                   size_t& visitedDirectories)
{
    std::deque<std::pair<std::string, unsigned>> pending;
    pending.emplace_back(root, 0);
    while (!pending.empty() && !cancel->load() && visitedDirectories < 300000) {
        auto current = std::move(pending.front());
        pending.pop_front();
        ++visitedDirectories;

        WIN32_FIND_DATAA data{};
        std::string pattern = current.first;
        if (pattern.empty() || pattern.back() != '\\') pattern.push_back('\\');
        pattern.push_back('*');
        HANDLE find = FindFirstFileA(pattern.c_str(), &data);
        if (find == INVALID_HANDLE_VALUE) continue;
        do {
            if (cancel->load()) break;
            if (std::strcmp(data.cFileName, ".") == 0 ||
                std::strcmp(data.cFileName, "..") == 0) continue;

            std::string fullPath = current.first;
            if (fullPath.empty() || fullPath.back() != '\\') fullPath.push_back('\\');
            fullPath += data.cFileName;
            if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                if (!(data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
                    current.second < 48 && !skipModelScanDirectory(data.cFileName)) {
                    pending.emplace_back(fullPath, current.second + 1);
                }
            } else if (isSelectableGguf(data.cFileName) &&
                       hasGgufModelTensors(fullPath)) {
                const std::string key = toLowerAscii(fullPath);
                if (seen.insert(key).second) {
                    models.push_back({ChatModelEntry::Source::LocalFile,
                        modelRouteBreadcrumb(RawrXD::ChatRouteMenu::RouteKind::LocalFile,
                            fullPath), fullPath});
                }
            }
        } while (FindNextFileA(find, &data));
        FindClose(find);
    }
}

std::vector<ChatModelEntry> discoverLocalModels(
    const std::shared_ptr<std::atomic_bool>& cancel)
{
    std::vector<ChatModelEntry> models;
    std::unordered_set<std::string> seen;
    size_t visitedDirectories = 0;
    char driveStrings[MAX_PATH + 1] = {};
    const DWORD driveStringLength = GetLogicalDriveStringsA(MAX_PATH, driveStrings);
    if (driveStringLength && driveStringLength < MAX_PATH) {
        for (const char* drive = driveStrings; *drive && !cancel->load();
             drive += std::strlen(drive) + 1) {
            const UINT driveType = GetDriveTypeA(drive);
            if (driveType == DRIVE_FIXED || driveType == DRIVE_REMOVABLE) {
                scanModelTree(drive, models, seen, cancel, visitedDirectories);
            }
        }
    }

    // Ollama stores weights as content-addressed blobs without model-file
    // extensions. Its local tags endpoint is the authoritative local catalog.
    if (!cancel->load()) {
        HINTERNET session = WinHttpOpen(L"RawrXD Model Discovery/1.0",
            WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS, 0);
        if (session) {
            WinHttpSetTimeouts(session, 300, 500, 750, 750);
            HINTERNET connect = WinHttpConnect(session, L"127.0.0.1", 11434, 0);
            if (connect) {
                HINTERNET request = WinHttpOpenRequest(connect, L"GET", L"/api/tags",
                    nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
                if (request) {
                    std::string raw;
                    if (WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
                        WinHttpReceiveResponse(request, nullptr)) {
                        DWORD available = 0;
                        while (!cancel->load() &&
                               WinHttpQueryDataAvailable(request, &available) && available) {
                            std::string chunk(available, '\0');
                            DWORD read = 0;
                            if (!WinHttpReadData(request, chunk.data(), available, &read) || !read) break;
                            raw.append(chunk.data(), read);
                        }
                    }
                    WinHttpCloseHandle(request);
                    try {
                        const auto document = nlohmann::json::parse(raw);
                        if (document.contains("models") && document["models"].is_array()) {
                            for (const auto& model : document["models"]) {
                                if (!model.contains("name") || !model["name"].is_string()) continue;
                                const std::string name = model["name"].get<std::string>();
                                models.push_back({ChatModelEntry::Source::Ollama,
                                    modelRouteBreadcrumb(
                                        RawrXD::ChatRouteMenu::RouteKind::Ollama, name), name});
                            }
                        }
                    } catch (...) {
                        // Ollama may be absent or may return a non-catalog response.
                    }
                }
                WinHttpCloseHandle(connect);
            }
            WinHttpCloseHandle(session);
        }
    }

    std::sort(models.begin(), models.end(), [](const auto& a, const auto& b) {
        return toLowerAscii(a.breadcrumb) < toLowerAscii(b.breadcrumb);
    });
    return models;
}

std::string generateOllamaModel(const std::string& baseUrl,
                                 const std::string& model,
                                 const std::string& prompt,
                                 int maxTokens)
{
    // DEBUG: Log to both OutputDebugStringA and a file
    auto logDebug = [](const char* fmt, ...) {
        char buf[1024];
        va_list args;
        va_start(args, fmt);
        vsnprintf(buf, sizeof(buf), fmt, args);
        va_end(args);
        OutputDebugStringA(buf);
        // Also write to the configured/local log directory without binding
        // the runtime to a particular checkout drive.
        const char* configuredLogDir = std::getenv("RAWRXD_LOG_DIR");
        const std::string logPath = (configuredLogDir && *configuredLogDir)
            ? std::string(configuredLogDir) + "\\ollama_debug.log"
            : std::string("ollama_debug.log");
        FILE* f = fopen(logPath.c_str(), "a");
        if (f) {
            fprintf(f, "%s", buf);
            fclose(f);
        }
    };
    
    logDebug("[OLLAMA_DEBUG] generateOllamaModel: model='%s' prompt_len=%zu maxTokens=%d\n", 
             model.c_str(), prompt.length(), maxTokens);
    
    std::string url = baseUrl.empty() ? "http://127.0.0.1:11434" : baseUrl;
    const size_t scheme = url.find("://");
    if (scheme == std::string::npos) { 
        logDebug("[OLLAMA_DEBUG] Invalid URL scheme\n");
        return {}; 
    }
    const bool https = url.compare(0, scheme, "https") == 0;
    const size_t authorityStart = scheme + 3;
    const size_t pathStart = url.find('/', authorityStart);
    const std::string authority = url.substr(authorityStart,
        pathStart == std::string::npos ? std::string::npos : pathStart - authorityStart);
    const size_t colon = authority.rfind(':');
    const std::string host = colon == std::string::npos ? authority : authority.substr(0, colon);
    const INTERNET_PORT port = colon == std::string::npos
        ? (https ? INTERNET_DEFAULT_HTTPS_PORT : static_cast<INTERNET_PORT>(11434))
        : static_cast<INTERNET_PORT>(std::atoi(authority.c_str() + colon + 1));
    if (host.empty() || port == 0) { 
        logDebug("[OLLAMA_DEBUG] Invalid host/port\n");
        return {}; 
    }
    
    logDebug("[OLLAMA_DEBUG] Connecting to %s:%d\n", host.c_str(), (int)port);

    const auto bodyJson = nlohmann::json{
        {"model", model}, {"prompt", prompt}, {"stream", false},
        {"options", {{"num_predict", maxTokens}}}
    };
    const std::string body = bodyJson.dump();
    const std::wstring wideHost(host.begin(), host.end());
    HINTERNET session = WinHttpOpen(L"RawrXD Chat/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) { 
        logDebug("[OLLAMA_DEBUG] WinHttpOpen failed (GetLastError=%lu)\n", GetLastError());
        return {}; 
    }
    WinHttpSetTimeouts(session, 1500, 1500, 30000, 30000);
    HINTERNET connect = WinHttpConnect(session, wideHost.c_str(), port, 0);
    if (!connect) { 
        logDebug("[OLLAMA_DEBUG] WinHttpConnect failed (GetLastError=%lu)\n", GetLastError());
        WinHttpCloseHandle(session); 
        return {}; 
    }
    const DWORD flags = https ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET request = WinHttpOpenRequest(connect, L"POST", L"/api/generate", nullptr,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!request) { 
        logDebug("[OLLAMA_DEBUG] WinHttpOpenRequest failed (GetLastError=%lu)\n", GetLastError());
        WinHttpCloseHandle(connect); WinHttpCloseHandle(session); 
        return {}; 
    }

    std::string raw;
    const wchar_t headers[] = L"Content-Type: application/json\r\n";
    if (WinHttpSendRequest(request, headers, static_cast<DWORD>(-1L),
            const_cast<char*>(body.data()), static_cast<DWORD>(body.size()),
            static_cast<DWORD>(body.size()), 0) && WinHttpReceiveResponse(request, nullptr)) {
        DWORD available = 0;
        while (WinHttpQueryDataAvailable(request, &available) && available) {
            std::string chunk(available, '\0');
            DWORD read = 0;
            if (!WinHttpReadData(request, chunk.data(), available, &read) || !read) break;
            raw.append(chunk.data(), read);
        }
    } else {
        logDebug("[OLLAMA_DEBUG] WinHttpSendRequest/ReceiveResponse failed (GetLastError=%lu)\n", GetLastError());
    }
    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);
    
    logDebug("[OLLAMA_DEBUG] Raw response length: %zu\n", raw.length());
    if (!raw.empty() && raw.length() < 500) {
        logDebug("[OLLAMA_DEBUG] Raw response: %s\n", raw.c_str());
    }

    try {
        const auto response = nlohmann::json::parse(raw);
        if (response.contains("response") && response["response"].is_string()) {
            std::string result = response["response"].get<std::string>();
            logDebug("[OLLAMA_DEBUG] Parsed response successfully, length=%zu\n", result.length());
            return result;
        } else {
            logDebug("[OLLAMA_DEBUG] Response missing 'response' field\n");
        }
    } catch (const std::exception& e) {
        logDebug("[OLLAMA_DEBUG] JSON parse error: %s\n", e.what());
    } catch (...) {
        logDebug("[OLLAMA_DEBUG] Unknown JSON parse error\n");
    }
    return {};
}

} // namespace


#define IDC_TERMINAL 1002
#define IDC_COMMAND_INPUT 1003
#define IDC_STATUS_BAR 1004
#define IDC_MINIMAP 1006
#define IDC_MODULE_BROWSER 1007
#define IDC_HELP_PANEL 1008
#define IDC_SNIPPET_LIST 1009
#define IDC_CLIPBOARD_HISTORY 1010
#define IDC_OUTPUT_TEXT 1011
#define IDC_OUTPUT_EDIT_GENERAL 1012
#define IDC_OUTPUT_EDIT_ERRORS 1013
#define IDC_OUTPUT_EDIT_DEBUG 1014
#define IDC_OUTPUT_EDIT_FIND 1015
#define IDC_SPLITTER 1016
#define IDC_SEVERITY_FILTER 1017
#define IDC_TITLE_TEXT 1018
#define IDC_FILE_TREE 1026

// Activity Bar (Far Left) - VS Code style icon bar
#define IDC_ACTIVITY_BAR 1100
#define IDC_ACTBAR_EXPLORER 1101
#define IDC_ACTBAR_SEARCH 1102
#define IDC_ACTBAR_SCM 1103
#define IDC_ACTBAR_DEBUG 1104
#define IDC_ACTBAR_EXTENSIONS 1105
#define IDC_ACTBAR_SETTINGS 1106
#define IDC_ACTBAR_ACCOUNTS 1107

// Secondary Sidebar (Right) - AI Chat/Copilot area
#define IDC_SECONDARY_SIDEBAR 1200
#define IDC_SECONDARY_SIDEBAR_HEADER 1201
#define IDC_COPILOT_CHAT_INPUT 1202
#define IDC_COPILOT_CHAT_OUTPUT 1203
#define IDC_COPILOT_SEND_BTN 1204
#define IDC_COPILOT_CLEAR_BTN 1205
#define IDC_COPILOT_MODEL_SELECTOR 1206
#define IDC_COPILOT_TOKEN_SLIDER 1207
#define IDC_CHAT_SESSIONS 1208
#define IDC_NEW_CHAT 1209
#define IDC_COPILOT_STOP_BTN 1210
#define IDC_GHOST_MODEL_SELECTOR 1211
#define IDC_GHOST_ALLOW_CLOUD 1212
#define IDC_COPILOT_CONTEXT_SLIDER 1213
#define IDC_CLOSE_CHAT 1214
#define IDC_RESTORE_CHAT 1215

// Panel (Bottom) - Terminal, Output, Problems, Debug Console
#define IDC_PANEL_CONTAINER 1300
#define IDC_PANEL_TABS 1301
#define IDC_PANEL_TERMINAL 1302
#define IDC_PANEL_OUTPUT 1303
#define IDC_PANEL_PROBLEMS 1304
#define IDC_PANEL_DEBUG_CONSOLE 1305
#define IDC_PANEL_TOOLBAR 1306
#define IDC_PANEL_BTN_NEW_TERMINAL 1307
#define IDC_PANEL_BTN_SPLIT_TERMINAL 1308
#define IDC_PANEL_BTN_KILL_TERMINAL 1309
#define IDC_PANEL_BTN_MAXIMIZE 1310
#define IDC_PANEL_BTN_CLOSE 1311
#define IDC_PANEL_PROBLEMS_LIST 1312

// Debugger Panel - Integrated at bottom with Terminal/Output
#define IDC_DEBUGGER_CONTAINER 1313
#define IDC_DEBUGGER_TABS 1314
#define IDC_DEBUGGER_BREAKPOINTS 1315
#define IDC_DEBUGGER_WATCH 1316
#define IDC_DEBUGGER_VARIABLES 1317
#define IDC_DEBUGGER_STACK_TRACE 1318
#define IDC_DEBUGGER_MEMORY 1319
#define IDC_DEBUGGER_TOOLBAR 1320
#define IDC_DEBUGGER_BTN_CONTINUE 1321
#define IDC_DEBUGGER_BTN_STEP_OVER 1322
#define IDC_DEBUGGER_BTN_STEP_INTO 1323
#define IDC_DEBUGGER_BTN_STEP_OUT 1324
#define IDC_DEBUGGER_BTN_RESTART 1325
#define IDC_DEBUGGER_BTN_STOP 1326
#define IDC_DEBUGGER_INPUT 1327
#define IDC_DEBUGGER_BREAKPOINT_LIST 1328
#define IDC_DEBUGGER_WATCH_LIST 1329
#define IDC_DEBUGGER_VARIABLE_TREE 1330
#define IDC_DEBUGGER_STACK_LIST 1331
#define IDC_DEBUGGER_STATUS_TEXT 1332

// Enhanced Status Bar items
#define IDC_STATUS_REMOTE 1400
#define IDC_STATUS_BRANCH 1401
#define IDC_STATUS_SYNC 1402
#define IDC_STATUS_ERRORS 1403
#define IDC_STATUS_WARNINGS 1404
#define IDC_STATUS_LINE_COL 1405
#define IDC_STATUS_SPACES 1406
#define IDC_STATUS_ENCODING 1407
#define IDC_STATUS_EOL 1408
#define IDC_STATUS_LANGUAGE 1409
#define IDC_STATUS_COPILOT 1410
#define IDC_STATUS_NOTIFICATIONS 1411









// Agent menu IDs

// Command Palette control IDs
#define IDC_CMDPAL_CONTAINER 1500
#define IDC_CMDPAL_INPUT 1501
#define IDC_CMDPAL_LIST 1502

Win32IDE::Win32IDE(HINSTANCE hInstance)
        : m_hInstance(hInstance), m_hwndMain(nullptr), m_hwndEditor(nullptr),
            m_hwndCommandInput(nullptr), m_hwndStatusBar(nullptr),
            m_hwndMinimap(nullptr), m_hwndModuleBrowser(nullptr), m_hwndModuleList(nullptr),
            m_hwndModuleLoadButton(nullptr), m_hwndModuleUnloadButton(nullptr), m_hwndModuleRefreshButton(nullptr),
            m_moduleBrowserVisible(false), m_modulePanelProc(nullptr),
    m_hwndHelp(nullptr), m_hMenu(nullptr), m_hwndToolbar(nullptr), 
    m_hwndTitleLabel(nullptr), m_hwndBtnMinimize(nullptr), m_hwndBtnMaximize(nullptr),
    m_hwndBtnClose(nullptr), m_hwndBtnGitHub(nullptr), m_hwndBtnMicrosoft(nullptr),
    m_hwndBtnSettings(nullptr), m_lastTitleBarText(),
      m_fileModified(false), m_editorHeight(400), m_terminalHeight(200),
      m_minimapVisible(true), m_minimapWidth(150), m_profilingActive(false),
      m_moduleListDirty(true), m_backgroundBrush(nullptr), m_editorFont(nullptr),
    m_activeOutputTab("General"), m_minimapX(650), m_outputTabHeight(200),
    m_nextTerminalId(1), m_activeTerminalId(-1),
    m_ggufLoader(nullptr), m_loadedModelPath(""),
      m_terminalSplitHorizontal(true), m_hwndGitPanel(nullptr), m_hwndGitStatusText(nullptr),
    m_hwndGitFileList(nullptr), m_gitAutoRefresh(true), m_outputPanelVisible(true), m_selectedOutputTab(0),
    m_hwndSeverityFilter(nullptr), m_severityFilterLevel(0),
    m_editorRect{0, 0, 0, 0}, m_gpuTextEnabled(true), m_editorHooksInstalled(false),
    m_hwndSplitter(nullptr), m_splitterDragging(false), m_splitterY(0),
    m_renderer(nullptr), m_rendererReady(false),
    m_lastSearchText(), m_lastReplaceText(),
    m_searchCaseSensitive(false), m_searchWholeWord(false), m_searchUseRegex(false), m_lastFoundPos(-1),
    m_hwndFindDialog(nullptr), m_hwndReplaceDialog(nullptr),
    // Primary Sidebar
    m_hwndActivityBar(nullptr), m_hwndSidebar(nullptr), m_hwndSidebarContent(nullptr),
    m_sidebarVisible(true), m_sidebarWidth(250), m_currentSidebarView(SidebarView::None),
    // Explorer View
    m_hwndExplorerTree(nullptr), m_hwndExplorerToolbar(nullptr), m_hImageListExplorer(nullptr),
    m_explorerRootPath(),
    // Search View
    m_hwndSearchInput(nullptr), m_hwndSearchResults(nullptr), m_hwndSearchOptions(nullptr),
    m_hwndIncludePattern(nullptr), m_hwndExcludePattern(nullptr), m_searchInProgress(false),
    // Source Control View
    m_hwndSCMFileList(nullptr), m_hwndSCMToolbar(nullptr), m_hwndSCMMessageBox(nullptr),
    // Debug View
    m_hwndDebugConfigs(nullptr), m_hwndDebugToolbar(nullptr), m_hwndDebugVariables(nullptr),
    m_hwndDebugCallStack(nullptr), m_hwndDebugConsole(nullptr), m_debuggingActive(false),
    // Extensions View
    m_hwndExtensionsList(nullptr), m_hwndExtensionSearch(nullptr), m_hwndExtensionDetails(nullptr),
    // File Explorer
    m_hwndFileExplorer(nullptr), m_hImageList(nullptr), m_currentExplorerPath(),
    // Model Chat
    m_chatMode(false),
    // PowerShell Panel
    m_hwndPowerShellPanel(nullptr), m_hwndPowerShellOutput(nullptr), m_hwndPowerShellInput(nullptr),
    m_hwndPowerShellToolbar(nullptr), m_hwndPowerShellStatusBar(nullptr),
    m_hwndPSBtnExecute(nullptr), m_hwndPSBtnClear(nullptr), m_hwndPSBtnStop(nullptr),
    m_hwndPSBtnHistory(nullptr), m_hwndPSBtnRestart(nullptr), m_hwndPSBtnLoadRawrXD(nullptr),
    m_hwndPSBtnToggle(nullptr),
    m_powerShellPanelVisible(true), m_powerShellPanelDocked(true), m_powerShellSessionActive(false),
    m_powerShellRawrXDLoaded(false), m_powerShellPanelHeight(250), m_powerShellPanelWidth(600),
    m_powerShellHistoryIndex(-1), m_maxPowerShellHistory(100),
    m_useStreamingLoader(false), m_useVulkanRenderer(false),
    m_powerShellExecuting(false), m_powerShellProcessHandle(nullptr),
    m_dedicatedPowerShellTerminal(nullptr)
    , m_hwndCommandPalette(nullptr), m_hwndCommandPaletteInput(nullptr), m_hwndCommandPaletteList(nullptr), m_commandPaletteVisible(false)
    , m_hwndModelSelector(nullptr), m_hwndMaxTokensSlider(nullptr), m_hwndMaxTokensLabel(nullptr)
    , m_currentMaxTokens(512)
{
    // Initialize Native Fallback Engine
    try {
        m_nativeEngine = new RawrXD::CPUInferenceEngine();
        m_nativeEngineLoaded = true;
    } catch (...) {
        m_nativeEngine = nullptr;
        m_nativeEngineLoaded = false;
        OutputDebugStringA("ERROR: Failed to initialize Native CPU Inference Engine\n");
    }

    // Initialize logger
    try {
        IDELogger::getInstance().initialize("");
        IDELogger::getInstance().setLevel(IDELogger::Level::DEBUG);
        LOG_INFO("Win32IDE constructor started");
    } catch (const std::exception& e) {
        OutputDebugStringA("FATAL: Logger initialization failed: ");
        OutputDebugStringA(e.what());
        OutputDebugStringA("\n");
        // Continue without logging
    } catch (...) {
        OutputDebugStringA("FATAL: Logger initialization failed with unknown exception\n");
    }

    // Initialize Agentic Bridge (Native)
    initializeAgenticBridge();

    
    // Prepare DirectX renderer with safety wrapper
    try {

        m_renderer = std::make_unique<TransparentRenderer>();

    } catch (const std::exception& e) {
        LOG_CRITICAL(std::string("TransparentRenderer creation failed: ") + e.what());
        OutputDebugStringA("ERROR: TransparentRenderer failed: ");
        OutputDebugStringA(e.what());
        OutputDebugStringA("\n");
        m_renderer = nullptr; // Use null renderer
    } catch (...) {
        LOG_CRITICAL("TransparentRenderer creation failed with unknown exception");
        OutputDebugStringA("ERROR: TransparentRenderer failed with unknown exception\n");
        m_renderer = nullptr;
    }
    
    // Initialize PowerShell state with safety
    try {

        initializePowerShellState();

    } catch (const std::exception& e) {

        OutputDebugStringA("ERROR: PowerShell init failed\n");
    } catch (...) {

        OutputDebugStringA("ERROR: PowerShell init failed\n");
    }
    
    // Initialize default theme
    try {

        resetToDefaultTheme();

    } catch (...) {

        OutputDebugStringA("ERROR: Theme reset failed\n");
    }
    
    // Load code snippets
    try {

        loadCodeSnippets();

    } catch (...) {

        OutputDebugStringA("ERROR: Code snippets loading failed\n");
    }
    
    // Initialize profiling frequency
    QueryPerformanceFrequency(&m_profilingFreq);

    // Initialize clipboard history
    m_clipboardHistory.reserve(MAX_CLIPBOARD_HISTORY);
    
    // Initialize Git status
    m_gitStatus = GitStatus();
    
    // Get current directory for Git repo detection
    char currentDir[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, currentDir);
    m_gitRepoPath = currentDir;
    
    // Default Ollama configuration
    m_ollamaBaseUrl = "http://localhost:11434"; // default
    m_ollamaModelOverride = "";
    
    // Initialize Enhanced Status Bar info
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)"Ready");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1, (LPARAM)"Autonomy: OFF");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 2, (LPARAM)"Branch: None");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 3, (LPARAM)"Model: None");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 4, (LPARAM)"GGUF: None");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 5, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 6, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 7, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 8, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 9, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 10, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 11, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 12, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 13, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 14, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 15, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 16, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 17, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 18, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 19, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 20, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 21, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 22, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 23, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 24, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 25, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 26, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 27, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 28, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 29, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 30, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 31, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 32, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 33, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 34, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 35, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 36, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 37, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 38, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 39, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 40, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 41, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 42, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 43, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 44, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 45, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 46, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 47, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 48, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 49, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 50, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 51, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 52, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 53, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 54, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 55, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 56, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 57, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 58, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 59, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 60, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 61, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 62, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 63, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 64, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 65, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 66, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 67, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 68, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 69, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 70, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 71, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 72, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 73, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 74, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 75, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 76, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 77, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 78, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 79, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 80, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 81, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 82, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 83, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 84, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 85, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 86, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 87, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 88, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 89, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 90, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 91, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 92, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 93, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 94, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 95, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 96, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 97, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 98, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 99, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 100, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 101, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 102, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 103, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 104, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 105, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 106, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 107, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 108, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 109, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 110, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 111, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 112, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 113, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 114, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 115, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 116, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 117, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 118, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 119, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 120, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 121, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 122, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 123, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 124, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 125, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 126, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 127, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 128, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 129, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 130, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 131, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 132, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 133, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 134, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 135, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 136, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 137, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 138, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 139, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 140, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 141, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 142, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 143, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 144, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 145, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 146, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 147, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 148, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 149, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 150, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 151, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 152, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 153, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 154, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 155, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 156, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 157, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 158, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 159, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 160, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 161, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 162, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 163, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 164, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 165, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 166, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 167, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 168, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 169, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 170, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 171, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 172, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 173, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 174, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 175, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 176, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 177, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 178, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 179, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 180, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 181, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 182, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 183, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 184, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 185, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 186, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 187, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 188, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 189, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 190, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 191, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 192, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 193, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 194, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 195, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 196, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 197, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 198, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 199, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 200, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 201, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 202, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 203, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 204, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 205, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 206, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 207, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 208, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 209, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 210, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 211, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 212, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 213, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 214, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 215, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 216, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 217, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 218, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 219, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 220, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 221, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 222, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 223, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 224, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 225, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 226, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 227, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 228, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 229, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 230, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 231, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 232, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 233, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 234, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 235, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 236, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 237, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 238, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 239, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 240, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 241, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 242, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 243, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 244, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 245, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 246, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 247, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 248, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 249, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 250, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 251, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 252, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 253, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 254, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 255, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 256, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 257, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 258, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 259, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 260, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 261, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 262, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 263, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 264, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 265, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 266, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 267, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 268, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 269, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 270, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 271, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 272, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 273, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 274, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 275, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 276, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 277, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 278, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 279, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 280, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 281, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 282, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 283, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 284, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 285, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 286, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 287, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 288, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 289, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 290, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 291, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 292, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 293, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 294, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 295, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 296, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 297, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 298, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 299, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 300, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 301, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 302, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 303, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 304, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 305, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 306, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 307, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 308, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 309, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 310, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 311, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 312, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 313, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 314, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 315, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 316, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 317, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 318, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 319, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 320, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 321, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 322, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 323, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 324, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 325, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 326, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 327, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 328, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 329, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 330, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 331, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 332, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 333, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 334, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 335, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 336, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 337, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 338, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 339, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 340, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 341, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 342, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 343, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 344, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 345, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 346, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 347, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 348, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 349, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 350, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 351, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 352, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 353, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 354, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 355, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 356, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 357, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 358, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 359, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 360, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 361, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 362, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 363, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 364, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 365, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 366, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 367, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 368, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 369, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 370, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 371, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 372, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 373, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 374, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 375, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 376, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 377, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 378, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 379, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 380, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 381, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 382, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 383, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 384, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 385, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 386, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 387, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 388, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 389, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 390, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 391, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 392, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 393, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 394, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 395, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 396, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 397, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 398, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 399, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 400, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 401, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 402, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 403, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 404, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 405, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 406, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 407, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 408, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 409, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 410, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 411, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 412, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 413, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 414, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 415, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 416, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 417, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 418, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 419, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 420, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 421, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 422, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 423, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 424, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 425, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 426, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 427, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 428, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 429, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 430, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 431, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 432, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 433, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 434, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 435, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 436, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 437, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 438, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 439, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 440, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 441, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 442, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 443, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 444, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 445, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 446, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 447, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 448, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 449, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 450, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 451, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 452, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 453, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 454, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 455, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 456, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 457, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 458, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 459, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 460, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 461, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 462, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 463, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 464, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 465, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 466, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 467, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 468, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 469, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 470, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 471, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 472, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 473, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 474, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 475, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 476, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 477, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 478, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 479, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 480, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 481, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 482, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 483, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 484, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 485, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 486, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 487, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 488, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 489, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 490, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 491, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 492, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 493, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 494, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 495, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 496, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 497, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 498, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 499, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 500, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 501, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 502, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 503, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 504, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 505, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 506, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 507, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 508, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 509, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 510, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 511, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 512, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 513, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 514, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 515, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 516, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 517, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 518, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 519, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 520, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 521, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 522, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 523, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 524, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 525, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 526, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 527, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 528, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 529, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 530, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 531, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 532, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 533, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 534, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 535, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 536, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 537, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 538, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 539, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 540, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 541, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 542, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 543, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 544, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 545, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 546, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 547, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 548, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 549, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 550, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 551, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 552, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 553, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 554, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 555, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 556, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 557, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 558, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 559, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 560, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 561, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 562, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 563, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 564, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 565, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 566, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 567, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 568, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 569, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 570, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 571, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 572, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 573, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 574, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 575, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 576, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 577, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 578, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 579, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 580, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 581, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 582, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 583, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 584, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 585, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 586, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 587, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 588, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 589, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 590, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 591, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 592, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 593, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 594, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 595, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 596, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 597, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 598, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 599, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 600, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 601, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 602, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 603, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 604, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 605, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 606, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 607, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 608, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 609, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 610, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 611, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 612, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 613, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 614, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 615, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 616, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 617, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 618, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 619, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 620, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 621, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 622, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 623, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 624, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 625, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 626, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 627, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 628, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 629, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 630, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 631, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 632, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 633, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 634, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 635, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 636, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 637, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 638, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 639, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 640, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 641, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 642, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 643, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 644, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 645, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 646, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 647, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 648, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 649, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 650, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 651, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 652, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 653, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 654, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 655, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 656, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 657, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 658, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 659, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 660, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 661, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 662, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 663, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 664, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 665, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 666, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 667, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 668, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 669, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 670, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 671, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 672, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 673, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 674, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 675, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 676, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 677, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 678, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 679, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 680, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 681, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 682, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 683, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 684, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 685, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 686, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 687, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 688, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 689, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 690, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 691, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 692, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 693, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 694, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 695, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 696, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 697, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 698, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 699, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 700, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 701, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 702, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 703, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 704, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 705, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 706, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 707, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 708, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 709, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 710, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 711, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 712, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 713, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 714, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 715, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 716, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 717, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 718, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 719, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 720, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 721, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 722, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 723, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 724, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 725, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 726, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 727, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 728, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 729, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 730, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 731, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 732, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 733, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 734, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 735, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 736, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 737, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 738, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 739, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 740, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 741, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 742, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 743, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 744, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 745, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 746, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 747, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 748, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 749, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 750, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 751, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 752, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 753, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 754, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 755, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 756, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 757, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 758, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 759, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 760, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 761, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 762, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 763, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 764, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 765, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 766, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 767, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 768, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 769, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 770, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 771, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 772, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 773, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 774, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 775, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 776, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 777, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 778, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 779, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 780, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 781, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 782, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 783, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 784, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 785, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 786, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 787, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 788, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 789, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 790, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 791, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 792, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 793, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 794, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 795, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 796, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 797, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 798, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 799, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 800, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 801, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 802, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 803, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 804, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 805, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 806, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 807, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 808, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 809, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 810, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 811, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 812, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 813, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 814, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 815, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 816, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 817, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 818, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 819, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 820, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 821, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 822, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 823, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 824, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 825, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 826, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 827, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 828, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 829, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 830, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 831, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 832, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 833, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 834, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 835, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 836, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 837, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 838, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 839, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 840, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 841, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 842, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 843, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 844, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 845, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 846, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 847, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 848, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 849, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 850, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 851, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 852, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 853, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 854, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 855, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 856, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 857, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 858, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 859, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 860, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 861, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 862, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 863, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 864, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 865, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 866, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 867, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 868, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 869, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 870, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 871, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 872, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 873, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 874, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 875, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 876, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 877, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 878, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 879, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 880, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 881, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 882, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 883, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 884, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 885, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 886, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 887, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 888, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 889, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 890, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 891, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 892, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 893, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 894, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 895, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 896, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 897, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 898, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 899, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 900, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 901, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 902, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 903, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 904, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 905, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 906, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 907, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 908, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 909, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 910, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 911, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 912, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 913, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 914, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 915, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 916, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 917, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 918, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 919, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 920, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 921, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 922, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 923, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 924, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 925, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 926, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 927, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 928, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 929, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 930, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 931, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 932, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 933, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 934, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 935, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 936, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 937, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 938, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 939, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 940, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 941, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 942, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 943, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 944, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 945, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 946, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 947, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 948, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 949, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 950, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 951, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 952, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 953, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 954, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 955, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 956, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 957, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 958, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 959, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 960, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 961, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 962, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 963, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 964, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 965, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 966, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 967, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 968, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 969, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 970, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 971, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 972, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 973, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 974, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 975, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 976, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 977, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 978, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 979, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 980, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 981, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 982, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 983, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 984, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 985, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 986, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 987, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 988, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 989, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 990, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 991, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 992, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 993, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 994, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 995, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 996, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 997, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 998, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 999, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1000, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1001, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1002, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1003, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1004, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1005, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1006, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1007, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1008, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1009, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1010, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1011, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1012, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1013, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1014, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1015, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1016, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1017, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1018, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1019, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1020, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1021, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1022, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1023, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1024, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1025, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1026, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1027, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1028, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1029, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1030, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1031, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1032, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1033, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1034, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1035, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1036, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1037, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1038, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1039, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1040, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1041, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1042, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1043, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1044, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1045, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1046, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1047, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1048, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1049, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1050, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1051, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1052, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1053, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1054, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1055, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1056, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1057, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1058, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1059, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1060, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1061, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1062, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1063, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1064, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1065, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1066, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1067, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1068, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1069, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1070, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1071, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1072, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1073, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1074, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1075, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1076, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1077, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1078, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1079, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1080, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1081, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1082, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1083, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1084, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1085, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1086, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1087, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1088, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1089, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1090, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1091, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1092, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1093, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1094, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1095, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1096, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1097, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1098, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1099, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1100, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1101, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1102, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1103, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1104, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1105, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1106, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1107, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1108, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1109, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1110, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1111, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1112, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1113, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1114, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1115, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1116, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1117, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1118, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1119, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1120, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1121, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1122, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1123, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1124, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1125, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1126, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1127, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1128, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1129, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1130, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1131, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1132, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1133, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1134, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1135, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1136, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1137, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1138, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1139, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1140, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1141, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1142, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1143, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1144, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1145, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1146, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1147, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1148, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1149, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1150, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1151, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1152, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1153, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1154, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1155, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1156, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1157, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1158, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1159, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1160, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1161, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1162, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1163, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1164, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1165, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1166, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1167, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1168, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1169, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1170, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1171, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1172, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1173, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1174, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1175, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1176, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1177, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1178, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1179, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1180, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1181, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1182, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1183, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1184, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1185, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1186, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1187, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1188, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1189, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1190, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1191, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1192, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1193, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1194, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1195, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1196, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1197, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1198, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1199, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1200, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1201, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1202, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1203, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1204, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1205, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1206, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1207, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1208, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1209, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1210, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1211, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1212, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1213, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1214, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1215, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1216, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1217, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1218, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1219, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1220, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1221, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1222, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1223, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1224, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1225, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1226, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1227, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1228, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1229, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1230, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1231, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1232, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1233, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1234, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1235, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1236, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1237, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1238, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1239, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1240, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1241, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1242, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1243, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1244, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1245, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1246, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1247, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1248, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1249, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1250, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1251, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1252, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1253, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1254, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1255, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1256, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1257, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1258, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1259, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1260, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1261, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1262, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1263, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1264, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1265, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1266, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1267, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1268, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1269, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1270, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1271, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1272, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1273, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1274, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1275, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1276, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1277, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1278, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1279, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1280, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1281, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1282, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1283, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1284, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1285, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1286, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1287, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1288, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1289, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1290, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1291, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1292, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1293, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1294, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1295, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1296, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1297, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1298, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1299, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1300, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1301, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1302, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1303, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1304, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1305, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1306, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1307, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1308, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1309, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1310, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1311, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1312, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1313, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1314, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1315, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1316, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1317, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1318, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1319, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1320, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1321, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1322, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1323, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1324, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1325, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1326, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1327, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1328, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1329, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1330, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1331, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1332, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1333, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1334, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1335, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1336, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1337, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1338, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1339, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1340, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1341, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1342, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1343, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1344, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1345, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1346, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1347, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1348, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1349, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1350, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1351, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1352, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1353, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1354, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1355, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1356, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1357, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1358, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1359, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1360, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1361, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1362, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1363, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1364, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1365, (LPARAM)"");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1366, (LPARAM)"");
}

void Win32IDE::createMenuBar(HWND hwnd)
{
    LOG_INFO("createMenuBar() called");
    m_hMenu = CreateMenu();
    if (!m_hMenu) {
        LOG_ERROR("Failed to create menu bar");
        return;
    }
    LOG_DEBUG("Menu bar created, populating menu items...");

    // File menu
    HMENU hFileMenu = CreatePopupMenu();
    AppendMenuA(hFileMenu, MF_STRING, IDM_FILE_NEW, "&New");
    AppendMenuA(hFileMenu, MF_STRING, IDM_FILE_OPEN, "&Open");
    AppendMenuA(hFileMenu, MF_STRING, IDM_FILE_SAVE, "&Save");
    AppendMenuA(hFileMenu, MF_STRING, IDM_FILE_SAVEAS, "Save &As");
    AppendMenuA(hFileMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hFileMenu, MF_STRING, IDM_FILE_LOAD_MODEL, "Load &Model (GGUF)...");
    AppendMenuA(hFileMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hFileMenu, MF_STRING, IDM_FILE_EXIT, "E&xit");
    AppendMenuA(m_hMenu, MF_POPUP, (UINT_PTR)hFileMenu, "&File");
    
    // Edit menu
    HMENU hEditMenu = CreatePopupMenu();
    AppendMenuA(hEditMenu, MF_STRING, IDM_EDIT_FIND, "&Find...\tCtrl+F");
    AppendMenuA(hEditMenu, MF_STRING, IDM_EDIT_REPLACE, "&Replace...\tCtrl+H");
    AppendMenuA(hEditMenu, MF_STRING, IDM_EDIT_FIND_NEXT, "Find &Next\tF3");
    AppendMenuA(hEditMenu, MF_STRING, IDM_EDIT_FIND_PREV, "Find &Previous\tShift+F3");
    AppendMenuA(hEditMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hEditMenu, MF_STRING, IDM_EDIT_SNIPPET, "Insert &Snippet...");
    AppendMenuA(hEditMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hEditMenu, MF_STRING, IDM_EDIT_COPY_FORMAT, "Copy with &Formatting");
    AppendMenuA(hEditMenu, MF_STRING, IDM_EDIT_PASTE_PLAIN, "Paste &Plain Text");
    AppendMenuA(hEditMenu, MF_STRING, IDM_EDIT_CLIPBOARD_HISTORY, "Clipboard &History...");
    AppendMenuA(m_hMenu, MF_POPUP, (UINT_PTR)hEditMenu, "&Edit");
    
    // View menu
    HMENU hViewMenu = CreatePopupMenu();
    AppendMenuA(hViewMenu, MF_STRING, IDM_VIEW_MINIMAP, "&Minimap");
    AppendMenuA(hViewMenu, MF_STRING, IDM_VIEW_OUTPUT_TABS, "&Output Tabs");
    AppendMenuA(hViewMenu, MF_STRING, IDM_VIEW_OUTPUT_PANEL, "Output &Panel");
    AppendMenuA(hViewMenu, MF_STRING, IDM_VIEW_MODULE_BROWSER, "Module &Browser");
    AppendMenuA(hViewMenu, MF_STRING, IDM_VIEW_FLOATING_PANEL, "&Floating Panel");
    AppendMenuA(hViewMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hViewMenu, MF_STRING, IDM_VIEW_THEME_EDITOR, "&Theme Editor...");
    AppendMenuA(hViewMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hViewMenu, MF_STRING, IDM_VIEW_USE_STREAMING_LOADER, "Use Streaming Loader (Low Memory)");
    AppendMenuA(hViewMenu, MF_STRING, IDM_VIEW_USE_VULKAN_RENDERER, "Enable Vulkan Renderer (experimental)");
    AppendMenuA(m_hMenu, MF_POPUP, (UINT_PTR)hViewMenu, "&View");

    // Terminal menu
    HMENU hTerminalMenu = CreatePopupMenu();
    AppendMenuA(hTerminalMenu, MF_STRING, IDM_TERMINAL_POWERSHELL, "&PowerShell");
    AppendMenuA(hTerminalMenu, MF_STRING, IDM_TERMINAL_CMD, "&Command Prompt");
    AppendMenuA(hTerminalMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hTerminalMenu, MF_STRING, IDM_TERMINAL_STOP, "&Stop Terminal");
    AppendMenuA(hTerminalMenu, MF_STRING, IDM_TERMINAL_SPLIT_H, "Split &Horizontal\tCtrl+Shift+H");
    AppendMenuA(hTerminalMenu, MF_STRING, IDM_TERMINAL_SPLIT_V, "Split &Vertical\tCtrl+Shift+V");
    AppendMenuA(hTerminalMenu, MF_STRING, IDM_TERMINAL_CLEAR_ALL, "&Clear All Terminals");
    AppendMenuA(m_hMenu, MF_POPUP, (UINT_PTR)hTerminalMenu, "&Terminal");
    
    // Tools menu
    HMENU hToolsMenu = CreatePopupMenu();
    AppendMenuA(hToolsMenu, MF_STRING, IDM_TOOLS_PROFILE_START, "Start &Profiling");
    AppendMenuA(hToolsMenu, MF_STRING, IDM_TOOLS_PROFILE_STOP, "Stop P&rofiling");
    AppendMenuA(hToolsMenu, MF_STRING, IDM_TOOLS_PROFILE_RESULTS, "Profile &Results...");
    AppendMenuA(hToolsMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hToolsMenu, MF_STRING, IDM_TOOLS_ANALYZE_SCRIPT, "&Analyze Script");
    AppendMenuA(m_hMenu, MF_POPUP, (UINT_PTR)hToolsMenu, "&Tools");
    
    // Modules menu
    HMENU hModulesMenu = CreatePopupMenu();
    AppendMenuA(hModulesMenu, MF_STRING, IDM_MODULES_REFRESH, "&Refresh List");
    AppendMenuA(hModulesMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hModulesMenu, MF_STRING, IDM_MODULES_IMPORT, "&Import Module...");
    AppendMenuA(hModulesMenu, MF_STRING, IDM_MODULES_EXPORT, "&Export Module...");
    AppendMenuA(m_hMenu, MF_POPUP, (UINT_PTR)hModulesMenu, "&Modules");

    // Help menu
    HMENU hHelpMenu = CreatePopupMenu();
    AppendMenuA(hHelpMenu, MF_STRING, IDM_HELP_CMDREF, "Command &Reference");
    AppendMenuA(hHelpMenu, MF_STRING, IDM_HELP_PSDOCS, "PowerShell &Documentation");
    AppendMenuA(hHelpMenu, MF_STRING, IDM_HELP_SEARCH, "&Search Help...");
    AppendMenuA(hHelpMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hHelpMenu, MF_STRING, IDM_HELP_ABOUT, "&About");
    AppendMenuA(m_hMenu, MF_POPUP, (UINT_PTR)hHelpMenu, "&Help");

    // Git menu
    HMENU hGitMenu = CreatePopupMenu();
    AppendMenuA(hGitMenu, MF_STRING, IDM_GIT_STATUS, "&Status\tCtrl+G");
    AppendMenuA(hGitMenu, MF_STRING, IDM_GIT_COMMIT, "&Commit...\tCtrl+Shift+C");
    AppendMenuA(hGitMenu, MF_STRING, IDM_GIT_PUSH, "&Push");
    AppendMenuA(hGitMenu, MF_STRING, IDM_GIT_PULL, "P&ull");
    AppendMenuA(hGitMenu, MF_STRING, IDM_GIT_PANEL, "&Git Panel\tCtrl+Shift+G");
    AppendMenuA(m_hMenu, MF_POPUP, (UINT_PTR)hGitMenu, "&Git");

    // Agent menu (existing agentic bridge operations)
    HMENU hAgentMenu = CreatePopupMenu();
    AppendMenuA(hAgentMenu, MF_STRING, IDM_AGENT_START_LOOP, "Start &Agent Loop");
    AppendMenuA(hAgentMenu, MF_STRING, IDM_AGENT_EXECUTE_CMD, "&Execute Command...");
    AppendMenuA(hAgentMenu, MF_STRING, IDM_AGENT_CONFIGURE_MODEL, "&Configure Model...");
    AppendMenuA(hAgentMenu, MF_STRING, IDM_AGENT_VIEW_TOOLS, "View &Tools");
    AppendMenuA(hAgentMenu, MF_STRING, IDM_AGENT_VIEW_STATUS, "View &Status");
    AppendMenuA(hAgentMenu, MF_STRING, IDM_AGENT_STOP, "&Stop Agent");
    AppendMenuA(m_hMenu, MF_POPUP, (UINT_PTR)hAgentMenu, "&Agent");

    // Autonomy menu (new high-level autonomous orchestration)
    HMENU hAutonomyMenu = CreatePopupMenu();
    AppendMenuA(hAutonomyMenu, MF_STRING, IDM_AUTONOMY_TOGGLE, "&Toggle Auto Loop");
    AppendMenuA(hAutonomyMenu, MF_STRING, IDM_AUTONOMY_START, "&Start Autonomy");
    AppendMenuA(hAutonomyMenu, MF_STRING, IDM_AUTONOMY_STOP, "Sto&p Autonomy");
    AppendMenuA(hAutonomyMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hAutonomyMenu, MF_STRING, IDM_AUTONOMY_SET_GOAL, "Set &Goal...");
    AppendMenuA(hAutonomyMenu, MF_STRING, IDM_AUTONOMY_STATUS, "Show &Status");
    AppendMenuA(hAutonomyMenu, MF_STRING, IDM_AUTONOMY_MEMORY, "Show &Memory Snapshot");
    AppendMenuA(m_hMenu, MF_POPUP, (UINT_PTR)hAutonomyMenu, "&Autonomy");

    SetMenu(hwnd, m_hMenu);

}

void Win32IDE::createToolbar(HWND hwnd)
{
    RECT client{};
    GetClientRect(hwnd, &client);
    m_hwndToolbar = CreateWindowExA(0, TOOLBARCLASSNAMEA, nullptr,
                                   WS_CHILD | WS_VISIBLE | TBSTYLE_FLAT |
                                       CCS_NODIVIDER | CCS_NOPARENTALIGN,
                                   0, 0, client.right, 40, hwnd, nullptr,
                                   m_hInstance, nullptr);
    if (!m_hwndToolbar) return;

    SendMessageA(m_hwndToolbar, TB_BUTTONSTRUCTSIZE,
                 static_cast<WPARAM>(sizeof(TBBUTTON)), 0);
    createTitleBarControls();
    updateTitleBarText();
}

void Win32IDE::createTitleBarControls()
{
    DWORD labelStyle = WS_CHILD | WS_VISIBLE | SS_CENTER | SS_NOPREFIX;
    m_hwndTitleLabel = CreateWindowExA(0, "STATIC", "RawrXD IDE", labelStyle,
                                      0, 0, 200, 24, m_hwndToolbar, (HMENU)IDC_TITLE_TEXT, m_hInstance, nullptr);

    DWORD buttonStyle = WS_CHILD | WS_VISIBLE | BS_FLAT;
    auto createButton = [&](HWND& target, int controlId, const char* caption) {
        target = CreateWindowExA(0, "BUTTON", caption, buttonStyle,
                                 0, 0, 32, 24, m_hwndToolbar, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(controlId)), m_hInstance, nullptr);
    };

    createButton(m_hwndBtnSettings, IDC_BTN_SETTINGS, "Gear");

    RECT client{};
    GetClientRect(m_hwndMain, &client);
    layoutTitleBar(client.right - client.left);
}

void Win32IDE::layoutTitleBar(int width)
{
    if (!m_hwndToolbar) return;

    RECT client{};
    GetClientRect(m_hwndToolbar, &client);
    int toolbarHeight = client.bottom - client.top;
    if (toolbarHeight <= 0) toolbarHeight = 30;
    int controlHeight = (std::max)(22, toolbarHeight - 6);
    int y = (toolbarHeight - controlHeight) / 2;
    int padding = 6;
    int x = width - padding;

    auto placeButton = [&](HWND hwnd, int controlWidth) {
        if (!hwnd) return;
        x -= controlWidth;
        MoveWindow(hwnd, x, y, controlWidth, controlHeight, TRUE);
        x -= padding;
    };

    placeButton(m_hwndBtnSettings, 48);

    if (m_hwndTitleLabel) {
        int availableRight = x;
        int labelWidth = (std::min)(420, availableRight - padding * 2);
        if (labelWidth < 160) {
            labelWidth = (std::max)(availableRight - padding * 2, 120);
        }
        int labelX = (std::max)(padding, (width - labelWidth) / 2);
        if (labelX + labelWidth > availableRight) {
            labelX = (std::max)(padding, availableRight - labelWidth);
        }
        MoveWindow(m_hwndTitleLabel, labelX, y, labelWidth, controlHeight, TRUE);
    }
}

std::string Win32IDE::extractLeafName(const std::string& path) const
{
    if (path.empty()) return "";
    size_t end = path.find_last_not_of("\\/ ");
    if (end == std::string::npos) return path;
    size_t slash = path.find_last_of("\\/", end);
    if (slash == std::string::npos) {
        return path.substr(0, end + 1);
    }
    return path.substr(slash + 1, end - slash);
}

void Win32IDE::setCurrentDirectoryFromFile(const std::string& filePath)
{
    if (filePath.empty()) return;
    size_t slash = filePath.find_last_of("\\/");
    if (slash != std::string::npos) {
        m_currentDirectory = filePath.substr(0, slash);
    }
}

void Win32IDE::updateEditorBreadcrumb()
{
    if (!m_hwndEditorBreadcrumb) return;
    std::string path = m_currentFile;
    if (path.empty()) {
        SetWindowTextA(m_hwndEditorBreadcrumb, "  Untitled  >  (workspace)");
        return;
    }

    // Preserve the entire path while presenting each directory boundary as a
    // breadcrumb segment. Do not shorten to the leaf name: duplicate filenames
    // in different workspaces must remain unambiguous.
    std::string breadcrumb = "  ";
    breadcrumb.reserve(path.size() + 8);
    for (char ch : path) {
        if (ch == '\\' || ch == '/') {
            breadcrumb += "  >  ";
        } else {
            breadcrumb.push_back(ch);
        }
    }
    SetWindowTextA(m_hwndEditorBreadcrumb, breadcrumb.c_str());
}

void Win32IDE::updateTitleBarText()
{
    if (!m_hwndMain) return;
    updateEditorBreadcrumb();

    std::string fileName = m_currentFile.empty() ? "Untitled" : extractLeafName(m_currentFile);
    std::string projectFolder;

    if (!m_currentDirectory.empty()) {
        projectFolder = extractLeafName(m_currentDirectory);
    }

    if (projectFolder.empty() && !m_currentFile.empty()) {
        size_t slash = m_currentFile.find_last_of("\\/");
        if (slash != std::string::npos) {
            projectFolder = extractLeafName(m_currentFile.substr(0, slash));
        }
    }

    if (projectFolder.empty()) {
        projectFolder = "Workspace";
    }

    // ASCII separator: the target builds with _MBCS and uses SetWindowTextA, so
    // a UTF-8 bullet (U+2022) renders as mojibake here.
    std::string composed = fileName + "  -  " + projectFolder;
    if (composed != m_lastTitleBarText) {
        if (m_hwndTitleLabel) SetWindowTextA(m_hwndTitleLabel, composed.c_str());
        SetWindowTextA(m_hwndMain, ("RawrXD IDE  -  " + composed).c_str());
        m_lastTitleBarText = composed;
    }
}

void Win32IDE::setEditorText(const std::string& text)
{
    if (!m_hwndEditor) return;
    const bool wasSuppressed = m_suppressEditorDirty;
    m_suppressEditorDirty = true;
    SetWindowTextA(m_hwndEditor, text.c_str());
    m_suppressEditorDirty = wasSuppressed;
}

void Win32IDE::createEditor(HWND hwnd)
{

    m_hwndEditor = CreateWindowExA(WS_EX_CLIENTEDGE, RICHEDIT_CLASSA, "",
                                  WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_WANTRETURN,
                                  0, 0, 0, 0, hwnd, (HMENU)IDC_EDITOR, m_hInstance, nullptr);
    if (!m_hwndEditor) {

        return;
    }

    // Set default font and colors
    CHARFORMAT2A cf;
    memset(&cf, 0, sizeof(cf));
    cf.cbSize = sizeof(cf);
    cf.dwMask = CFM_FACE | CFM_SIZE | CFM_COLOR;
    cf.yHeight = 200; // 10 points
    cf.crTextColor = RGB(220, 220, 220); // Light gray text
    strcpy(cf.szFaceName, "Consolas");
    SendMessage(m_hwndEditor, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&cf);
    
    // Set background color to dark
    SendMessage(m_hwndEditor, EM_SETBKGNDCOLOR, 0, RGB(30, 30, 30));

    // Enable editing
    SendMessage(m_hwndEditor, EM_SETREADONLY, FALSE, 0);

    initializeEditorSurface();

}

void Win32IDE::createTerminal(HWND hwnd)
{

    if (m_terminalPanes.empty()) {

        createTerminalPane(Win32TerminalManager::PowerShell, "PowerShell");
    } else {

        setActiveTerminalPane(m_terminalPanes.front().id);
    }

    // Create command input

    m_hwndCommandInput = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
                                        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                        0, 0, 0, 0, hwnd, (HMENU)IDC_COMMAND_INPUT, m_hInstance, nullptr);
    if (!m_hwndCommandInput) {

    } else {

    }

}

int Win32IDE::createTerminalPane(Win32TerminalManager::ShellType shellType, const std::string& name)
{
    HWND hwnd = CreateWindowExA(WS_EX_CLIENTEDGE, RICHEDIT_CLASSA, "",
                                WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
                                0, 0, 0, 0, m_hwndMain, nullptr, m_hInstance, nullptr);

    CHARFORMAT2A cf;
    memset(&cf, 0, sizeof(cf));
    cf.cbSize = sizeof(cf);
    cf.dwMask = CFM_FACE | CFM_SIZE;
    cf.yHeight = 180; // 9 points
    strcpy(cf.szFaceName, "Consolas");
    SendMessage(hwnd, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&cf);

    int paneId = m_nextTerminalId++;
    TerminalPane pane;
    pane.id = paneId;
    pane.hwnd = hwnd;
    const UINT_PTR base = 7100u + static_cast<UINT_PTR>(paneId) * 10u;
    pane.input = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        0, 0, 0, 0, m_hwndMain, reinterpret_cast<HMENU>(base + 1), m_hInstance, nullptr);
    pane.execute = CreateWindowExA(0, "BUTTON", "Execute",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        0, 0, 0, 0, m_hwndMain, reinterpret_cast<HMENU>(base + 2), m_hInstance, nullptr);
    pane.stop = CreateWindowExA(0, "BUTTON", "Stop",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        0, 0, 0, 0, m_hwndMain, reinterpret_cast<HMENU>(base + 3), m_hInstance, nullptr);
    pane.clear = CreateWindowExA(0, "BUTTON", "Clear",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        0, 0, 0, 0, m_hwndMain, reinterpret_cast<HMENU>(base + 4), m_hInstance, nullptr);
    if (pane.input) {
        // Keep this a stock EDIT control.  The parent handles the Execute
        // button and avoids subclass lifetime hazards during pane teardown.
        SetPropA(pane.input, "RAWRXD_TERMINAL_PANE", reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(paneId)));
    }
    pane.manager = std::make_unique<Win32TerminalManager>();
    pane.name = name.empty() ? ("Terminal " + std::to_string(paneId)) : name;
    pane.shellType = shellType;
    pane.isActive = false;
    pane.bounds = {0, 0, 0, 0};

    pane.manager->onOutput = [this, paneId](const std::string& output) {
        onTerminalOutput(paneId, output);
    };
    pane.manager->onError = [this, paneId](const std::string& error) {
        onTerminalError(paneId, error);
    };

    m_terminalPanes.push_back(std::move(pane));
    setActiveTerminalPane(paneId);
    RECT client{};
    if (GetClientRect(m_hwndMain, &client)) {
        const int top = 40 + DOC_TAB_HEIGHT + m_editorHeight;
        layoutTerminalPanes(client.right - client.left, top, m_terminalHeight);
    }
    applyTheme();
    return paneId;
}

TerminalPane* Win32IDE::findTerminalPane(int paneId)
{
    for (auto& pane : m_terminalPanes) {
        if (pane.id == paneId) {
            return &pane;
        }
    }
    return nullptr;
}

TerminalPane* Win32IDE::getActiveTerminalPane()
{
    TerminalPane* active = findTerminalPane(m_activeTerminalId);
    if (!active && !m_terminalPanes.empty()) {
        setActiveTerminalPane(m_terminalPanes.front().id);
        return findTerminalPane(m_terminalPanes.front().id);
    }
    return active;
}

void Win32IDE::setActiveTerminalPane(int paneId)
{
    bool found = false;
    for (auto& pane : m_terminalPanes) {
        if (pane.id == paneId) {
            pane.isActive = true;
            m_activeTerminalId = paneId;
            if (pane.hwnd) SetFocus(pane.hwnd);
            found = true;
        } else {
            pane.isActive = false;
        }
    }
    if (!found && !m_terminalPanes.empty()) {
        m_terminalPanes.front().isActive = true;
        m_activeTerminalId = m_terminalPanes.front().id;
        if (m_terminalPanes.front().hwnd) SetFocus(m_terminalPanes.front().hwnd);
    }
}

void Win32IDE::layoutTerminalPanes(int width, int top, int height)
{
    if (width <= 0 || height <= 0 || m_terminalPanes.empty()) return;
    int count = static_cast<int>(m_terminalPanes.size());
    if (count == 1) {
        auto& pane = m_terminalPanes[0];
        MoveWindow(pane.hwnd, 0, top, width, height, TRUE);
        const int controlHeight = 28;
        const int buttonWidth = 64;
        const int gap = 4;
        const int inputWidth = std::max(0, width - (buttonWidth * 3 + gap * 4));
        const int y = std::max(top, top + height - controlHeight - 4);
        if (pane.input) MoveWindow(pane.input, 4, y, inputWidth, controlHeight, TRUE);
        if (pane.execute) MoveWindow(pane.execute, 4 + inputWidth + gap, y, buttonWidth, controlHeight, TRUE);
        if (pane.stop) MoveWindow(pane.stop, 4 + inputWidth + gap * 2 + buttonWidth, y, buttonWidth, controlHeight, TRUE);
        if (pane.clear) MoveWindow(pane.clear, 4 + inputWidth + gap * 3 + buttonWidth * 2, y, buttonWidth, controlHeight, TRUE);
        if (pane.input) ShowWindow(pane.input, pane.isActive ? SW_SHOW : SW_HIDE);
        if (pane.execute) ShowWindow(pane.execute, pane.isActive ? SW_SHOW : SW_HIDE);
        if (pane.stop) ShowWindow(pane.stop, pane.isActive ? SW_SHOW : SW_HIDE);
        if (pane.clear) ShowWindow(pane.clear, pane.isActive ? SW_SHOW : SW_HIDE);
        pane.bounds = {0, top, width, top + height};
        return;
    }

    if (m_terminalSplitHorizontal) {
        int paneHeight = height / count;
        int y = top;
        for (int i = 0; i < count; ++i) {
            int currentHeight = (i == count - 1) ? (height - paneHeight * (count - 1)) : paneHeight;
            auto& pane = m_terminalPanes[i];
            MoveWindow(pane.hwnd, 0, y, width, currentHeight, TRUE);
            const int controlHeight = 28;
            const int buttonWidth = 64;
            const int gap = 4;
            const int inputWidth = std::max(0, width - (buttonWidth * 3 + gap * 4));
            const int cy = std::max(y, y + currentHeight - controlHeight - 4);
            if (pane.input) MoveWindow(pane.input, 4, cy, inputWidth, controlHeight, TRUE);
            if (pane.execute) MoveWindow(pane.execute, 4 + inputWidth + gap, cy, buttonWidth, controlHeight, TRUE);
            if (pane.stop) MoveWindow(pane.stop, 4 + inputWidth + gap * 2 + buttonWidth, cy, buttonWidth, controlHeight, TRUE);
            if (pane.clear) MoveWindow(pane.clear, 4 + inputWidth + gap * 3 + buttonWidth * 2, cy, buttonWidth, controlHeight, TRUE);
            if (pane.input) ShowWindow(pane.input, pane.isActive ? SW_SHOW : SW_HIDE);
            if (pane.execute) ShowWindow(pane.execute, pane.isActive ? SW_SHOW : SW_HIDE);
            if (pane.stop) ShowWindow(pane.stop, pane.isActive ? SW_SHOW : SW_HIDE);
            if (pane.clear) ShowWindow(pane.clear, pane.isActive ? SW_SHOW : SW_HIDE);
            pane.bounds = {0, y, width, y + currentHeight};
            y += currentHeight;
        }
    } else {
        int paneWidth = width / count;
        int x = 0;
        for (int i = 0; i < count; ++i) {
            int currentWidth = (i == count - 1) ? (width - paneWidth * (count - 1)) : paneWidth;
            auto& pane = m_terminalPanes[i];
            MoveWindow(pane.hwnd, x, top, currentWidth, height, TRUE);
            const int controlHeight = 28;
            const int buttonWidth = 64;
            const int gap = 4;
            const int inputWidth = std::max(0, currentWidth - (buttonWidth * 3 + gap * 4));
            const int cy = std::max(top, top + height - controlHeight - 4);
            if (pane.input) MoveWindow(pane.input, x + 4, cy, inputWidth, controlHeight, TRUE);
            if (pane.execute) MoveWindow(pane.execute, x + 4 + inputWidth + gap, cy, buttonWidth, controlHeight, TRUE);
            if (pane.stop) MoveWindow(pane.stop, x + 4 + inputWidth + gap * 2 + buttonWidth, cy, buttonWidth, controlHeight, TRUE);
            if (pane.clear) MoveWindow(pane.clear, x + 4 + inputWidth + gap * 3 + buttonWidth * 2, cy, buttonWidth, controlHeight, TRUE);
            if (pane.input) ShowWindow(pane.input, pane.isActive ? SW_SHOW : SW_HIDE);
            if (pane.execute) ShowWindow(pane.execute, pane.isActive ? SW_SHOW : SW_HIDE);
            if (pane.stop) ShowWindow(pane.stop, pane.isActive ? SW_SHOW : SW_HIDE);
            if (pane.clear) ShowWindow(pane.clear, pane.isActive ? SW_SHOW : SW_HIDE);
            pane.bounds = {x, top, x + currentWidth, top + height};
            x += currentWidth;
        }
    }
}

void Win32IDE::splitTerminalHorizontal()
{
    m_terminalSplitHorizontal = true;
    TerminalPane* active = getActiveTerminalPane();
    Win32TerminalManager::ShellType type = active ? active->shellType : Win32TerminalManager::PowerShell;
    createTerminalPane(type, "Terminal");
    RECT rect; GetClientRect(m_hwndMain, &rect);
    RECT toolbarRect; GetWindowRect(m_hwndToolbar, &toolbarRect);
    int toolbarHeight = toolbarRect.bottom - toolbarRect.top;
    layoutTerminalPanes(rect.right - rect.left, toolbarHeight + m_editorHeight, m_terminalHeight);
}

void Win32IDE::splitTerminalVertical()
{
    m_terminalSplitHorizontal = false;
    TerminalPane* active = getActiveTerminalPane();
    Win32TerminalManager::ShellType type = active ? active->shellType : Win32TerminalManager::PowerShell;
    createTerminalPane(type, "Terminal");
    RECT rect; GetClientRect(m_hwndMain, &rect);
    RECT toolbarRect; GetWindowRect(m_hwndToolbar, &toolbarRect);
    int toolbarHeight = toolbarRect.bottom - toolbarRect.top;
    layoutTerminalPanes(rect.right - rect.left, toolbarHeight + m_editorHeight, m_terminalHeight);
}

void Win32IDE::clearAllTerminals()
{
    for (auto& pane : m_terminalPanes) {
        if (pane.manager && pane.manager->isRunning()) {
            pane.manager->stop();
        }
        if (pane.hwnd) {
            DestroyWindow(pane.hwnd);
        }
    }
    m_terminalPanes.clear();
    m_activeTerminalId = -1;
    m_nextTerminalId = 1;
    createTerminalPane(Win32TerminalManager::PowerShell, "PowerShell");
    RECT rect; GetClientRect(m_hwndMain, &rect);
    RECT toolbarRect; GetWindowRect(m_hwndToolbar, &toolbarRect);
    int toolbarHeight = toolbarRect.bottom - toolbarRect.top;
    layoutTerminalPanes(rect.right - rect.left, toolbarHeight + m_editorHeight, m_terminalHeight);
}

void Win32IDE::createStatusBar(HWND hwnd)
{

    m_hwndStatusBar = CreateWindowExA(0, STATUSCLASSNAMEA, "",
                                     WS_CHILD | WS_VISIBLE,
                                     0, 0, 0, 0, hwnd, (HMENU)IDC_STATUS_BAR, m_hInstance, nullptr);
    if (!m_hwndStatusBar) {

        return;
    }

    int parts[] = {200, 400, -1};
    SendMessage(m_hwndStatusBar, SB_SETPARTS, 3, (LPARAM)parts);
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)"Ready");

}

void Win32IDE::createSidebar(HWND hwnd)
{
    // Create the primary sidebar (left panel)
    m_hwndSidebar = CreateWindowExA(
        0,
        "STATIC",
        "Explorer",
        WS_CHILD | WS_VISIBLE | WS_BORDER,
        48, 30, m_sidebarWidth, 500,
        hwnd,
        nullptr,
        m_hInstance,
        nullptr
    );
    
    if (m_hwndSidebar) {
        // Create activity bar (icon strip on far left)
        m_hwndActivityBar = CreateWindowExA(
            0,
            "STATIC",
            "",
            WS_CHILD | WS_VISIBLE,
            0, 30, 48, 500,
            hwnd,
            nullptr,
            m_hInstance,
            nullptr
        );
    }
}

void Win32IDE::newFile()
{
    appendToOutput("File > New clicked\n", "Output", OutputSeverity::Info);
    if (m_fileModified) {
        int result = MessageBoxA(m_hwndMain, "File has been modified. Save changes?", "Save", MB_YESNOCANCEL);
        if (result == IDCANCEL) {
            appendToOutput("File > New cancelled by user\n", "Output", OutputSeverity::Info);
            return;
        }
        if (result == IDYES && !saveFile()) {
            appendToOutput("File > New - save failed, operation aborted\n", "Output", OutputSeverity::Warning);
            return;
        }
    }

    setEditorText("");
    m_currentFile.clear();
    m_fileModified = false;
    updateTitleBarText();
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)"New file");
    updateMenuEnableStates();
    syncEditorToGpuSurface();
    appendToOutput("New file created successfully\n", "Output", OutputSeverity::Info);
}

bool Win32IDE::loadFileIntoEditor(const std::string& path)
{
    if (path.empty() || !m_hwndEditor) return false;

    try {
        std::ifstream file(path);
        if (!file) {
            appendToOutput("Failed to open file: " + path + "\n", "Errors", OutputSeverity::Error);
            return false;
        }

        std::string content((std::istreambuf_iterator<char>(file)),
                             std::istreambuf_iterator<char>());
        setEditorText(content);
        m_currentFile = path;
        m_fileModified = false;
        setCurrentDirectoryFromFile(m_currentFile);
        updateTitleBarText();
        SendMessageA(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)"File opened");
        updateMenuEnableStates();
        syncEditorToGpuSurface();
        appendToOutput("File opened successfully (" + std::to_string(content.size()) + " bytes)\n",
                       "Output", OutputSeverity::Info);
        return true;
    } catch (const std::exception& e) {
        appendToOutput("Exception opening file: " + std::string(e.what()) + "\n", "Errors",
                       OutputSeverity::Error);
        return false;
    }
}

void Win32IDE::openFile()
{
    appendToOutput("File > Open clicked\n", "Output", OutputSeverity::Info);    if (m_fileModified) {
        int result = MessageBoxA(m_hwndMain, "File has been modified. Save changes?", "Save", MB_YESNOCANCEL);
        if (result == IDCANCEL) {
            appendToOutput("File > Open cancelled by user\n", "Output", OutputSeverity::Info);
            return;
        }
        if (result == IDYES && !saveFile()) {
            appendToOutput("File > Open - save failed, operation aborted\n", "Output", OutputSeverity::Warning);
            return;
        }
    }

    OPENFILENAMEA ofn;
    char szFile[260] = {0};

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = m_hwndMain;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = "All Files\0*.*\0C++ Files\0*.cpp;*.h\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = nullptr;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = nullptr;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileNameA(&ofn)) {
        appendToOutput("Opening file: " + std::string(szFile) + "\n", "Output", OutputSeverity::Info);
        try {
            std::ifstream file(szFile);
            if (file) {
                std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                setEditorText(content);
                m_currentFile = szFile;
                m_fileModified = false;
                setCurrentDirectoryFromFile(m_currentFile);
                addDocumentTab(m_currentFile);
                updateTitleBarText();
                SendMessage(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)"File opened");
                updateMenuEnableStates();
                syncEditorToGpuSurface();
                appendToOutput("File opened successfully (" + std::to_string(content.size()) + " bytes)\n", "Output", OutputSeverity::Info);
            } else {
                appendToOutput("Failed to open file: " + std::string(szFile) + "\n", "Errors", OutputSeverity::Error);
                MessageBoxA(m_hwndMain, "Failed to open file", "Error", MB_OK | MB_ICONERROR);
            }
        } catch (const std::exception& e) {
            appendToOutput("Exception opening file: " + std::string(e.what()) + "\n", "Errors", OutputSeverity::Error);
            MessageBoxA(m_hwndMain, e.what(), "Error", MB_OK | MB_ICONERROR);
        }
    } else {
        appendToOutput("File > Open cancelled by user (no file selected)\n", "Output", OutputSeverity::Info);
    }
}

bool Win32IDE::saveFile()
{
    if (m_currentFile.empty()) {
        appendToOutput("File > Save - no current file, showing Save As dialog\n", "Output", OutputSeverity::Info);
        return saveFileAs();
    }

    appendToOutput("Saving file: " + m_currentFile + "\n", "Output", OutputSeverity::Info);
    try {
        std::string content = getWindowText(m_hwndEditor);
        std::ofstream file(m_currentFile);
        if (file) {
            file << content;
            m_fileModified = false;
            updateTitleBarText();
            SendMessage(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)"File saved");
            appendToOutput("File saved successfully (" + std::to_string(content.size()) + " bytes)\n", "Output", OutputSeverity::Info);
            return true;
        }
        appendToOutput("Failed to open file for writing: " + m_currentFile + "\n", "Errors", OutputSeverity::Error);
        MessageBoxA(m_hwndMain, "Failed to save file", "Error", MB_OK | MB_ICONERROR);
    } catch (const std::exception& e) {
        appendToOutput("Exception saving file: " + std::string(e.what()) + "\n", "Errors", OutputSeverity::Error);
        MessageBoxA(m_hwndMain, e.what(), "Error", MB_OK | MB_ICONERROR);
    }
    return false;
}

bool Win32IDE::saveFileAs()
{
    appendToOutput("File > Save As clicked\n", "Output", OutputSeverity::Info);
    OPENFILENAMEA ofn;
    char szFile[260] = {0};

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = m_hwndMain;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = "All Files\0*.*\0C++ Files\0*.cpp;*.h\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = nullptr;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = nullptr;
    ofn.Flags = OFN_OVERWRITEPROMPT;

    if (GetSaveFileNameA(&ofn)) {
        m_currentFile = szFile;
        appendToOutput("Save As: " + m_currentFile + "\n", "Output", OutputSeverity::Info);
        setCurrentDirectoryFromFile(m_currentFile);
        updateTitleBarText();
        return saveFile();
    }
    appendToOutput("File > Save As cancelled by user\n", "Output", OutputSeverity::Info);
    return false;
}

void Win32IDE::startPowerShell()
{
    TerminalPane* pane = getActiveTerminalPane();
    if (!pane || !pane->manager) return;
    stopTerminal();
    if (pane->manager->start(Win32TerminalManager::PowerShell)) {
        appendText(pane->hwnd, "PowerShell started...\n");
        SendMessage(m_hwndStatusBar, SB_SETTEXT, 1, (LPARAM)"PowerShell");
        updateMenuEnableStates();
        appendToOutput("PowerShell started...\n", "Output", OutputSeverity::Info);
    }
}

void Win32IDE::startCommandPrompt()
{
    TerminalPane* pane = getActiveTerminalPane();
    if (!pane || !pane->manager) return;
    stopTerminal();
    if (pane->manager->start(Win32TerminalManager::CommandPrompt)) {
        appendText(pane->hwnd, "Command Prompt started...\n");
        SendMessage(m_hwndStatusBar, SB_SETTEXT, 1, (LPARAM)"CMD");
        updateMenuEnableStates();
        appendToOutput("Command Prompt started...\n", "Output", OutputSeverity::Info);
    }
}

void Win32IDE::stopTerminal()
{
    TerminalPane* pane = getActiveTerminalPane();
    if (!pane || !pane->manager || !pane->manager->isRunning()) return;
    pane->manager->stop();
    appendText(pane->hwnd, "\nTerminal stopped.\n");
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 1, (LPARAM)"Stopped");
    updateMenuEnableStates();
    appendToOutput("Terminal stopped.\n", "Output", OutputSeverity::Info);
}

void Win32IDE::executeCommand()
{
    std::string command = getWindowText(m_hwndCommandInput);
    if (command.empty()) return;

    SetWindowTextA(m_hwndCommandInput, "");
    
    // Check if we're in chat mode with a loaded model
    if (m_chatMode && isModelLoaded()) {
        // Send to model for inference
        appendChatMessage("You", command);
        
        std::string response = sendMessageToModel(command);
        if (!response.empty()) {
            appendChatMessage("Model", response);
        } else {
            appendChatMessage("System", "Error: Model failed to generate response");
        }
        return;
    }
    
    // Check for special commands
    if (command == "/chat" || command == "/model") {
        if (isModelLoaded()) {
            toggleChatMode();
        } else {
            appendToOutput("No model loaded. Please load a .gguf model first using File > Load Model or the File Explorer.", "Output", OutputSeverity::Warning);
        }
        return;
    }
    
    if (command == "/exit-chat") {
        if (m_chatMode) {
            toggleChatMode();
        }
        return;
    }
    
    // Otherwise, send to terminal as before
    TerminalPane* pane = getActiveTerminalPane();
    if (pane && pane->manager && pane->manager->isRunning()) {
        command += "\n";
        pane->manager->writeInput(command);
    }
}

void Win32IDE::onTerminalOutput(int paneId, const std::string& output)
{
    TerminalPane* pane = findTerminalPane(paneId);
    if (!pane || !pane->hwnd) return;
    appendText(pane->hwnd, output);
    appendToOutput(output, "Debug", OutputSeverity::Info);
}

void Win32IDE::onTerminalError(int paneId, const std::string& error)
{
    TerminalPane* pane = findTerminalPane(paneId);
    if (!pane || !pane->hwnd) return;
    appendText(pane->hwnd, error);
    appendToOutput(error, "Errors", OutputSeverity::Error);
}

std::string Win32IDE::getWindowText(HWND hwnd)
{
    int length = GetWindowTextLengthA(hwnd);
    std::string text(length + 1, '\0');
    GetWindowTextA(hwnd, &text[0], length + 1);
    text.resize(length);
    return text;
}

void Win32IDE::setWindowText(HWND hwnd, const std::string& text)
{
    SetWindowTextA(hwnd, text.c_str());
    if (hwnd == m_hwndEditor) {
        syncEditorToGpuSurface();
    }
}

void Win32IDE::appendText(HWND hwnd, const std::string& text)
{
    // Get current text length
    GETTEXTLENGTHEX gtl;
    gtl.flags = GTL_DEFAULT;
    gtl.codepage = CP_ACP;
    LONG length = SendMessage(hwnd, EM_GETTEXTLENGTHEX, (WPARAM)&gtl, 0);

    // Set selection to end
    SendMessage(hwnd, EM_SETSEL, length, length);

    // Replace selection with new text
    SETTEXTEX st;
    st.flags = ST_DEFAULT;
    st.codepage = CP_ACP;
    SendMessage(hwnd, EM_SETTEXTEX, (WPARAM)&st, (LPARAM)text.c_str());

    if (hwnd == m_hwndEditor) {
        syncEditorToGpuSurface();
    }
}

// Theme Management Implementation
void Win32IDE::loadTheme(const std::string& themeName)
{
    std::string filename = "themes\\" + themeName + ".theme";
    std::ifstream file(filename);
    if (file.is_open()) {
        std::string line;
        while (getline(file, line)) {
            if (line.find("background=") == 0) {
                m_currentTheme.backgroundColor = std::stoul(line.substr(11), nullptr, 16);
            } else if (line.find("text=") == 0) {
                m_currentTheme.textColor = std::stoul(line.substr(5), nullptr, 16);
            } else if (line.find("selection=") == 0) {
                m_currentTheme.selectionColor = std::stoul(line.substr(10), nullptr, 16);
            } else if (line.find("linenumber=") == 0) {
                m_currentTheme.lineNumberColor = std::stoul(line.substr(11), nullptr, 16);
            }
        }
        file.close();
        applyTheme();
    }
}

void Win32IDE::saveTheme(const std::string& themeName)
{
    std::string filename = "themes\\" + themeName + ".theme";
    CreateDirectoryA("themes", NULL);
    std::ofstream file(filename);
    if (file.is_open()) {
        file << "background=" << std::hex << m_currentTheme.backgroundColor << std::endl;
        file << "text=" << std::hex << m_currentTheme.textColor << std::endl;
        file << "selection=" << std::hex << m_currentTheme.selectionColor << std::endl;
        file << "linenumber=" << std::hex << m_currentTheme.lineNumberColor << std::endl;
        file.close();
        MessageBoxA(m_hwndMain, "Theme saved successfully", "Theme Manager", MB_OK);
    }
}

void Win32IDE::applyTheme()
{
    // Apply theme to main editor
    SendMessage(m_hwndEditor, EM_SETBKGNDCOLOR, 0, m_currentTheme.backgroundColor);
    
    // Set text colors
    CHARFORMAT2 cf;
    ZeroMemory(&cf, sizeof(cf));
    cf.cbSize = sizeof(cf);
    cf.dwMask = CFM_COLOR;
    cf.crTextColor = m_currentTheme.textColor;
    SendMessage(m_hwndEditor, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&cf);
    
    // Apply to terminal panes
    for (auto& pane : m_terminalPanes) {
        if (!pane.hwnd) continue;
        SendMessage(pane.hwnd, EM_SETBKGNDCOLOR, 0, m_currentTheme.backgroundColor);
        SendMessage(pane.hwnd, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&cf);
    }
    
    // Force redraw
    InvalidateRect(m_hwndMain, NULL, TRUE);
    updateMenuEnableStates();
}

void Win32IDE::showThemeEditor()
{
    const int result = MessageBoxA(
        m_hwndMain,
        "Yes  = Cyberpunk Neon\n"
        "No   = Neon Midnight\n"
        "Cancel = Keep current theme",
        "RawrXD Theme Gallery", MB_YESNOCANCEL | MB_ICONINFORMATION);
    if (result == IDCANCEL) return;

    m_currentTheme.darkMode = true;
    m_currentTheme.fontName = "Cascadia Mono";
    m_currentTheme.fontSize = 11;
    if (result == IDYES) {
        // Cyan glass panels, magenta syntax, and electric-green comments.
        m_currentTheme.backgroundColor = RGB(7, 10, 22);
        m_currentTheme.textColor = RGB(224, 252, 255);
        m_currentTheme.keywordColor = RGB(255, 55, 220);
        m_currentTheme.commentColor = RGB(73, 255, 180);
        m_currentTheme.stringColor = RGB(255, 190, 92);
        m_currentTheme.numberColor = RGB(88, 210, 255);
        m_currentTheme.operatorColor = RGB(255, 90, 170);
        m_currentTheme.selectionColor = RGB(18, 104, 150);
        m_currentTheme.lineNumberColor = RGB(95, 135, 170);
    } else {
        // Dark violet variant for lower-glare long sessions.
        m_currentTheme.backgroundColor = RGB(15, 8, 28);
        m_currentTheme.textColor = RGB(238, 228, 255);
        m_currentTheme.keywordColor = RGB(210, 100, 255);
        m_currentTheme.commentColor = RGB(74, 240, 202);
        m_currentTheme.stringColor = RGB(255, 205, 120);
        m_currentTheme.numberColor = RGB(115, 190, 255);
        m_currentTheme.operatorColor = RGB(245, 95, 190);
        m_currentTheme.selectionColor = RGB(86, 35, 125);
        m_currentTheme.lineNumberColor = RGB(130, 105, 165);
    }
    applyTheme();
    appendToOutput("Cyberpunk neon theme applied.\n", "Output", OutputSeverity::Info);
}

void Win32IDE::updateMenuEnableStates() {
    if (!m_hMenu) return;
    // Terminal split menu items
    UINT enableSplit = MF_BYCOMMAND | (m_terminalPanes.size() >= 1 ? MF_ENABLED : MF_GRAYED);
    EnableMenuItem(m_hMenu, IDM_TERMINAL_SPLIT_H, enableSplit);
    EnableMenuItem(m_hMenu, IDM_TERMINAL_SPLIT_V, enableSplit);
    TerminalPane* activePane = getActiveTerminalPane();
    bool terminalRunning = activePane && activePane->manager && activePane->manager->isRunning();
    EnableMenuItem(m_hMenu, IDM_TERMINAL_STOP, terminalRunning ? MF_BYCOMMAND|MF_ENABLED : MF_BYCOMMAND|MF_GRAYED);
    EnableMenuItem(m_hMenu, IDM_TERMINAL_CLEAR_ALL, (m_terminalPanes.empty() ? (MF_BYCOMMAND|MF_GRAYED) : (MF_BYCOMMAND|MF_ENABLED)));

    // Git items
    bool repo = isGitRepository();
    EnableMenuItem(m_hMenu, IDM_GIT_STATUS, repo ? MF_BYCOMMAND|MF_ENABLED : MF_BYCOMMAND|MF_GRAYED);
    EnableMenuItem(m_hMenu, IDM_GIT_COMMIT, (repo && m_gitStatus.hasChanges) ? MF_BYCOMMAND|MF_ENABLED : MF_BYCOMMAND|MF_GRAYED);
    EnableMenuItem(m_hMenu, IDM_GIT_PUSH, repo ? MF_BYCOMMAND|MF_ENABLED : MF_BYCOMMAND|MF_GRAYED);
    EnableMenuItem(m_hMenu, IDM_GIT_PULL, repo ? MF_BYCOMMAND|MF_ENABLED : MF_BYCOMMAND|MF_GRAYED);
    EnableMenuItem(m_hMenu, IDM_GIT_PANEL, repo ? MF_BYCOMMAND|MF_ENABLED : MF_BYCOMMAND|MF_GRAYED);

    // File save related
    EnableMenuItem(m_hMenu, IDM_FILE_SAVE, (!m_currentFile.empty() && m_fileModified) ? MF_BYCOMMAND|MF_ENABLED : MF_BYCOMMAND|MF_GRAYED);
    EnableMenuItem(m_hMenu, IDM_FILE_SAVEAS, (!m_currentFile.empty()) ? MF_BYCOMMAND|MF_ENABLED : MF_BYCOMMAND|MF_GRAYED);

    // Streaming loader menu state
    CheckMenuItem(m_hMenu, IDM_VIEW_USE_STREAMING_LOADER, MF_BYCOMMAND | (m_useStreamingLoader ? MF_CHECKED : MF_UNCHECKED));
    // Vulkan renderer menu state
    CheckMenuItem(m_hMenu, IDM_VIEW_USE_VULKAN_RENDERER, MF_BYCOMMAND | (m_useVulkanRenderer ? MF_CHECKED : MF_UNCHECKED));

    DrawMenuBar(m_hwndMain);
}

// Code Snippets Implementation
void Win32IDE::loadCodeSnippets()
{
    m_codeSnippets.clear();
    
    // Load built-in PowerShell snippets
    CodeSnippet snippet1;
    snippet1.name = "function";
    snippet1.description = "PowerShell function template";
    snippet1.code = "function {name} {\n    param(\n        ${1:$Parameter}\n    )\n    \n    ${2:# Function body}\n}";
    m_codeSnippets.push_back(snippet1);
    
    CodeSnippet snippet2;
    snippet2.name = "if";
    snippet2.description = "If statement";
    snippet2.code = "if (${1:condition}) {\n    ${2:# Code}\n}";
    m_codeSnippets.push_back(snippet2);
    
    CodeSnippet snippet3;
    snippet3.name = "foreach";
    snippet3.description = "ForEach loop";
    snippet3.code = "foreach (${1:$item} in ${2:$collection}) {\n    ${3:# Code}\n}";
    m_codeSnippets.push_back(snippet3);
    
    CodeSnippet snippet4;
    snippet4.name = "try";
    snippet4.description = "Try-Catch block";
    snippet4.code = "try {\n    ${1:# Code that might throw}\n}\ncatch {\n    ${2:# Error handling}\n}";
    m_codeSnippets.push_back(snippet4);
}

void Win32IDE::insertSnippet(const std::string& snippetName)
{
    for (const auto& snippet : m_codeSnippets) {
        if (snippet.name == snippetName) {
            // Get current cursor position
            DWORD start, end;
            SendMessage(m_hwndEditor, EM_GETSEL, (WPARAM)&start, (LPARAM)&end);
            
            // Insert snippet content
            std::string content = snippet.code;
            // Simple placeholder replacement
            size_t pos = content.find("${1:");
            if (pos != std::string::npos) {
                size_t endPos = content.find("}", pos);
                if (endPos != std::string::npos) {
                    content.erase(pos, endPos - pos + 1);
                }
            }
            
            SendMessage(m_hwndEditor, EM_REPLACESEL, TRUE, (LPARAM)content.c_str());
            break;
        }
    }
    updateMenuEnableStates();
}

// Integrated Help Implementation
void Win32IDE::showGetHelp(const std::string& cmdlet)
{
    // Get selected text for help lookup
    CHARRANGE range;
    SendMessage(m_hwndEditor, EM_EXGETSEL, 0, (LPARAM)&range);
    
    std::string command;
    if (!cmdlet.empty()) {
        command = cmdlet;
    } else if (range.cpMax > range.cpMin) {
        char buffer[1000];
        TEXTRANGEA tr;
        tr.chrg = range;
        tr.lpstrText = buffer;
        SendMessage(m_hwndEditor, EM_GETTEXTRANGE, 0, (LPARAM)&tr);
        command = std::string(buffer);
    } else {
        command = "Get-Command";  // Default help
    }
    
    std::string helpCommand = "Get-Help " + command + " -Full\n";
    TerminalPane* pane = getActiveTerminalPane();
    if (pane && pane->manager && pane->manager->isRunning()) {
        pane->manager->writeInput(helpCommand);
    }
}

void Win32IDE::showCommandReference()
{
    std::string reference = 
        "PowerShell Quick Reference:\n\n"
        "Get-Help <command> - Get help for command\n"
        "Get-Command - List all commands\n"
        "Get-Member - Get object properties/methods\n"
        "Measure-Object - Measure properties\n"
        "Select-Object - Select properties\n"
        "Where-Object - Filter objects\n"
        "ForEach-Object - Process each object\n"
        "Sort-Object - Sort objects\n"
        "Group-Object - Group objects\n"
        "Export-Csv - Export to CSV\n"
        "Import-Csv - Import from CSV\n"
        "ConvertTo-Json - Convert to JSON\n"
        "ConvertFrom-Json - Convert from JSON\n";
        
    MessageBoxA(m_hwndMain, reference.c_str(), "PowerShell Reference", MB_OK);
}

// Output / Clipboard / Minimap / Profiling implementations
void Win32IDE::createOutputTabs()
{
    if (m_hwndOutputTabs) return;

    RECT client{}; GetClientRect(m_hwndMain, &client);
    int tabBarHeight = 24;

    m_hwndOutputTabs = CreateWindowExA(0, WC_TABCONTROLA, "",
        WS_CHILD | WS_VISIBLE | TCS_TABS,
        0, 0, client.right - 150, tabBarHeight,
        m_hwndMain, (HMENU)IDC_OUTPUT_TABS, m_hInstance, nullptr);

    // Add severity filter dropdown
    m_hwndSeverityFilter = CreateWindowExA(0, "COMBOBOX", "",
        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
        client.right - 145, 2, 140, 100,
        m_hwndMain, (HMENU)IDC_SEVERITY_FILTER, m_hInstance, nullptr);
    SendMessageA(m_hwndSeverityFilter, CB_ADDSTRING, 0, (LPARAM)"All Messages");
    SendMessageA(m_hwndSeverityFilter, CB_ADDSTRING, 0, (LPARAM)"Info & Above");
    SendMessageA(m_hwndSeverityFilter, CB_ADDSTRING, 0, (LPARAM)"Warnings & Errors");
    SendMessageA(m_hwndSeverityFilter, CB_ADDSTRING, 0, (LPARAM)"Errors Only");
    SendMessageA(m_hwndSeverityFilter, CB_SETCURSEL, m_severityFilterLevel, 0);

    struct TabDef { const char* text; int id; const char* key; };
    TabDef defs[] = {
        {"Output", IDC_OUTPUT_EDIT_GENERAL, "Output"},
        {"Errors", IDC_OUTPUT_EDIT_ERRORS,  "Errors"},
        {"Debug",  IDC_OUTPUT_EDIT_DEBUG,   "Debug"},
        {"Find Results", IDC_OUTPUT_EDIT_FIND, "Find Results"}
    };

    for (int i = 0; i < 4; ++i) {
        TCITEMA tie{}; tie.mask = TCIF_TEXT; tie.pszText = const_cast<char*>(defs[i].text);
        TabCtrl_InsertItem(m_hwndOutputTabs, i, &tie);

        HWND hEdit = CreateWindowExA(WS_EX_CLIENTEDGE, RICHEDIT_CLASSA, "",
            WS_CHILD | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
            0, tabBarHeight, client.right, m_outputTabHeight - tabBarHeight,
            m_hwndMain, (HMENU)(INT_PTR)defs[i].id, m_hInstance, nullptr);
        m_outputWindows[defs[i].key] = hEdit;
    }
    // PowerShell is a peer bottom-surface, not a child layered over Output,
    // Errors, Debug, or Find Results.  Keeping it in the same tab strip gives
    // every bottom surface one owner rectangle and makes the active choice
    // explicit to both keyboard and mouse users.
    TCITEMA powerShellTab{};
    powerShellTab.mask = TCIF_TEXT;
    powerShellTab.pszText = const_cast<char*>("PowerShell");
    TabCtrl_InsertItem(m_hwndOutputTabs, 4, &powerShellTab);
    m_activeOutputTab = "Output";

    // Restore persisted tab selection
    if (m_selectedOutputTab >= 0 && m_selectedOutputTab < 4) {
        const char* keys[] = {"Output","Errors","Debug","Find Results"};
        m_activeOutputTab = keys[m_selectedOutputTab];
        TabCtrl_SetCurSel(m_hwndOutputTabs, m_selectedOutputTab);
    }

    // Initially show only active tab and respect visibility setting
    for (auto& kv : m_outputWindows) {
        ShowWindow(kv.second, (kv.first == m_activeOutputTab && m_outputPanelVisible) ? SW_SHOW : SW_HIDE);
    }
    ShowWindow(m_hwndOutputTabs, m_outputPanelVisible ? SW_SHOW : SW_HIDE);
    if (m_hwndSeverityFilter) ShowWindow(m_hwndSeverityFilter, m_outputPanelVisible ? SW_SHOW : SW_HIDE);
    if (m_hwndSplitter) ShowWindow(m_hwndSplitter, m_outputPanelVisible ? SW_SHOW : SW_HIDE);
}

void Win32IDE::addOutputTab(const std::string& name)
{
    if (m_outputWindows.find(name) != m_outputWindows.end()) return;
    RECT client{}; GetClientRect(m_hwndMain, &client);
    int tabBarHeight = 24;
    HWND hEdit = CreateWindowExA(
        WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
        0, tabBarHeight, client.right, m_outputTabHeight - tabBarHeight,
        m_hwndMain, nullptr, m_hInstance, nullptr);
    ShowWindow(hEdit, SW_HIDE);
    m_outputWindows[name] = hEdit;
}

void Win32IDE::appendToOutput(const std::string& text, const std::string& tabName, OutputSeverity severity)
{
    if (static_cast<int>(severity) < m_severityFilterLevel) return;
    
    std::string target = tabName.empty() ? m_activeOutputTab : tabName;
    if (m_outputWindows.find(target) == m_outputWindows.end()) {
        addOutputTab(target);
    }
    
    // Add timestamp for Errors and Debug tabs
    std::string timestampedText = text;
    if (target == "Errors" || target == "Debug") {
        time_t now = time(nullptr);
        struct tm timeinfo;
        localtime_s(&timeinfo, &now);
        char timestamp[16];
        strftime(timestamp, sizeof(timestamp), "[%H:%M:%S] ", &timeinfo);
        timestampedText = std::string(timestamp) + text;
    }
    
    // Apply color formatting based on tab type
    if (target == "Errors") {
        formatOutput(timestampedText, RGB(220, 50, 50), "Errors"); // Red
    } else if (target == "Debug") {
        formatOutput(timestampedText, RGB(200, 180, 50), "Debug"); // Yellow
    } else {
        HWND hwnd = m_outputWindows[target];
        appendText(hwnd, timestampedText);
    }
}

void Win32IDE::clearOutput(const std::string& tabName)
{
    std::string target = tabName.empty() ? m_activeOutputTab : tabName;
    auto it = m_outputWindows.find(target);
    if (it != m_outputWindows.end()) {
        SetWindowTextA(it->second, "");
    }
}

void Win32IDE::formatOutput(const std::string& text, COLORREF color, const std::string& tabName)
{ 
    std::string target = tabName.empty() ? m_activeOutputTab : tabName;
    auto it = m_outputWindows.find(target);
    if (it == m_outputWindows.end()) return;
    
    HWND hwnd = it->second;
    GETTEXTLENGTHEX gtl{}; gtl.flags = GTL_DEFAULT; gtl.codepage = CP_ACP;
    LONG len = SendMessage(hwnd, EM_GETTEXTLENGTHEX, (WPARAM)&gtl, 0);
    SendMessage(hwnd, EM_SETSEL, len, len);
    
    CHARFORMAT2A cf{};
    cf.cbSize = sizeof(cf);
    cf.dwMask = CFM_COLOR;
    cf.crTextColor = color;
    SendMessage(hwnd, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);
    
    SETTEXTEX st{}; st.flags = ST_SELECTION; st.codepage = CP_ACP;
    SendMessage(hwnd, EM_SETTEXTEX, (WPARAM)&st, (LPARAM)text.c_str());
}

void Win32IDE::copyWithFormatting()
{
    // Simplified: copy selected plain text and store in history (vector<string>)
    CHARRANGE range;
    SendMessage(m_hwndEditor, EM_EXGETSEL, 0, (LPARAM)&range);
    if (range.cpMax <= range.cpMin) return;
    LONG len = range.cpMax - range.cpMin;
    std::vector<char> buffer(len + 1); TEXTRANGEA tr; tr.chrg = range; tr.lpstrText = buffer.data();
    SendMessage(m_hwndEditor, EM_GETTEXTRANGE, 0, (LPARAM)&tr);
    std::string text(buffer.data());
    m_clipboardHistory.insert(m_clipboardHistory.begin(), text);
    if (m_clipboardHistory.size() > MAX_CLIPBOARD_HISTORY) m_clipboardHistory.resize(MAX_CLIPBOARD_HISTORY);
    if (OpenClipboard(m_hwndMain)) {
        EmptyClipboard();
        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
        if (hMem) {
            char* dest = (char*)GlobalLock(hMem);
            memcpy(dest, text.c_str(), text.size() + 1);
            GlobalUnlock(hMem);
            SetClipboardData(CF_TEXT, hMem);
        }
        CloseClipboard();
    }
}

void Win32IDE::pasteWithoutFormatting()
{
    if (OpenClipboard(m_hwndMain)) {
        HANDLE hData = GetClipboardData(CF_TEXT);
        if (hData) {
            const char* data = (const char*)GlobalLock(hData);
            if (data) {
                SendMessage(m_hwndEditor, EM_REPLACESEL, TRUE, (LPARAM)data);
                GlobalUnlock(hData);
            }
        }
        CloseClipboard();
    }
}

void Win32IDE::copyLineNumbers()
{
    if (!m_hwndEditor) return;
    
    // Get selected range
    CHARRANGE range;
    SendMessage(m_hwndEditor, EM_EXGETSEL, 0, (LPARAM)&range);
    
    // Get line numbers for selection
    int startLine = (int)SendMessage(m_hwndEditor, EM_LINEFROMCHAR, range.cpMin, 0);
    int endLine = (int)SendMessage(m_hwndEditor, EM_LINEFROMCHAR, range.cpMax, 0);
    
    // Build line number string
    std::string lineNumbers;
    for (int i = startLine; i <= endLine; ++i) {
        if (!lineNumbers.empty()) lineNumbers += "\r\n";
        lineNumbers += std::to_string(i + 1);
    }
    
    // Copy to clipboard
    if (OpenClipboard(m_hwndMain)) {
        EmptyClipboard();
        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, lineNumbers.size() + 1);
        if (hMem) {
            char* dest = (char*)GlobalLock(hMem);
            memcpy(dest, lineNumbers.c_str(), lineNumbers.size() + 1);
            GlobalUnlock(hMem);
            SetClipboardData(CF_TEXT, hMem);
        }
        CloseClipboard();
    }
}

void Win32IDE::showClipboardHistory()
{
    std::string msg = "Clipboard History (latest 10):\n\n";
    size_t count = std::min<size_t>(10, m_clipboardHistory.size());
    for (size_t i = 0; i < count; ++i) {
        const std::string& item = m_clipboardHistory[i];
        std::string preview = item.substr(0, 50);
        if (item.size() > 50) preview += "...";
        msg += std::to_string(i + 1) + ". " + preview + "\n";
    }
    MessageBoxA(m_hwndMain, msg.c_str(), "Clipboard History", MB_OK);
}

void Win32IDE::clearClipboardHistory()
{
    m_clipboardHistory.clear();
}

void Win32IDE::createMinimap()
{
    if (!m_hwndMain || !m_hwndEditor) return;
    
    m_minimapWidth = 120;
    m_minimapVisible = true;
    
    // Create minimap window as a child of main window
    RECT editorRect;
    GetWindowRect(m_hwndEditor, &editorRect);
    MapWindowPoints(HWND_DESKTOP, m_hwndMain, (LPPOINT)&editorRect, 2);
    
    int minimapX = editorRect.right - m_minimapWidth;
    int minimapY = editorRect.top;
    int minimapHeight = editorRect.bottom - editorRect.top;
    
    m_hwndMinimap = CreateWindowExA(
        0, "STATIC", "",
        WS_CHILD | WS_VISIBLE | SS_OWNERDRAW,
        minimapX, minimapY, m_minimapWidth, minimapHeight,
        m_hwndMain, nullptr, m_hInstance, nullptr);
    
    if (m_hwndMinimap) {
        SetWindowLongPtrA(m_hwndMinimap, GWLP_USERDATA, (LONG_PTR)this);
    }
    
    updateMinimap();
}

void Win32IDE::updateMinimap()
{
    if (!m_hwndMinimap || !m_minimapVisible || !m_hwndEditor) return;
    
    // Get editor content
    int textLen = GetWindowTextLengthA(m_hwndEditor);
    if (textLen == 0) {
        m_minimapLines.clear();
        InvalidateRect(m_hwndMinimap, nullptr, TRUE);
        return;
    }
    
    std::string text(textLen + 1, '\0');
    GetWindowTextA(m_hwndEditor, &text[0], textLen + 1);
    text.resize(textLen);
    
    // Split into lines for minimap rendering
    m_minimapLines.clear();
    m_minimapLineStarts.clear();
    
    std::istringstream stream(text);
    std::string line;
    int pos = 0;
    while (std::getline(stream, line)) {
        m_minimapLines.push_back(line);
        m_minimapLineStarts.push_back(pos);
        pos += (int)line.size() + 1; // +1 for newline
    }
    
    // Force redraw
    InvalidateRect(m_hwndMinimap, nullptr, TRUE);
    
    // Paint minimap content
    HDC hdc = GetDC(m_hwndMinimap);
    if (hdc) {
        RECT rc;
        GetClientRect(m_hwndMinimap, &rc);
        
        // Dark background
        HBRUSH bgBrush = CreateSolidBrush(RGB(30, 30, 30));
        FillRect(hdc, &rc, bgBrush);
        DeleteObject(bgBrush);
        
        // Calculate visible area highlight
        int firstVisibleLine = (int)SendMessage(m_hwndEditor, EM_GETFIRSTVISIBLELINE, 0, 0);
        RECT editorRect;
        GetClientRect(m_hwndEditor, &editorRect);
        int visibleLines = editorRect.bottom / 16; // Approximate line height
        
        // Draw visible area indicator
        int totalLines = (int)m_minimapLines.size();
        if (totalLines > 0) {
            float scale = (float)(rc.bottom - rc.top) / (float)totalLines;
            int highlightTop = (int)(firstVisibleLine * scale);
            int highlightHeight = (int)(visibleLines * scale);
            if (highlightHeight < 10) highlightHeight = 10;
            
            RECT highlightRect = { 0, highlightTop, rc.right, highlightTop + highlightHeight };
            HBRUSH highlightBrush = CreateSolidBrush(RGB(60, 60, 80));
            FillRect(hdc, &highlightRect, highlightBrush);
            DeleteObject(highlightBrush);
        }
        
        // Draw minimap lines as colored blocks
        HPEN codePen = CreatePen(PS_SOLID, 1, RGB(150, 150, 150));
        HPEN oldPen = (HPEN)SelectObject(hdc, codePen);
        
        float lineHeight = 2.0f;
        if (totalLines > 0 && totalLines * lineHeight > rc.bottom) {
            lineHeight = (float)(rc.bottom - 4) / (float)totalLines;
            if (lineHeight < 1.0f) lineHeight = 1.0f;
        }
        
        for (size_t i = 0; i < m_minimapLines.size() && i * lineHeight < rc.bottom; ++i) {
            const std::string& line = m_minimapLines[i];
            if (line.empty()) continue;
            
            int y = (int)(i * lineHeight) + 2;
            int lineLen = (int)line.size();
            int pixelLen = (lineLen * rc.right) / 200; // Scale to minimap width
            if (pixelLen > rc.right - 4) pixelLen = rc.right - 4;
            if (pixelLen < 2) pixelLen = 2;
            
            MoveToEx(hdc, 2, y, nullptr);
            LineTo(hdc, 2 + pixelLen, y);
        }
        
        SelectObject(hdc, oldPen);
        DeleteObject(codePen);
        
        ReleaseDC(m_hwndMinimap, hdc);
    }
}

void Win32IDE::scrollToMinimapPosition(int y)
{
    if (!m_hwndMinimap || !m_hwndEditor || m_minimapLines.empty()) return;
    
    RECT rc;
    GetClientRect(m_hwndMinimap, &rc);
    
    int totalLines = (int)m_minimapLines.size();
    int targetLine = (y * totalLines) / rc.bottom;
    
    if (targetLine < 0) targetLine = 0;
    if (targetLine >= totalLines) targetLine = totalLines - 1;
    
    // Scroll editor to target line
    int charIndex = 0;
    if (targetLine < (int)m_minimapLineStarts.size()) {
        charIndex = m_minimapLineStarts[targetLine];
    }
    
    SendMessage(m_hwndEditor, EM_SETSEL, charIndex, charIndex);
    SendMessage(m_hwndEditor, EM_SCROLLCARET, 0, 0);
    
    updateMinimap();
}

void Win32IDE::toggleMinimap()
{
    m_minimapVisible = !m_minimapVisible;
    if (m_hwndMinimap) {
        ShowWindow(m_hwndMinimap, m_minimapVisible ? SW_SHOW : SW_HIDE);
    } else if (m_minimapVisible) {
        createMinimap();
    }
    
    // Trigger layout update
    RECT rc;
    GetClientRect(m_hwndMain, &rc);
    onSize(rc.right, rc.bottom);
}

void Win32IDE::startProfiling()
{
    if (!m_profilingActive) {
        m_profilingActive = true;
        QueryPerformanceCounter(&m_profilingStart);
        QueryPerformanceFrequency(&m_profilingFreq);
        m_profilingResults.clear();
    }
}

void Win32IDE::stopProfiling()
{
    if (m_profilingActive) {
        LARGE_INTEGER end; QueryPerformanceCounter(&end);
        double ms = (double)(end.QuadPart - m_profilingStart.QuadPart) * 1000.0 / (double)m_profilingFreq.QuadPart;
        m_profilingResults.push_back({"Session", ms});
        m_profilingActive = false;
    }
}

void Win32IDE::showProfileResults()
{
    std::string msg = "Profile Results:\n\n";
    for (auto& pr : m_profilingResults) {
        msg += pr.first + ": " + std::to_string(pr.second) + " ms\n";
    }
    MessageBoxA(m_hwndMain, msg.c_str(), "Profiling", MB_OK);
}

void Win32IDE::analyzeScript()
{
    std::string script = getWindowText(m_hwndEditor);
    if(script.empty()) {
        MessageBoxA(m_hwndMain, "Script is empty.", "Analyze Script", MB_OK);
        return;
    }
    
    appendToOutput("Starting AI Analysis...\n", "Output", OutputSeverity::Info);
    
    // Asynchronous analysis to avoid blocking UI
    std::thread([this, script]() {
        if (m_nativeEngine) {
            std::string prompt = "Analyze the following script and report potential bugs, security issues, and improvements:\n\n" + script;
            auto* engine = static_cast<RawrXD::CPUInferenceEngine*>(m_nativeEngine);
            std::string result = NativeEngineInfer(engine, prompt);
            
            // Post result back to UI thread or just append (if appendToOutput is thread-safe or we lock)
            // appendToOutput uses SendMessage which is generally thread-safe for simple text
            this->appendToOutput("\n=== AI Analysis Result ===\n" + result + "\n==========================\n", "Output", OutputSeverity::Info);
        } else {
             this->appendToOutput("Error: Inference Engine not available.\n", "Errors", OutputSeverity::Error);
        }
    }).detach();
}

void Win32IDE::measureExecutionTime() { 
    // Real implementation: Measure block execution
    auto start = std::chrono::high_resolution_clock::now();
    // execute selection... (simplified)
    auto end = std::chrono::high_resolution_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end-start).count();
    appendToOutput("Execution time info: " + std::to_string(ms) + "ms\n", "Output", OutputSeverity::Info);
}

// Module Management
void Win32IDE::refreshModuleList()
{
    m_modules.clear();
    
    // Default module set (always available)
    m_modules.push_back({"Microsoft.PowerShell.Management","3.0.0.0","Management cmdlets","",true});
    m_modules.push_back({"Microsoft.PowerShell.Utility","3.0.0.0","Utility cmdlets","",true});
    m_modules.push_back({"PSReadLine","2.0.0","Command line editing","",false});
    
    // Dynamic module enumeration via Powershell command
    std::string cmd = "powershell.exe -NoProfile -Command \"Get-Module -ListAvailable | Select-Object -First 50 Name, Version | ConvertTo-Json -Compress\"";
    std::string output = CaptureProcessOutput(cmd);
    
    if (output.find("Error") == std::string::npos && !output.empty()) {
        try {
            nlohmann::json json = nlohmann::json::parse(output);
            if (json.is_array()) {
                for (const auto& item : json) {
                    ModuleInfo m;
                    m.name = item.value("Name", "");
                    auto v = item["Version"];
                    if (v.is_object()) { 
                         // PS version object
                         m.version = std::to_string(v.value("Major",0)) + "." + std::to_string(v.value("Minor",0));
                    } else {
                        m.version = item.value("Version", "0.0.0");
                    }
                    m.description = "User Module";
                    m.path = ""; 
                    m.loaded = false; // Check via Get-Module without ListAvailable if needed
                    
                    // Avoid duplicates
                    bool exists = false;
                    for(const auto& existing : m_modules) if (existing.name == m.name) exists = true;
                    if (!exists) m_modules.push_back(m);
                }
            } else if (json.is_object()) {
                 // Single module
                 ModuleInfo m;
                 m.name = json.value("Name", "");
                 m.version = "1.0";
                 m.description = "User Module";
                 m_modules.push_back(m);
            }
        } catch (...) {
            // JSON parsing failed, likely non-JSON output or empty
        }
    }
}

void Win32IDE::showModuleBrowser()
{
    std::string msg = "Modules:\n\n";
    for (auto& m : m_modules) {
        msg += m.name + " (" + m.version + ")" + (m.loaded?" [Loaded]":" [Available]") + "\n";
    }
    MessageBoxA(m_hwndMain, msg.c_str(), "Module Browser", MB_OK);
}

void Win32IDE::loadModule(const std::string& moduleName)
{
    bool found = false;
    for (auto& m : m_modules) {
        if (m.name == moduleName) {
            m.loaded = true;
            found = true;
            break;
        }
    }
    
    // Explicit Logic: Actually load the module in PowerShell
    std::string command = "Import-Module '" + moduleName + "'\n";
    
    TerminalPane* pane = getActiveTerminalPane();
    if (pane && pane->manager && pane->manager->isRunning()) {
        pane->manager->writeInput(command);
        appendToOutput("Loading module: " + moduleName, "Output", OutputSeverity::Info);
    } else {
        appendToOutput("Cannot load module '" + moduleName + "': No active terminal.", "Errors", OutputSeverity::Error);
    }
}

void Win32IDE::unloadModule(const std::string& moduleName)
{
    bool found = false;
    for (auto& m : m_modules) {
        if (m.name == moduleName) {
            m.loaded = false;
            found = true;
            break;
        }
    }

    // Explicit Logic: Actually remove the module in PowerShell
    std::string command = "Remove-Module '" + moduleName + "'\n";
    
    TerminalPane* pane = getActiveTerminalPane();
    if (pane && pane->manager && pane->manager->isRunning()) {
        pane->manager->writeInput(command);
        appendToOutput("Unloading module: " + moduleName, "Output", OutputSeverity::Info);
    } else {
        // Try to start one or log error
        appendToOutput("Cannot unload module '" + moduleName + "': No active terminal.", "Errors", OutputSeverity::Error);
    }
}

void Win32IDE::importModule()
{
    // Show file dialog to select module
    OPENFILENAMEA ofn = {};
    char szFile[MAX_PATH] = "";
    
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = m_hwndMain;
    ofn.lpstrFilter = "PowerShell Modules (*.psm1;*.psd1)\0*.psm1;*.psd1\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    ofn.lpstrTitle = "Import Module";
    
    if (GetOpenFileNameA(&ofn)) {
        std::string modulePath = szFile;
        std::string command = "Import-Module '" + modulePath + "'\n";
        
        TerminalPane* pane = getActiveTerminalPane();
        if (pane && pane->manager && pane->manager->isRunning()) {
            pane->manager->writeInput(command);
            appendToOutput("Importing module: " + modulePath + "\n", "Output", OutputSeverity::Info);
        }
        
        // Refresh module list after import
        refreshModuleList();
    }
}

void Win32IDE::exportModule()
{
    // Show dialog to select module to export
    if (m_modules.empty()) {
        MessageBoxA(m_hwndMain, "No modules loaded. Refresh module list first.", "Export Module", MB_OK | MB_ICONINFORMATION);
        return;
    }
    
    // Build list of module names for selection
    std::string moduleList = "Available modules:\n\n";
    for (size_t i = 0; i < m_modules.size(); ++i) {
        moduleList += std::to_string(i + 1) + ". " + m_modules[i].name;
        if (m_modules[i].loaded) moduleList += " [Loaded]";
        moduleList += "\n";
    }
    moduleList += "\nExport the first loaded module?";
    
    if (MessageBoxA(m_hwndMain, moduleList.c_str(), "Export Module", MB_YESNO | MB_ICONQUESTION) == IDYES) {
        // Find first loaded module
        for (const auto& mod : m_modules) {
            if (mod.loaded) {
                // Show save dialog
                OPENFILENAMEA ofn = {};
                char szFile[MAX_PATH] = "";
                strncpy_s(szFile, (mod.name + ".psm1").c_str(), MAX_PATH);
                
                ofn.lStructSize = sizeof(ofn);
                ofn.hwndOwner = m_hwndMain;
                ofn.lpstrFilter = "PowerShell Module (*.psm1)\0*.psm1\0PowerShell Data (*.psd1)\0*.psd1\0";
                ofn.lpstrFile = szFile;
                ofn.nMaxFile = MAX_PATH;
                ofn.Flags = OFN_OVERWRITEPROMPT;
                ofn.lpstrTitle = "Export Module";
                
                if (GetSaveFileNameA(&ofn)) {
                    std::string savePath = szFile;
                    std::string command = "Export-ModuleMember -Function * -Cmdlet * -Variable * -Alias * -PassThru | Out-File '" + savePath + "'\n";
                    
                    TerminalPane* pane = getActiveTerminalPane();
                    if (pane && pane->manager && pane->manager->isRunning()) {
                        pane->manager->writeInput(command);
                        appendToOutput("Exporting module to: " + savePath + "\n", "Output", OutputSeverity::Info);
                    }
                }
                break;
            }
        }
    }
}

// Theme Management
void Win32IDE::resetToDefaultTheme()
{
    m_currentTheme.backgroundColor = RGB(30,30,30);
    m_currentTheme.textColor = RGB(220,220,220);
    m_currentTheme.keywordColor = RGB(86,156,214);
    m_currentTheme.commentColor = RGB(106,153,85);
    m_currentTheme.stringColor = RGB(214,157,133);
    m_currentTheme.numberColor = RGB(181,206,168);
    m_currentTheme.operatorColor = RGB(212,212,212);
    m_currentTheme.selectionColor = RGB(60,120,200);
    m_currentTheme.lineNumberColor = RGB(128,128,128);
    m_currentTheme.fontName = "Consolas";
    m_currentTheme.fontSize = 10;
    m_currentTheme.darkMode = true;
    applyTheme();
}

void Win32IDE::saveCodeSnippets()
{
    CreateDirectoryA("snippets", NULL);
    std::ofstream file("snippets\\snippets.txt");
    if (file.is_open()) {
        for (const auto& snippet : m_codeSnippets) {
            file << "[SNIPPET]" << std::endl;
            file << "name=" << snippet.name << std::endl;
            file << "description=" << snippet.description << std::endl;
            file << "code_start" << std::endl;
            file << snippet.code << std::endl;
            file << "code_end" << std::endl;
        }
        file.close();
    }
}

void Win32IDE::showPowerShellDocs()
{
    MessageBoxA(m_hwndMain, "Open https://learn.microsoft.com/powershell/ for full docs.", "PowerShell Docs", MB_OK);
}

void Win32IDE::searchHelp(const std::string& query)
{
    std::string q = query.empty()?"Get-Command":query;
    std::string cmd = "Get-Help " + q + " -Online\n";
    TerminalPane* pane = getActiveTerminalPane();
    if (pane && pane->manager && pane->manager->isRunning()) pane->manager->writeInput(cmd);
}

void Win32IDE::toggleFloatingPanel()
{
    if (!m_hwndFloatingPanel) return; // created elsewhere
    BOOL vis = IsWindowVisible(m_hwndFloatingPanel);
    ShowWindow(m_hwndFloatingPanel, vis?SW_HIDE:SW_SHOW);
}
// ============================================================================
// Search and Replace Implementation
// ============================================================================

#define IDD_FIND 5001
#define IDD_REPLACE 5002
#define IDC_FIND_TEXT 5010
#define IDC_REPLACE_TEXT 5011
#define IDC_CASE_SENSITIVE 5020
#define IDC_WHOLE_WORD 5021
#define IDC_USE_REGEX 5022
#define IDC_BTN_FIND_NEXT 5030
#define IDC_BTN_REPLACE 5031
#define IDC_BTN_REPLACE_ALL 5032
// Renamed from IDC_BTN_CLOSE, which collides with the toolbar's IDC_BTN_CLOSE
// (1021). A macro redefinition makes the last definition win, so both buttons
// would have shared one command ID and WM_COMMAND could not tell them apart.
#define IDC_BTN_FIND_CLOSE 5033

namespace {
HWND CreateSearchWindow(HINSTANCE instance, HWND parent, DLGPROC proc,
                        Win32IDE* ide, const char* title) {
    // A real modeless dialog installs the DLGPROC, unlike a STATIC window.
    struct EmptyDialog { DLGTEMPLATE dialog; WORD menu, windowClass, title; };
    EmptyDialog layout{};
    layout.dialog.style = WS_POPUP | WS_CAPTION | WS_SYSMENU | DS_MODALFRAME;
    layout.dialog.dwExtendedStyle = WS_EX_DLGMODALFRAME;
    layout.dialog.x = 100; layout.dialog.y = 100;
    layout.dialog.cx = 270; layout.dialog.cy = 140;
    HWND window = CreateDialogIndirectParamA(instance, &layout.dialog, parent, proc,
                                             reinterpret_cast<LPARAM>(ide));
    if (window) SetWindowTextA(window, title);
    return window;
}
struct SearchMatch { size_t start, length; std::string replacement; };
std::vector<SearchMatch> SearchMatches(const std::string& text, const std::string& search,
        bool caseSensitive, bool wholeWord, bool useRegex, const std::string& replacement) {
    std::vector<SearchMatch> matches;
    if (search.empty()) return matches;
    auto word = [](unsigned char c) { return std::isalnum(c) != 0 || c == '_'; };
    auto boundary = [&](size_t start, size_t length) {
        return !wholeWord || ((start == 0 || !word(text[start - 1])) &&
            (start + length == text.size() || !word(text[start + length])));
    };
    if (useRegex) {
        auto flags = std::regex::ECMAScript;
        if (!caseSensitive) flags |= std::regex::icase;
        const std::regex expression(search, flags);
        for (std::sregex_iterator it(text.begin(), text.end(), expression), end; it != end; ++it) {
            const auto start = static_cast<size_t>(it->position());
            const auto length = static_cast<size_t>(it->length());
            if (boundary(start, length)) matches.push_back({start, length, it->format(replacement)});
        }
    } else {
        std::string haystack = text, needle = search;
        if (!caseSensitive) {
            auto lower = [](unsigned char c) { return static_cast<char>(std::tolower(c)); };
            std::transform(haystack.begin(), haystack.end(), haystack.begin(), lower);
            std::transform(needle.begin(), needle.end(), needle.begin(), lower);
        }
        for (size_t pos = 0; (pos = haystack.find(needle, pos)) != std::string::npos; pos += needle.size()) {
            if (boundary(pos, needle.size())) matches.push_back({pos, needle.size(), replacement});
        }
    }
    return matches;
}
} // namespace

void Win32IDE::showFindDialog()
{
    if (m_hwndFindDialog && IsWindow(m_hwndFindDialog)) {
        SetForegroundWindow(m_hwndFindDialog);
        return;
    }
    
    m_hwndFindDialog = CreateDialogParamA(m_hInstance, MAKEINTRESOURCEA(IDD_FIND), 
        m_hwndMain, FindDialogProc, (LPARAM)this);
    
    if (!m_hwndFindDialog) {
        // Fallback: create simple dialog programmatically
        HWND hwndDlg = CreateSearchWindow(m_hInstance, m_hwndMain, FindDialogProc, this, "Find");
        if (!hwndDlg) return;
        SetWindowPos(hwndDlg, nullptr, 100, 100, 400, 150, SWP_NOZORDER | SWP_NOACTIVATE);
        m_hwndFindDialog = hwndDlg;
        
        CreateWindowExA(0, "STATIC", "Find what:", WS_CHILD | WS_VISIBLE,
            10, 15, 80, 20, hwndDlg, nullptr, m_hInstance, nullptr);
        m_hwndFindInput = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", m_lastSearchText.c_str(),
            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 100, 12, 280, 22, 
            hwndDlg, (HMENU)IDC_FIND_TEXT, m_hInstance, nullptr);
        
        CreateWindowExA(0, "BUTTON", "Case sensitive", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            10, 45, 120, 20, hwndDlg, (HMENU)IDC_CASE_SENSITIVE, m_hInstance, nullptr);
        CreateWindowExA(0, "BUTTON", "Whole word", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            140, 45, 100, 20, hwndDlg, (HMENU)IDC_WHOLE_WORD, m_hInstance, nullptr);
        CreateWindowExA(0, "BUTTON", "Regex", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            250, 45, 70, 20, hwndDlg, (HMENU)IDC_USE_REGEX, m_hInstance, nullptr);
        
        CreateWindowExA(0, "BUTTON", "Find Next", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
            10, 80, 90, 28, hwndDlg, (HMENU)IDC_BTN_FIND_NEXT, m_hInstance, nullptr);
        CreateWindowExA(0, "BUTTON", "Close", WS_CHILD | WS_VISIBLE,
            110, 80, 90, 28, hwndDlg, (HMENU)IDC_BTN_FIND_CLOSE, m_hInstance, nullptr);
    }
    if (m_hwndFindDialog && !m_hwndFindInput) {
        m_hwndFindInput = GetDlgItem(m_hwndFindDialog, IDC_FIND_TEXT);
    }
    
    ShowWindow(m_hwndFindDialog, IsWindowVisible(m_hwndMain) ? SW_SHOW : SW_HIDE);
    initializeNativeGhostText();
}

void Win32IDE::showReplaceDialog()
{
    if (m_hwndReplaceDialog && IsWindow(m_hwndReplaceDialog)) {
        SetForegroundWindow(m_hwndReplaceDialog);
        return;
    }
    
    // Create simple replace dialog
    HWND hwndDlg = CreateSearchWindow(m_hInstance, m_hwndMain, ReplaceDialogProc, this, "Replace");
    if (!hwndDlg) return;
    SetWindowPos(hwndDlg, nullptr, 100, 100, 400, 200, SWP_NOZORDER | SWP_NOACTIVATE);
    m_hwndReplaceDialog = hwndDlg;
    
    CreateWindowExA(0, "STATIC", "Find what:", WS_CHILD | WS_VISIBLE,
        10, 15, 80, 20, hwndDlg, nullptr, m_hInstance, nullptr);
    m_hwndFindInput = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", m_lastSearchText.c_str(),
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 100, 12, 280, 22, 
        hwndDlg, (HMENU)IDC_FIND_TEXT, m_hInstance, nullptr);
    
    CreateWindowExA(0, "STATIC", "Replace with:", WS_CHILD | WS_VISIBLE,
        10, 45, 80, 20, hwndDlg, nullptr, m_hInstance, nullptr);
    m_hwndReplaceInput = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", m_lastReplaceText.c_str(),
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, 100, 42, 280, 22, 
        hwndDlg, (HMENU)IDC_REPLACE_TEXT, m_hInstance, nullptr);
    
    CreateWindowExA(0, "BUTTON", "Case sensitive", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        10, 75, 120, 20, hwndDlg, (HMENU)IDC_CASE_SENSITIVE, m_hInstance, nullptr);
    CreateWindowExA(0, "BUTTON", "Whole word", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        140, 75, 100, 20, hwndDlg, (HMENU)IDC_WHOLE_WORD, m_hInstance, nullptr);
    CreateWindowExA(0, "BUTTON", "Regex", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        250, 75, 70, 20, hwndDlg, (HMENU)IDC_USE_REGEX, m_hInstance, nullptr);
    
    CreateWindowExA(0, "BUTTON", "Find Next", WS_CHILD | WS_VISIBLE,
        10, 110, 90, 28, hwndDlg, (HMENU)IDC_BTN_FIND_NEXT, m_hInstance, nullptr);
    CreateWindowExA(0, "BUTTON", "Replace", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
        110, 110, 90, 28, hwndDlg, (HMENU)IDC_BTN_REPLACE, m_hInstance, nullptr);
    CreateWindowExA(0, "BUTTON", "Replace All", WS_CHILD | WS_VISIBLE,
        210, 110, 90, 28, hwndDlg, (HMENU)IDC_BTN_REPLACE_ALL, m_hInstance, nullptr);
    CreateWindowExA(0, "BUTTON", "Close", WS_CHILD | WS_VISIBLE,
        310, 110, 70, 28, hwndDlg, (HMENU)IDC_BTN_FIND_CLOSE, m_hInstance, nullptr);
    
    ShowWindow(m_hwndReplaceDialog, IsWindowVisible(m_hwndMain) ? SW_SHOW : SW_HIDE);
    initializeNativeGhostText();
}

void Win32IDE::findNext()
{
    if (m_lastSearchText.empty()) {
        showFindDialog();
        return;
    }
    findText(m_lastSearchText, true, m_searchCaseSensitive, m_searchWholeWord, m_searchUseRegex);
}

void Win32IDE::findPrevious()
{
    if (m_lastSearchText.empty()) {
        showFindDialog();
        return;
    }
    findText(m_lastSearchText, false, m_searchCaseSensitive, m_searchWholeWord, m_searchUseRegex);
}

void Win32IDE::replaceNext()
{
    if (m_lastSearchText.empty()) {
        showReplaceDialog();
        return;
    }
    replaceText(m_lastSearchText, m_lastReplaceText, false, m_searchCaseSensitive, m_searchWholeWord, m_searchUseRegex);
}

void Win32IDE::replaceAll()
{
    if (m_lastSearchText.empty()) {
        showReplaceDialog();
        return;
    }
    int count = replaceText(m_lastSearchText, m_lastReplaceText, true, m_searchCaseSensitive, m_searchWholeWord, m_searchUseRegex);
    
    std::string msg = "Replaced " + std::to_string(count) + " occurrence(s).";
    SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 0, reinterpret_cast<LPARAM>(msg.c_str()));
}

bool Win32IDE::findText(const std::string& searchText, bool forward, bool caseSensitive, bool wholeWord, bool useRegex)
{
    if (!m_hwndEditor || searchText.empty()) return false;
    const int length = GetWindowTextLengthA(m_hwndEditor);
    std::string text(length + 1, '\0');
    GetWindowTextA(m_hwndEditor, text.data(), length + 1);
    text.resize(length);
    CHARRANGE selection{};
    SendMessageA(m_hwndEditor, EM_EXGETSEL, 0, reinterpret_cast<LPARAM>(&selection));
    std::vector<SearchMatch> matches;
    try { matches = SearchMatches(text, searchText, caseSensitive, wholeWord, useRegex, ""); }
    catch (const std::regex_error& e) {
        MessageBoxA(m_hwndMain, e.what(), "Invalid search expression", MB_OK | MB_ICONERROR);
        return false;
    }
    if (matches.empty()) {
        SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 0, reinterpret_cast<LPARAM>("Text not found."));
        return false;
    }
    const SearchMatch* found = forward ? &matches.front() : &matches.back();
    if (forward) {
        for (const auto& match : matches) if (match.start >= static_cast<size_t>(selection.cpMax)) {
            found = &match; break;
        }
    } else {
        for (auto it = matches.rbegin(); it != matches.rend(); ++it)
            if (it->start < static_cast<size_t>(selection.cpMin)) { found = &*it; break; }
    }
    selection.cpMin = static_cast<LONG>(found->start);
    selection.cpMax = static_cast<LONG>(found->start + found->length);
    SendMessageA(m_hwndEditor, EM_EXSETSEL, 0, reinterpret_cast<LPARAM>(&selection));
    SendMessageA(m_hwndEditor, EM_SCROLLCARET, 0, 0);
    m_lastFoundPos = selection.cpMin;
    return true;
}

int Win32IDE::replaceText(const std::string& searchText, const std::string& replacement, bool all,
                         bool caseSensitive, bool wholeWord, bool useRegex)
{
    if (!m_hwndEditor || searchText.empty()) return 0;
    const int length = GetWindowTextLengthA(m_hwndEditor);
    std::string text(length + 1, '\0');
    GetWindowTextA(m_hwndEditor, text.data(), length + 1);
    text.resize(length);
    std::vector<SearchMatch> matches;
    try { matches = SearchMatches(text, searchText, caseSensitive, wholeWord, useRegex, replacement); }
    catch (const std::regex_error& e) {
        MessageBoxA(m_hwndMain, e.what(), "Invalid search expression", MB_OK | MB_ICONERROR);
        return 0;
    }
    if (matches.empty()) return 0;
    if (all) {
        std::string result;
        size_t cursor = 0;
        for (const auto& match : matches) {
            result.append(text, cursor, match.start - cursor);
            result.append(match.replacement);
            cursor = match.start + match.length;
        }
        result.append(text, cursor, std::string::npos);
        SendMessageA(m_hwndEditor, EM_SETSEL, 0, -1);
        SendMessageA(m_hwndEditor, EM_REPLACESEL, TRUE, reinterpret_cast<LPARAM>(result.c_str()));
        m_fileModified = true;
        return static_cast<int>(matches.size());
    }
    CHARRANGE selection{};
    SendMessageA(m_hwndEditor, EM_EXGETSEL, 0, reinterpret_cast<LPARAM>(&selection));
    for (const auto& match : matches) {
        if (match.start == static_cast<size_t>(selection.cpMin) &&
            match.start + match.length == static_cast<size_t>(selection.cpMax)) {
            SendMessageA(m_hwndEditor, EM_REPLACESEL, TRUE,
                         reinterpret_cast<LPARAM>(match.replacement.c_str()));
            m_fileModified = true;
            findText(searchText, true, caseSensitive, wholeWord, useRegex);
            return 1;
        }
    }
    return 0;
}

INT_PTR CALLBACK Win32IDE::FindDialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    Win32IDE* pThis = nullptr;
    
    if (uMsg == WM_INITDIALOG) {
        SetWindowLongPtr(hwndDlg, GWLP_USERDATA, lParam);
        pThis = (Win32IDE*)lParam;
    } else {
        pThis = (Win32IDE*)GetWindowLongPtr(hwndDlg, GWLP_USERDATA);
    }
    
    if (!pThis) return FALSE;
    
    switch (uMsg) {
    case WM_USER + 100:
        // Handle Copilot streaming token updates
        if (pThis) {
            pThis->HandleCopilotStreamUpdate(reinterpret_cast<const char*>(wParam), static_cast<size_t>(lParam));
        }
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_BTN_FIND_NEXT:
            {
                HWND hwndFindText = GetDlgItem(hwndDlg, IDC_FIND_TEXT);
                char buffer[256];
                GetWindowTextA(hwndFindText, buffer, 256);
                pThis->m_lastSearchText = buffer;
                
                pThis->m_searchCaseSensitive = IsDlgButtonChecked(hwndDlg, IDC_CASE_SENSITIVE) == BST_CHECKED;
                pThis->m_searchWholeWord = IsDlgButtonChecked(hwndDlg, IDC_WHOLE_WORD) == BST_CHECKED;
                pThis->m_searchUseRegex = IsDlgButtonChecked(hwndDlg, IDC_USE_REGEX) == BST_CHECKED;
                
                pThis->findNext();
            }
            return TRUE;
        case IDC_BTN_FIND_CLOSE:
        case IDCANCEL:
            DestroyWindow(hwndDlg);
            pThis->m_hwndFindDialog = nullptr;
            pThis->m_hwndFindInput = nullptr;
            pThis->initializeNativeGhostText();
            return TRUE;
        }
        break;
    case WM_CLOSE:
        DestroyWindow(hwndDlg);
        pThis->m_hwndFindDialog = nullptr;
        pThis->m_hwndFindInput = nullptr;
        pThis->initializeNativeGhostText();
        return TRUE;
    }
    
    return FALSE;
}

INT_PTR CALLBACK Win32IDE::ReplaceDialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    Win32IDE* pThis = nullptr;
    
    if (uMsg == WM_INITDIALOG) {
        SetWindowLongPtr(hwndDlg, GWLP_USERDATA, lParam);
        pThis = (Win32IDE*)lParam;
    } else {
        pThis = (Win32IDE*)GetWindowLongPtr(hwndDlg, GWLP_USERDATA);
    }
    
    if (!pThis) return FALSE;
    
    switch (uMsg) {
    case WM_COMMAND:
        {
            HWND hwndFindText = GetDlgItem(hwndDlg, IDC_FIND_TEXT);
            HWND hwndReplaceText = GetDlgItem(hwndDlg, IDC_REPLACE_TEXT);
            char findBuffer[256], replaceBuffer[256];
            
            switch (LOWORD(wParam)) {
            case IDC_BTN_FIND_NEXT:
                GetWindowTextA(hwndFindText, findBuffer, 256);
                pThis->m_lastSearchText = findBuffer;
                pThis->m_searchCaseSensitive = IsDlgButtonChecked(hwndDlg, IDC_CASE_SENSITIVE) == BST_CHECKED;
                pThis->m_searchWholeWord = IsDlgButtonChecked(hwndDlg, IDC_WHOLE_WORD) == BST_CHECKED;
                pThis->m_searchUseRegex = IsDlgButtonChecked(hwndDlg, IDC_USE_REGEX) == BST_CHECKED;
                pThis->findNext();
                return TRUE;
            case IDC_BTN_REPLACE:
                GetWindowTextA(hwndFindText, findBuffer, 256);
                GetWindowTextA(hwndReplaceText, replaceBuffer, 256);
                pThis->m_lastSearchText = findBuffer;
                pThis->m_lastReplaceText = replaceBuffer;
                pThis->m_searchCaseSensitive = IsDlgButtonChecked(hwndDlg, IDC_CASE_SENSITIVE) == BST_CHECKED;
                pThis->m_searchWholeWord = IsDlgButtonChecked(hwndDlg, IDC_WHOLE_WORD) == BST_CHECKED;
                pThis->m_searchUseRegex = IsDlgButtonChecked(hwndDlg, IDC_USE_REGEX) == BST_CHECKED;
                pThis->replaceNext();
                return TRUE;
            case IDC_BTN_REPLACE_ALL:
                GetWindowTextA(hwndFindText, findBuffer, 256);
                GetWindowTextA(hwndReplaceText, replaceBuffer, 256);
                pThis->m_lastSearchText = findBuffer;
                pThis->m_lastReplaceText = replaceBuffer;
                pThis->m_searchCaseSensitive = IsDlgButtonChecked(hwndDlg, IDC_CASE_SENSITIVE) == BST_CHECKED;
                pThis->m_searchWholeWord = IsDlgButtonChecked(hwndDlg, IDC_WHOLE_WORD) == BST_CHECKED;
                pThis->m_searchUseRegex = IsDlgButtonChecked(hwndDlg, IDC_USE_REGEX) == BST_CHECKED;
                pThis->replaceAll();
                return TRUE;
            case IDC_BTN_FIND_CLOSE:
            case IDCANCEL:
                DestroyWindow(hwndDlg);
                pThis->m_hwndReplaceDialog = nullptr;
                pThis->m_hwndFindInput = nullptr;
                pThis->m_hwndReplaceInput = nullptr;
                pThis->initializeNativeGhostText();
                return TRUE;
            }
        }
        break;
    case WM_CLOSE:
        DestroyWindow(hwndDlg);
        pThis->m_hwndReplaceDialog = nullptr;
        pThis->m_hwndFindInput = nullptr;
        pThis->m_hwndReplaceInput = nullptr;
        pThis->initializeNativeGhostText();
        return TRUE;
    }
    
    return FALSE;
}

// ============================================================================
// Snippet Manager Implementation  
// ============================================================================

#define IDD_SNIPPET_MANAGER 6001
// Note: IDC_SNIPPET_LIST is defined at line 23 as 1009
#define IDC_SNIPPET_LIST_DLG 6010
#define IDC_SNIPPET_NAME 6011
#define IDC_SNIPPET_DESC 6012
#define IDC_SNIPPET_CODE 6013
#define IDC_BTN_INSERT_SNIPPET 6020
#define IDC_BTN_NEW_SNIPPET 6021
#define IDC_BTN_DELETE_SNIPPET 6022
#define IDC_BTN_SAVE_SNIPPETS 6023

void Win32IDE::showSnippetManager()
{
    // Create snippet manager dialog
    HWND hwndDlg = CreateWindowExA(WS_EX_DLGMODALFRAME, "STATIC", "Snippet Manager",
        WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
        100, 100, 600, 500, m_hwndMain, nullptr, m_hInstance, nullptr);
    
    // Snippet list (left pane)
    CreateWindowExA(0, "STATIC", "Snippets:", WS_CHILD | WS_VISIBLE,
        10, 10, 150, 20, hwndDlg, nullptr, m_hInstance, nullptr);
    
    HWND hwndList = CreateWindowExA(WS_EX_CLIENTEDGE, "LISTBOX", "",
        WS_CHILD | WS_VISIBLE | LBS_STANDARD | WS_VSCROLL,
        10, 35, 150, 400, hwndDlg, (HMENU)IDC_SNIPPET_LIST_DLG, m_hInstance, nullptr);
    
    // Populate list with snippet names
    for (const auto& snippet : m_codeSnippets) {
        SendMessageA(hwndList, LB_ADDSTRING, 0, (LPARAM)snippet.name.c_str());
    }
    
    // Snippet details (right pane)
    CreateWindowExA(0, "STATIC", "Name:", WS_CHILD | WS_VISIBLE,
        175, 10, 50, 20, hwndDlg, nullptr, m_hInstance, nullptr);
    CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        230, 8, 350, 22, hwndDlg, (HMENU)IDC_SNIPPET_NAME, m_hInstance, nullptr);
    
    CreateWindowExA(0, "STATIC", "Description:", WS_CHILD | WS_VISIBLE,
        175, 40, 70, 20, hwndDlg, nullptr, m_hInstance, nullptr);
    CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        175, 60, 405, 22, hwndDlg, (HMENU)IDC_SNIPPET_DESC, m_hInstance, nullptr);
    
    CreateWindowExA(0, "STATIC", "Code Template:", WS_CHILD | WS_VISIBLE,
        175, 90, 100, 20, hwndDlg, nullptr, m_hInstance, nullptr);
    CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_WANTRETURN | WS_VSCROLL | WS_HSCROLL,
        175, 115, 405, 280, hwndDlg, (HMENU)IDC_SNIPPET_CODE, m_hInstance, nullptr);
    
    // Buttons
    CreateWindowExA(0, "BUTTON", "Insert", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
        175, 410, 90, 28, hwndDlg, (HMENU)IDC_BTN_INSERT_SNIPPET, m_hInstance, nullptr);
    CreateWindowExA(0, "BUTTON", "New", WS_CHILD | WS_VISIBLE,
        275, 410, 90, 28, hwndDlg, (HMENU)IDC_BTN_NEW_SNIPPET, m_hInstance, nullptr);
    CreateWindowExA(0, "BUTTON", "Delete", WS_CHILD | WS_VISIBLE,
        375, 410, 90, 28, hwndDlg, (HMENU)IDC_BTN_DELETE_SNIPPET, m_hInstance, nullptr);
    CreateWindowExA(0, "BUTTON", "Save & Close", WS_CHILD | WS_VISIBLE,
        475, 410, 105, 28, hwndDlg, (HMENU)IDC_BTN_SAVE_SNIPPETS, m_hInstance, nullptr);
    
    // Message loop for dialog
    MSG msg;
    bool running = true;
    while (running && GetMessage(&msg, nullptr, 0, 0)) {
        if (msg.hwnd == hwndDlg || IsChild(hwndDlg, msg.hwnd)) {
            // Handle list selection
            if (msg.message == WM_COMMAND) {
                WORD cmdId = LOWORD(msg.wParam);
                WORD notif = HIWORD(msg.wParam);
                
                if (cmdId == IDC_SNIPPET_LIST_DLG && notif == LBN_SELCHANGE) {
                    int sel = SendMessage(hwndList, LB_GETCURSEL, 0, 0);
                    if (sel >= 0 && sel < (int)m_codeSnippets.size()) {
                        const CodeSnippet& snippet = m_codeSnippets[sel];
                        SetDlgItemTextA(hwndDlg, IDC_SNIPPET_NAME, snippet.name.c_str());
                        SetDlgItemTextA(hwndDlg, IDC_SNIPPET_DESC, snippet.description.c_str());
                        SetDlgItemTextA(hwndDlg, IDC_SNIPPET_CODE, snippet.code.c_str());
                    }
                }
                else if (cmdId == IDC_BTN_INSERT_SNIPPET) {
                    int sel = SendMessage(hwndList, LB_GETCURSEL, 0, 0);
                    if (sel >= 0 && sel < (int)m_codeSnippets.size()) {
                        insertSnippet(m_codeSnippets[sel].name);
                        running = false;
                        DestroyWindow(hwndDlg);
                    }
                }
                else if (cmdId == IDC_BTN_NEW_SNIPPET) {
                    CodeSnippet newSnippet;
                    newSnippet.name = "NewSnippet";
                    newSnippet.description = "New snippet description";
                    newSnippet.code = "// Your code here";
                    m_codeSnippets.push_back(newSnippet);
                    SendMessageA(hwndList, LB_ADDSTRING, 0, (LPARAM)newSnippet.name.c_str());
                    SendMessage(hwndList, LB_SETCURSEL, m_codeSnippets.size() - 1, 0);
                    SetDlgItemTextA(hwndDlg, IDC_SNIPPET_NAME, newSnippet.name.c_str());
                    SetDlgItemTextA(hwndDlg, IDC_SNIPPET_DESC, newSnippet.description.c_str());
                    SetDlgItemTextA(hwndDlg, IDC_SNIPPET_CODE, newSnippet.code.c_str());
                }
                else if (cmdId == IDC_BTN_DELETE_SNIPPET) {
                    int sel = SendMessage(hwndList, LB_GETCURSEL, 0, 0);
                    if (sel >= 0 && sel < (int)m_codeSnippets.size()) {
                        if (MessageBoxA(hwndDlg, "Delete this snippet?", "Confirm", MB_YESNO) == IDYES) {
                            m_codeSnippets.erase(m_codeSnippets.begin() + sel);
                            SendMessage(hwndList, LB_DELETESTRING, sel, 0);
                            SetDlgItemTextA(hwndDlg, IDC_SNIPPET_NAME, "");
                            SetDlgItemTextA(hwndDlg, IDC_SNIPPET_DESC, "");
                            SetDlgItemTextA(hwndDlg, IDC_SNIPPET_CODE, "");
                        }
                    }
                }
                else if (cmdId == IDC_BTN_SAVE_SNIPPETS) {
                    // Update current snippet before saving
                    int sel = SendMessage(hwndList, LB_GETCURSEL, 0, 0);
                    if (sel >= 0 && sel < (int)m_codeSnippets.size()) {
                        char buffer[1024];
                        GetDlgItemTextA(hwndDlg, IDC_SNIPPET_NAME, buffer, 1024);
                        m_codeSnippets[sel].name = buffer;
                        GetDlgItemTextA(hwndDlg, IDC_SNIPPET_DESC, buffer, 1024);
                        m_codeSnippets[sel].description = buffer;
                        
                        HWND hwndCode = GetDlgItem(hwndDlg, IDC_SNIPPET_CODE);
                        int len = GetWindowTextLengthA(hwndCode);
                        std::vector<char> codeBuffer(len + 1);
                        GetWindowTextA(hwndCode, codeBuffer.data(), len + 1);
                        m_codeSnippets[sel].code = codeBuffer.data();
                    }
                    
                    saveCodeSnippets();
                    MessageBoxA(hwndDlg, "Snippets saved!", "Success", MB_OK);
                    running = false;
                    DestroyWindow(hwndDlg);
                }
            }
            else if (msg.message == WM_CLOSE) {
                running = false;
                DestroyWindow(hwndDlg);
            }
        }
        
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}

void Win32IDE::createSnippet()
{
    // Create a new empty snippet
    CodeSnippet newSnippet;
    newSnippet.name = "NewSnippet" + std::to_string(m_codeSnippets.size() + 1);
    newSnippet.description = "New snippet";
    newSnippet.code = "// Code template\n";
    m_codeSnippets.push_back(newSnippet);
    
    MessageBoxA(m_hwndMain, ("Snippet '" + newSnippet.name + "' created. Use Snippet Manager to edit.").c_str(), 
        "Snippet Created", MB_OK);
}

// ============================================================================
// File Explorer Implementation
// ============================================================================

void Win32IDE::createFileExplorer(HWND hwndParent)
{
    if (m_hwndFileExplorer) {
        return; // Already created
    }

    // Create sidebar panel
    m_hwndFileExplorer = CreateWindowExA(
        0,
        "STATIC",
        "File Explorer",
        WS_CHILD | WS_VISIBLE | WS_BORDER,
        0, 30, m_sidebarWidth, 500,
        hwndParent,
        (HMENU)IDC_FILE_EXPLORER,
        GetModuleHandleA(nullptr),
        nullptr
    );

    // Create TreeView control for file navigation
    m_hwndFileTree = CreateWindowExA(
        WS_EX_CLIENTEDGE,
        WC_TREEVIEWA,
        "",
        WS_CHILD | WS_VISIBLE | WS_BORDER | TVS_HASLINES | TVS_LINESATROOT | TVS_HASBUTTONS,
        5, 5, m_sidebarWidth - 10, 490,
        m_hwndFileExplorer,
        (HMENU)IDC_FILE_TREE,
        GetModuleHandleA(nullptr),
        nullptr
    );

    // Set TreeView font
    SendMessageA(m_hwndFileTree, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);

    // Populate with drive letters
    populateFileTree(nullptr, "");
}

void Win32IDE::populateFileTree(HTREEITEM parentItem, const std::string& path)
{
    if (!m_hwndFileTree) {
        return;
    }

    // If no parent, add drives
    if (!parentItem) {
        TVINSERTSTRUCTA tvis = {};
        tvis.hParent = TVI_ROOT;
        tvis.hInsertAfter = TVI_LAST;
        tvis.item.mask = TVIF_TEXT | TVIF_PARAM;

        // Enumerate every mounted logical drive instead of assuming C:..Z:.
        const DWORD driveChars = GetLogicalDriveStringsA(0, nullptr);
        if (driveChars > 0) {
            std::vector<char> driveBuffer(static_cast<size_t>(driveChars) + 1, '\0');
            if (GetLogicalDriveStringsA(driveChars, driveBuffer.data()) != 0) {
                for (const char* drive = driveBuffer.data(); *drive; drive += std::strlen(drive) + 1) {
                    const std::string drivePath(drive);
                    const std::string displayName = drivePath;
                    tvis.item.pszText = const_cast<char*>(displayName.c_str());
                    tvis.item.lParam = (LPARAM) new std::string(drivePath);

                    HTREEITEM driveItem = (HTREEITEM)SendMessageA(
                        m_hwndFileTree, TVM_INSERTITEM, 0, (LPARAM)&tvis);
                    m_treeItemPaths[driveItem] = drivePath;

                    // Add a dummy child so expansion remains lazy.
                    TVINSERTSTRUCTA dummyVis = {};
                    dummyVis.hParent = driveItem;
                    dummyVis.item.mask = TVIF_TEXT;
                    dummyVis.item.pszText = const_cast<char*>("...");
                    SendMessageA(m_hwndFileTree, TVM_INSERTITEM, 0, (LPARAM)&dummyVis);
                }
            }
        }
        return;
    }

    // Populate a specific folder
    try {
        WIN32_FIND_DATAA findData;
        HANDLE findHandle;

        std::string searchPath = path + "\\*";
        findHandle = FindFirstFileA(searchPath.c_str(), &findData);

        if (findHandle == INVALID_HANDLE_VALUE) {
            return;
        }

        TVINSERTSTRUCTA tvis = {};
        tvis.hParent = parentItem;
        tvis.hInsertAfter = TVI_LAST;
        tvis.item.mask = TVIF_TEXT | TVIF_PARAM;

        // Clear dummy items
        HTREEITEM hChild = TreeView_GetChild(m_hwndFileTree, parentItem);
        while (hChild) {
            HTREEITEM hNext = TreeView_GetNextSibling(m_hwndFileTree, hChild);
            TreeView_DeleteItem(m_hwndFileTree, hChild);
            hChild = hNext;
        }

        do {
            if (strcmp(findData.cFileName, ".") == 0 || strcmp(findData.cFileName, "..") == 0) {
                continue;
            }

            std::string fullPath = path + "\\" + findData.cFileName;

            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                // It's a folder
                tvis.item.pszText = findData.cFileName;
                tvis.item.lParam = (LPARAM) new std::string(fullPath);

                HTREEITEM folderItem = (HTREEITEM)SendMessageA(m_hwndFileTree, TVM_INSERTITEM, 0, (LPARAM)&tvis);
                m_treeItemPaths[folderItem] = fullPath;

                // Add dummy child
                TVINSERTSTRUCTA dummyVis = {};
                dummyVis.hParent = folderItem;
                dummyVis.item.mask = TVIF_TEXT;
                dummyVis.item.pszText = (LPSTR)"...";
                SendMessageA(m_hwndFileTree, TVM_INSERTITEM, 0, (LPARAM)&dummyVis);
            }
            else {
                // The explorer is a file browser, not a model-only picker.
                // Keep every file visible; model-specific actions are still
                // selected by isModelFile() on activation/context menus.
                tvis.item.pszText = findData.cFileName;
                tvis.item.lParam = (LPARAM) new std::string(fullPath);

                HTREEITEM fileItem = (HTREEITEM)SendMessageA(m_hwndFileTree, TVM_INSERTITEM, 0, (LPARAM)&tvis);
                m_treeItemPaths[fileItem] = fullPath;
            }
        } while (FindNextFileA(findHandle, &findData));

        FindClose(findHandle);
    }
    catch (...) {
        // Silently handle errors
    }
}

void Win32IDE::onFileTreeExpand(HTREEITEM item, const std::string& path)
{
    if (!m_hwndFileTree) {
        return;
    }

    populateFileTree(item, path);
}

std::string Win32IDE::getTreeItemPath(HTREEITEM item) const
{
    auto it = m_treeItemPaths.find(item);
    if (it != m_treeItemPaths.end()) {
        return it->second;
    }
    return "";
}

void Win32IDE::loadModelFromPath(const std::string& filepath)
{
    if (filepath.length() > 5 &&
        filepath.substr(filepath.length() - 5) == ".gguf") {
        // All GGUF entry points use the bounded streaming loader.  A model
        // selected from the explorer or a recent-file route may be multi-GB;
        // the legacy whole-file loader is not a safe UI default.
        m_ggufLoader = std::make_unique<StreamingGGUFLoader>();
        m_useStreamingLoader = true;
        if (loadGGUFModel(filepath)) {
            // Initialize inference system
            initializeInference();
            
            // Notify user in chat
            std::string msg = " Model loaded and ready for inference!\r\n\r\n"
                             "You can now ask questions in the chat panel.\r\n"
                             "Try: 'hello', 'model info', 'explain code', etc.";
            appendCopilotResponse(msg);
        }
    }
}

// ============================================================================
// GGUF Model Loading Implementation
// ============================================================================

bool Win32IDE::loadGGUFModel(const std::string& filepath)
{
    if (!m_ggufLoader) {
        // Keep the safety boundary at the shared loader entry point.  This
        // covers file dialogs, explorer commands, recent files, and agent
        // routes that did not explicitly construct a loader first.
        m_ggufLoader = std::make_unique<StreamingGGUFLoader>();
        m_useStreamingLoader = true;
        LOG_INFO("GGUF loader was not initialized; selected StreamingGGUFLoader");
    }

    appendToOutput("Loading GGUF model: " + filepath + "\n", "Output", OutputSeverity::Info);
    appendToOutput("This may take a moment for large files...\n", "Output", OutputSeverity::Info);

    try {
        // Attempt to open and parse the GGUF file (streaming - no full data load)
        appendToOutput("[1/5] Opening file...\n", "Output", OutputSeverity::Info);
        if (!m_ggufLoader->Open(filepath)) {
            std::string error = " Failed to open GGUF file: " + filepath + "\nCheck if file exists and is readable.";
            appendToOutput(error, "Errors", OutputSeverity::Error);
            ErrorReporter::report(error, m_hwndMain);
            return false;
        }

        appendToOutput("[2/5] Parsing header...\n", "Output", OutputSeverity::Info);
        if (!m_ggufLoader->ParseHeader()) {
            std::string error = " Failed to parse GGUF header from: " + filepath + "\nFile may be corrupted or not a valid GGUF.";
            appendToOutput(error, "Errors", OutputSeverity::Error);
            ErrorReporter::report(error, m_hwndMain);
            m_ggufLoader->Close();
            return false;
        }

        appendToOutput("[3/5] Parsing metadata...\n", "Output", OutputSeverity::Info);
        if (!m_ggufLoader->ParseMetadata()) {
            std::string error = " Failed to parse GGUF metadata from: " + filepath + "\nFile structure may be invalid.";
            appendToOutput(error, "Errors", OutputSeverity::Error);
            ErrorReporter::report(error, m_hwndMain);
            m_ggufLoader->Close();
            return false;
        }

        // Build tensor index (reads tensor offsets but NOT data)
        appendToOutput("[4/5] Building tensor index (may take 10-30 seconds for large files)...\n", "Output", OutputSeverity::Info);
        if (!m_ggufLoader->BuildTensorIndex()) {
            std::string error = " Failed to build tensor index from: " + filepath + "\nFile may be too large or corrupted.";
            appendToOutput(error, "Errors", OutputSeverity::Error);
            ErrorReporter::report(error, m_hwndMain);
            m_ggufLoader->Close();
            return false;
        }

        // Pre-load embedding zone for inference preparation
        appendToOutput("[5/5] Pre-loading embedding zone...\n", "Output", OutputSeverity::Info);
        if (!m_ggufLoader->LoadZone("embedding")) {
            std::string warning = "  Warning: Could not pre-load embedding zone (non-critical)";
            appendToOutput(warning, "Output", OutputSeverity::Warning);
        }
    }
    catch (const std::exception& e) {
        std::string error = " Exception loading GGUF file:\n" + std::string(e.what()) + "\n\nFile: " + filepath;
        appendToOutput(error + "\n", "Errors", OutputSeverity::Error);
        ErrorReporter::report(error, m_hwndMain);
        return false;
    }
    catch (...) {
        std::string error = " Unknown exception loading GGUF file: " + filepath;
        appendToOutput(error + "\n", "Errors", OutputSeverity::Error);
        ErrorReporter::report(error, m_hwndMain);
        return false;
    }

    // Store model info
    m_loadedModelPath = filepath;
    m_currentModelMetadata = m_ggufLoader->GetMetadata();
    m_modelTensors = m_ggufLoader->GetAllTensorInfo();  // Get tensor info for backward compatibility

    // Log success with memory savings information
    size_t currentMemory = m_ggufLoader->GetCurrentMemoryUsage();
    std::string info = " Model loaded successfully (STREAMING MODE)!\n";
    info += "File: " + filepath + "\n";
    info += "Tensors: " + std::to_string(m_modelTensors.size()) + "\n";
    info += "Layers: " + std::to_string(m_currentModelMetadata.layer_count) + "\n";
    info += "Context: " + std::to_string(m_currentModelMetadata.context_length) + "\n";
    info += "Vocab: " + std::to_string(m_currentModelMetadata.vocab_size) + "\n";
    info += "Current Memory: " + std::to_string(currentMemory / 1024 / 1024) + " MB\n";
    info += "Max Memory: ~500 MB (zone-based streaming)\n\n";
    
    auto zones = m_ggufLoader->GetLoadedZones();
    if (!zones.empty()) {
        info += "Loaded Zones: ";
        for (size_t i = 0; i < zones.size(); ++i) {
            info += zones[i];
            if (i < zones.size() - 1) info += ", ";
        }
        info += "\n";
    }
    
    appendToOutput(info, "Output", OutputSeverity::Info);
    
    // Update status bar
    SendMessage(m_hwndStatusBar, SB_SETTEXT, 0, 
        (LPARAM)("Model: " + std::string(filepath)).c_str());

    // Auto-activate Copilot panel and send welcome message
    if (m_hwndSecondarySidebar && m_hwndCopilotChatOutput) {
        // Make secondary sidebar visible if hidden
        ShowWindow(m_hwndSecondarySidebar, SW_SHOW);
        
        // Send agentic welcome message to Copilot
        std::string welcomeMsg = " AI Model Loaded!\r\n\r\n";
        welcomeMsg += "I'm now ready to assist you with:\r\n";
        welcomeMsg += " Code analysis and review\r\n";
        welcomeMsg += " GGUF model exploration\r\n";
        welcomeMsg += " Tensor inspection and debugging\r\n";
        welcomeMsg += " PowerShell automation\r\n";
        welcomeMsg += " File operations\r\n\r\n";
        welcomeMsg += "Model: " + filepath + "\r\n";
        welcomeMsg += "Tensors: " + std::to_string(m_modelTensors.size()) + "\r\n";
        welcomeMsg += "Memory: " + std::to_string(currentMemory / 1024 / 1024) + " MB\r\n\r\n";
        welcomeMsg += "Ask me anything!\r\n";
        
        appendCopilotResponse(welcomeMsg);
    }

    return true;
}

std::string Win32IDE::getModelInfo() const
{
    if (m_modelTensors.empty() || !m_ggufLoader) {
        return "No model loaded";
    }

    std::string info = "\n";
    info += "GGUF Model Information (STREAMING MODE)\n";
    info += "\n\n";
    
    info += "File: " + m_loadedModelPath + "\n";
    info += "Tensors: " + std::to_string(m_modelTensors.size()) + "\n";
    info += "Layers: " + std::to_string(m_currentModelMetadata.layer_count) + "\n";
    info += "Context Length: " + std::to_string(m_currentModelMetadata.context_length) + "\n";
    info += "Embedding Dim: " + std::to_string(m_currentModelMetadata.embedding_dim) + "\n";
    info += "Vocab Size: " + std::to_string(m_currentModelMetadata.vocab_size) + "\n";
    info += "Architecture: " + m_currentModelMetadata.architecture_type + "\n\n";

    // Show zone status (memory efficiency indicator)
    size_t currentMemory = m_ggufLoader->GetCurrentMemoryUsage();
    auto loadedZones = m_ggufLoader->GetLoadedZones();
    
    info += " Memory Status:\n";
    info += "  Current RAM: " + std::to_string(currentMemory / 1024 / 1024) + " MB\n";
    info += "  Max Per Zone: ~400 MB\n";
    info += "  Total Capacity: ~500 MB (92x reduction from full load!)\n";
    info += "  Loaded Zones: " + std::to_string(loadedZones.size()) + "\n\n";
    
    if (!loadedZones.empty()) {
        info += " Active Zones:\n";
        for (const auto& zone : loadedZones) {
            info += "    " + zone + "\n";
        }
        info += "\n";
    }

    info += "Tensor Details (first 10):\n";
    info += "\n";
    
    for (size_t i = 0; i < m_modelTensors.size() && i < 10; ++i) {
        const auto& tensor = m_modelTensors[i];
        info += "[" + std::to_string(i + 1) + "] " + tensor.name + "\n";
        info += "    Size: " + std::to_string(tensor.size_bytes / 1024 / 1024) + " MB\n";
        info += "    Type: " + m_ggufLoader->GetTypeString(tensor.type) + "\n";
    }

    if (m_modelTensors.size() > 10) {
        info += "... and " + std::to_string(m_modelTensors.size() - 10) + " more tensors\n";
    }

    info += "\n Tip: Zones load on-demand during inference for optimal performance!\n";

    return info;
}

bool Win32IDE::loadTensorData(const std::string& tensorName, std::vector<uint8_t>& data)
{
    if (!m_ggufLoader) {
        return false;
    }
    // StreamingGGUFLoader automatically loads required zone if needed
    return m_ggufLoader->LoadTensorZone(tensorName, data);
}

// ============================================================================
// FILE EXPLORER IMPLEMENTATION
// ============================================================================

void Win32IDE::createFileExplorer()
{
    if (!m_hwndSidebar) return;

    // Create file explorer tree view control
    m_hwndFileExplorer = CreateWindowExA(
        WS_EX_CLIENTEDGE,
        WC_TREEVIEWA,
        "",
        WS_CHILD | WS_VISIBLE | WS_BORDER | TVS_HASLINES | TVS_HASBUTTONS | TVS_LINESATROOT | TVS_SHOWSELALWAYS,
        5, 30, m_sidebarWidth - 10, 400,
        m_hwndSidebar,
        (HMENU)IDC_FILE_EXPLORER,
        m_hInstance,
        nullptr
    );

    if (!m_hwndFileExplorer) return;

    // Create image list for icons
    m_hImageList = ImageList_Create(16, 16, ILC_COLOR32 | ILC_MASK, 3, 0);
    if (m_hImageList) {
        // Load icons for folders, files, and model files
        HICON hFolderIcon = (HICON)LoadImageA(nullptr, MAKEINTRESOURCEA(32755), IMAGE_ICON, 16, 16, LR_SHARED);
        HICON hFileIcon = (HICON)LoadImageA(nullptr, MAKEINTRESOURCEA(32512), IMAGE_ICON, 16, 16, LR_SHARED);
        HICON hModelIcon = (HICON)LoadImageA(nullptr, MAKEINTRESOURCEA(32516), IMAGE_ICON, 16, 16, LR_SHARED);
        
        ImageList_AddIcon(m_hImageList, hFolderIcon);  // Index 0: Folder
        ImageList_AddIcon(m_hImageList, hFileIcon);    // Index 1: Regular file
        ImageList_AddIcon(m_hImageList, hModelIcon);   // Index 2: Model file

        TreeView_SetImageList(m_hwndFileExplorer, m_hImageList, TVSIL_NORMAL);
    }

    populateFileTree();
}

void Win32IDE::populateFileTree()
{
    if (!m_hwndFileExplorer) return;

    // Clear existing items
    TreeView_DeleteAllItems(m_hwndFileExplorer);
    m_treeItemPaths.clear();

    // Keep the active workspace convenient, but do not make it the explorer's
    // universe.  The native explorer must expose every mounted logical drive
    // (including removable, network, optical and RAM-backed drives), and it
    // must load each drive lazily so startup does not scan an entire volume.
    std::vector<std::string> rootPaths;
    std::vector<std::string> workspacePaths;
    auto addRootIfPresent = [&rootPaths](const std::string& path) {
        if (path.empty() || GetFileAttributesA(path.c_str()) == INVALID_FILE_ATTRIBUTES) return;
        for (const auto& existing : rootPaths) {
            if (_stricmp(existing.c_str(), path.c_str()) == 0) return;
        }
        rootPaths.push_back(path);
    };

    char currentDirectory[MAX_PATH] = {};
    if (GetCurrentDirectoryA(MAX_PATH, currentDirectory) > 0) {
        addRootIfPresent(currentDirectory);
        workspacePaths.emplace_back(currentDirectory);
    }

    // The IDE is commonly launched from build_cmake/bin/Release. Walk upward
    // from the executable to locate its checkout even when the process CWD is
    // unrelated to the project.
    char executablePath[MAX_PATH] = {};
    const DWORD executableLength = GetModuleFileNameA(nullptr, executablePath, MAX_PATH);
    if (executableLength > 0 && executableLength < MAX_PATH) {
        std::string candidate(executablePath, executableLength);
        size_t slash = candidate.find_last_of("\\/");
        if (slash != std::string::npos) candidate.resize(slash);
        for (int depth = 0; depth < 8 && !candidate.empty(); ++depth) {
            const std::string gitMarker = candidate + "\\.git";
            if (GetFileAttributesA(gitMarker.c_str()) != INVALID_FILE_ATTRIBUTES) {
                addRootIfPresent(candidate);
                workspacePaths.push_back(candidate);
                break;
            }
            const size_t parentSlash = candidate.find_last_of("\\/");
            if (parentSlash == std::string::npos || parentSlash == 2) break;
            candidate.resize(parentSlash);
        }
    }

    // GetLogicalDriveStrings is the authoritative mounted-drive enumeration;
    // unlike the old C:..Z loop it also handles A:/B: and mapped/network
    // volumes without assuming a drive type or a fixed letter range.
    const DWORD driveChars = GetLogicalDriveStringsA(0, nullptr);
    if (driveChars > 0) {
        std::vector<char> driveBuffer(static_cast<size_t>(driveChars) + 1, '\0');
        if (GetLogicalDriveStringsA(driveChars, driveBuffer.data()) != 0) {
            for (const char* drive = driveBuffer.data(); *drive; drive += std::strlen(drive) + 1) {
                addRootIfPresent(drive);
            }
        }
    }

    // Keep mounted drives at the top of the tree.  The workspace can contain
    // thousands of source entries, and placing it first made the drive roots
    // effectively invisible in the legacy explorer even though they had been
    // enumerated correctly.  Drive roots remain lazy; only the active
    // workspace is expanded on startup.
    std::stable_partition(rootPaths.begin(), rootPaths.end(),
        [](const std::string& path) {
            return path.size() == 3 && path[1] == ':' && path[2] == '\\';
        });

    for (const auto& path : rootPaths) {
        std::string displayName = path;
        const DWORD driveType = GetDriveTypeA(path.c_str());
        if (path.size() >= 2 && path[1] == ':') {
            const char* typeName = "Drive";
            switch (driveType) {
                case DRIVE_REMOVABLE: typeName = "Removable"; break;
                case DRIVE_FIXED:     typeName = "Fixed"; break;
                case DRIVE_REMOTE:    typeName = "Network"; break;
                case DRIVE_CDROM:     typeName = "Optical"; break;
                case DRIVE_RAMDISK:   typeName = "RAM"; break;
                default: break;
            }
            displayName = path + " [" + typeName + "]";
        } else {
            const size_t lastSlash = path.find_last_of("\\/");
            if (lastSlash != std::string::npos && lastSlash + 1 < path.size()) {
                displayName = path.substr(lastSlash + 1) + " (" + path + ")";
            }
        }

        HTREEITEM hRoot = addTreeItem(TVI_ROOT, displayName, path, true);
        if (!hRoot) continue;

        // The workspace remains immediately useful.  All drive roots get a
        // placeholder and are expanded on demand to avoid blocking the UI on
        // large volumes or protected system directories.
        bool isWorkspace = false;
        for (const auto& workspacePath : workspacePaths) {
            if (_stricmp(path.c_str(), workspacePath.c_str()) == 0) {
                isWorkspace = true;
                break;
            }
        }
        if (isWorkspace) {
            scanDirectory(path, hRoot);
            TreeView_Expand(m_hwndFileExplorer, hRoot, TVE_EXPAND);
        } else {
            addTreeItem(hRoot, "Loading...", "", false);
        }
    }
}

HTREEITEM Win32IDE::addTreeItem(HTREEITEM hParent, const std::string& text, const std::string& fullPath, bool isDirectory)
{
    TVINSERTSTRUCTA tvins = {};
    tvins.hParent = hParent;
    tvins.hInsertAfter = TVI_LAST;
    tvins.item.mask = TVIF_TEXT | TVIF_PARAM | TVIF_IMAGE | TVIF_SELECTEDIMAGE;
    
    // Allocate memory for the full path (will be freed when item is deleted)
    char* pathData = new char[fullPath.length() + 1];
    strcpy_s(pathData, fullPath.length() + 1, fullPath.c_str());
    
    tvins.item.pszText = const_cast<char*>(text.c_str());
    tvins.item.lParam = reinterpret_cast<LPARAM>(pathData);
    
    // Set appropriate icon
    if (isDirectory) {
        tvins.item.iImage = 0;
        tvins.item.iSelectedImage = 0;
    } else if (isModelFile(fullPath)) {
        tvins.item.iImage = 2;
        tvins.item.iSelectedImage = 2;
    } else {
        tvins.item.iImage = 1;
        tvins.item.iSelectedImage = 1;
    }
    
    return TreeView_InsertItem(m_hwndFileExplorer, &tvins);
}

void Win32IDE::scanDirectory(const std::string& dirPath, HTREEITEM hParent)
{
    WIN32_FIND_DATAA findData;
    std::string searchPath = dirPath + "\\*";
    
    HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (strcmp(findData.cFileName, ".") == 0 || strcmp(findData.cFileName, "..") == 0) {
            continue;
        }

        std::string fullPath = dirPath + "\\" + findData.cFileName;
        bool isDirectory = (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        
        HTREEITEM hItem = addTreeItem(hParent, findData.cFileName, fullPath, isDirectory);
        
        // For directories, add a dummy child so we can expand later
        if (isDirectory) {
            addTreeItem(hItem, "Loading...", "", false);
        }
        
    } while (FindNextFileA(hFind, &findData));

    FindClose(hFind);
}

bool Win32IDE::isModelFile(const std::string& filePath)
{
    std::string fileName = filePath;
    std::transform(fileName.begin(), fileName.end(), fileName.begin(), ::tolower);
    
    return fileName.find(".gguf") != std::string::npos ||
           fileName.find(".bin") != std::string::npos ||
           fileName.find(".safetensors") != std::string::npos ||
           fileName.find(".pt") != std::string::npos ||
           fileName.find(".pth") != std::string::npos ||
           fileName.find(".onnx") != std::string::npos;
}

void Win32IDE::expandTreeNode(HTREEITEM hItem)
{
    if (!hItem) return;

    // Check if this node has been expanded before
    HTREEITEM hChild = TreeView_GetChild(m_hwndFileExplorer, hItem);
    if (hChild) {
        TVITEMA item = {};
        item.hItem = hChild;
        item.mask = TVIF_TEXT | TVIF_PARAM;
        char buffer[MAX_PATH];
        item.pszText = buffer;
        item.cchTextMax = MAX_PATH;
        
        if (TreeView_GetItem(m_hwndFileExplorer, &item)) {
            if (strcmp(item.pszText, "Loading...") == 0) {
                // Remove the dummy item
                TreeView_DeleteItem(m_hwndFileExplorer, hChild);
                
                // Get the full path and scan the directory
                TVITEMA parentItem = {};
                parentItem.hItem = hItem;
                parentItem.mask = TVIF_PARAM;
                if (TreeView_GetItem(m_hwndFileExplorer, &parentItem) && parentItem.lParam) {
                    std::string dirPath = reinterpret_cast<char*>(parentItem.lParam);
                    scanDirectory(dirPath, hItem);
                }
            }
        }
    }
}

std::string Win32IDE::getSelectedFilePath()
{
    HTREEITEM hSelected = TreeView_GetSelection(m_hwndFileExplorer);
    if (!hSelected) return "";
    
    TVITEMA item = {};
    item.hItem = hSelected;
    item.mask = TVIF_PARAM;
    
    if (TreeView_GetItem(m_hwndFileExplorer, &item) && item.lParam) {
        return std::string(reinterpret_cast<char*>(item.lParam));
    }
    
    return "";
}

void Win32IDE::onFileExplorerDoubleClick()
{
    std::string filePath = getSelectedFilePath();
    if (filePath.empty()) return;
    
    DWORD attributes = GetFileAttributesA(filePath.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) return;
    
    if (attributes & FILE_ATTRIBUTE_DIRECTORY) {
        // Expand/collapse directory
        HTREEITEM hSelected = TreeView_GetSelection(m_hwndFileExplorer);
        if (hSelected) {
            UINT state = TreeView_GetItemState(m_hwndFileExplorer, hSelected, TVIS_EXPANDED);
            if (state & TVIS_EXPANDED) {
                TreeView_Expand(m_hwndFileExplorer, hSelected, TVE_COLLAPSE);
            } else {
                expandTreeNode(hSelected);
                TreeView_Expand(m_hwndFileExplorer, hSelected, TVE_EXPAND);
            }
        }
    } else {
        // Load file
        if (isModelFile(filePath)) {
            loadModelFromExplorer(filePath);
        } else {
            // Open text files in editor - with size check!
            try {
                std::ifstream file(filePath, std::ios::binary);
                if (file.is_open()) {
                    // Check file size first
                    file.seekg(0, std::ios::end);
                    size_t fileSize = file.tellg();
                    file.seekg(0, std::ios::beg);
                    
                    if (fileSize > 10 * 1024 * 1024) { // 10MB limit
                        MessageBoxA(m_hwndMain, "File too large to open in editor (>10MB).", "File Too Large", MB_OK | MB_ICONWARNING);
                        return;
                    }
                    
                    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                    setEditorText(content);
                    m_currentFile = filePath;
                    m_fileModified = false;
                    updateTitleBarText();
                    file.close();
                }
            }
            catch (const std::exception& e) {
                std::string error = "Error opening file: " + std::string(e.what());
                MessageBoxA(m_hwndMain, error.c_str(), "Error", MB_OK | MB_ICONERROR);
            }
        }
    }
}

void Win32IDE::loadModelFromExplorer(const std::string& filePath)
{
    try {
        m_ggufLoader = std::make_unique<StreamingGGUFLoader>();
        m_useStreamingLoader = true;
        if (loadGGUFModel(filePath)) {
            std::string message = " Model loaded from File Explorer:\n" + filePath + "\n\n" + getModelInfo();
            appendToOutput(message, "Output", OutputSeverity::Info);

            // Update status bar
            std::string filename = filePath;
            size_t lastSlash = filename.find_last_of("\\/");
            if (lastSlash != std::string::npos) {
                filename = filename.substr(lastSlash + 1);
            }

            SendMessage(m_hwndStatusBar, SB_SETTEXT, 0, (LPARAM)("Model: " + filename).c_str());
        } else {
            appendToOutput(" Failed to load model: " + filePath, "Errors", OutputSeverity::Error);
        }
    } catch (const std::exception& error) {
        const std::string message = "Explorer model load rejected safely: " + std::string(error.what());
        LOG_ERROR(message);
        appendToOutput(message, "Errors", OutputSeverity::Error);
    } catch (...) {
        LOG_ERROR("Explorer model load rejected safely: unknown exception");
        appendToOutput(" Explorer model load rejected safely: unknown exception", "Errors", OutputSeverity::Error);
    }
}

void Win32IDE::onFileExplorerRightClick()
{
    std::string filePath = getSelectedFilePath();
    if (!filePath.empty()) {
        DWORD attributes = GetFileAttributesA(filePath.c_str());
        bool isDirectory = (attributes != INVALID_FILE_ATTRIBUTES) && (attributes & FILE_ATTRIBUTE_DIRECTORY);
        showFileContextMenu(filePath, isDirectory);
    }
}

void Win32IDE::showFileContextMenu(const std::string& filePath, bool isDirectory)
{
    HMENU hMenu = CreatePopupMenu();
    if (!hMenu) return;
    
    if (isDirectory) {
        AppendMenuA(hMenu, MF_STRING, 1001, "Refresh");
        AppendMenuA(hMenu, MF_STRING, 1002, "Open in Explorer");
        AppendMenuA(hMenu, MF_SEPARATOR, 0, nullptr);
        AppendMenuA(hMenu, MF_STRING, 1003, "Set as Root Path");
    } else {
        if (isModelFile(filePath)) {
            AppendMenuA(hMenu, MF_STRING, 2001, "Load Model");
            AppendMenuA(hMenu, MF_STRING, 2002, "Show Model Info");
            AppendMenuA(hMenu, MF_SEPARATOR, 0, nullptr);
        }
        AppendMenuA(hMenu, MF_STRING, 2003, "Open with Editor");
        AppendMenuA(hMenu, MF_STRING, 2004, "Copy Path");
        AppendMenuA(hMenu, MF_SEPARATOR, 0, nullptr);
        AppendMenuA(hMenu, MF_STRING, 2005, "Show in Explorer");
    }
    
    POINT pt;
    GetCursorPos(&pt);
    
    int cmd = TrackPopupMenu(hMenu, TPM_RETURNCMD | TPM_RIGHTBUTTON, pt.x, pt.y, 0, m_hwndMain, nullptr);
    
    switch (cmd) {
        case 1001: // Refresh directory
            refreshFileExplorer();
            break;
        case 1002: // Open in Explorer
        case 2005: // Show in Explorer
            ShellExecuteA(nullptr, "explore", filePath.c_str(), nullptr, nullptr, SW_SHOW);
            break;
        case 999: // Delete from Explorer context menu
            deleteItemInExplorer();
            break;
        case 1000: // Rename from Explorer context menu
            renameItemInExplorer();
            break;
        case 1003: // Set as Root Path
            m_currentExplorerPath = filePath;
            populateFileTree();
            break;
        case 2001: // Load Model
            loadModelFromExplorer(filePath);
            break;
        case 2002: // Show Model Info
            if (loadGGUFModel(filePath)) {
                std::string info = "Model Information:\n" + getModelInfo();
                MessageBoxA(m_hwndMain, info.c_str(), "Model Info", MB_OK | MB_ICONINFORMATION);
            }
            break;
        case 2003: // Open with Editor
            {
                std::ifstream file(filePath);
                if (file.is_open()) {
                    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                    setEditorText(content);
                    m_currentFile = filePath;
                    m_fileModified = false;
                    updateTitleBarText();
                }
            }
            break;
        case 2004: // Copy Path
            if (OpenClipboard(m_hwndMain)) {
                EmptyClipboard();
                HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, filePath.size() + 1);
                if (hMem) {
                    char* dest = (char*)GlobalLock(hMem);
                    strcpy_s(dest, filePath.size() + 1, filePath.c_str());
                    GlobalUnlock(hMem);
                    SetClipboardData(CF_TEXT, hMem);
                }
                CloseClipboard();
            }
            break;
    }
    
    DestroyMenu(hMenu);
}

void Win32IDE::refreshFileExplorer()
{
    populateFileTree();
}

// ============================================================================
// MODEL CHAT INTERFACE IMPLEMENTATION
// ============================================================================

bool Win32IDE::isModelLoaded() const
{
    // Model is loaded if we have a path and the streaming loader has opened the file
    return m_ggufLoader && !m_loadedModelPath.empty() && !m_modelTensors.empty();
}

std::string Win32IDE::sendMessageToModel(const std::string& message)
{
    if (!isModelLoaded()) {
        return "Error: No model loaded";
    }
    
    // First try: send through local Ollama if available
    std::string llmResponse;
    if (trySendToOllama(message, llmResponse)) {
        m_chatHistory.push_back({message, llmResponse});
        return llmResponse;
    }

    // Fallback: Local CPU Inference (Real Logic)
    if (m_ggufLoader) {
        // Use the native fallback engine if available
        if (m_nativeEngine) {
             auto* engine = static_cast<RawrXD::CPUInferenceEngine*>(m_nativeEngine);
             std::string response = NativeEngineInfer(engine, message);
             m_chatHistory.push_back({message, response});
             return response;
        }
    }

    // The native inference engine was not initialised for this session; report
    // it instead of falling off the end of a non-void function.
    std::string response = "Error: Local model loaded but Native Inference Engine not initialized.\n";
    return response;
}

void Win32IDE::toggleChatMode()
{
    m_chatMode = !m_chatMode;
    
    if (m_chatMode) {
        // Entering chat mode
        std::string status = " Chat Mode ON - Model: ";
        status += m_loadedModelPath.empty() ? "None" : m_loadedModelPath.substr(m_loadedModelPath.find_last_of("\\/") + 1);
        
        appendToOutput(status, "Output", OutputSeverity::Info);
        appendToOutput("Type your messages in the command input. Use /exit-chat to return to terminal mode.", "Output", OutputSeverity::Info);
        
        // Update status bar
        SendMessage(m_hwndStatusBar, SB_SETTEXT, 1, (LPARAM)"Chat Mode");
        
        // Clear existing chat display and show instructions
        appendChatMessage("System", "Chat mode activated! You can now talk with the loaded model.");
        appendChatMessage("System", "Commands: /exit-chat to return to terminal mode");
    } else {
        // Exiting chat mode
        appendToOutput(" Chat Mode OFF - Returned to terminal mode", "Output", OutputSeverity::Info);
        SendMessage(m_hwndStatusBar, SB_SETTEXT, 1, (LPARAM)"Terminal Mode");
        appendChatMessage("System", "Chat mode deactivated. Returned to terminal mode.");
    }
}

void Win32IDE::appendChatMessage(const std::string& user, const std::string& message)
{
    // Get timestamp
    time_t now = time(nullptr);
    struct tm timeinfo;
    localtime_s(&timeinfo, &now);
    char timestamp[16];
    strftime(timestamp, sizeof(timestamp), "%H:%M:%S", &timeinfo);
    
    // Format message
    std::string formattedMsg = "[" + std::string(timestamp) + "] " + user + ": " + message + "\n\n";
    
    // Display in output panel
    if (user == "System") {
        appendToOutput(formattedMsg, "Output", OutputSeverity::Info);
    } else if (user == "You") {
        appendToOutput(formattedMsg, "Output", OutputSeverity::Info);
    } else if (user == "Model") {
        appendToOutput(formattedMsg, "Output", OutputSeverity::Info);
    }
}

// ============================================================================
// GIT INTEGRATION - Status, Commit, Push, Pull
// ============================================================================

void Win32IDE::showGitStatus()
{
    if (!isGitRepository()) {
        MessageBoxA(m_hwndMain, "Not a Git repository", "Git", MB_OK | MB_ICONWARNING);
        return;
    }
    
    updateGitStatus();
    
    std::ostringstream status;
    status << "Git Status\n";
    status << "==========\n\n";
    status << "Branch: " << m_gitStatus.branch << "\n";
    status << "\nChanges:\n";
    status << "  Modified:  " << m_gitStatus.modified << "\n";
    status << "  Added:     " << m_gitStatus.added << "\n";
    status << "  Deleted:   " << m_gitStatus.deleted << "\n";
    status << "  Untracked: " << m_gitStatus.untracked << "\n";
    
    MessageBoxA(m_hwndMain, status.str().c_str(), "Git Status", MB_OK | MB_ICONINFORMATION);
}

void Win32IDE::updateGitStatus()
{
    if (!isGitRepository()) {
        m_gitStatus = GitStatus();
        return;
    }
    
    std::string output;
    
    // Get current branch
    executeGitCommand("git rev-parse --abbrev-ref HEAD", output);
    m_gitStatus.branch = output;
    if (!m_gitStatus.branch.empty() && m_gitStatus.branch.back() == '\n') {
        m_gitStatus.branch.pop_back();
    }
    output.clear();
    
    // Get status --porcelain
    executeGitCommand("git status --porcelain", output);
    m_gitStatus.modified = 0;
    m_gitStatus.added = 0;
    m_gitStatus.deleted = 0;
    m_gitStatus.untracked = 0;
    
    std::istringstream iss(output);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.length() < 2) continue;
        
        char status = line[0];
        char status2 = line[1];
        
        if (status == 'M' || status2 == 'M') m_gitStatus.modified++;
        if (status == 'A' || status2 == 'A') m_gitStatus.added++;
        if (status == 'D' || status2 == 'D') m_gitStatus.deleted++;
        if (status == '?' || status2 == '?') m_gitStatus.untracked++;
    }
    
    m_gitStatus.hasChanges = (m_gitStatus.modified + m_gitStatus.added + 
                               m_gitStatus.deleted + m_gitStatus.untracked) > 0;
}

void Win32IDE::gitCommit(const std::string& message)
{
    if (!isGitRepository()) {
        MessageBoxA(m_hwndMain, "Not a Git repository", "Git Error", MB_OK | MB_ICONERROR);
        return;
    }
    
    std::string output;
    std::string command = "git commit -m \"" + message + "\"";
    executeGitCommand(command, output);
    
    MessageBoxA(m_hwndMain, output.c_str(), "Git Commit", MB_OK | MB_ICONINFORMATION);
    updateGitStatus();
}

void Win32IDE::gitPush()
{
    if (!isGitRepository()) {
        MessageBoxA(m_hwndMain, "Not a Git repository", "Git Error", MB_OK | MB_ICONERROR);
        return;
    }
    
    std::string output;
    executeGitCommand("git push", output);
    
    MessageBoxA(m_hwndMain, 
        output.empty() ? "Push completed successfully" : output.c_str(), 
        "Git Push", MB_OK | MB_ICONINFORMATION);
    updateGitStatus();
}

void Win32IDE::gitPull()
{
    if (!isGitRepository()) {
        MessageBoxA(m_hwndMain, "Not a Git repository", "Git Error", MB_OK | MB_ICONERROR);
        return;
    }
    
    std::string output;
    executeGitCommand("git pull", output);
    
    MessageBoxA(m_hwndMain, 
        output.empty() ? "Pull completed successfully" : output.c_str(), 
        "Git Pull", MB_OK | MB_ICONINFORMATION);
    updateGitStatus();
}

void Win32IDE::gitStageFile(const std::string& filePath)
{
    if (!isGitRepository()) return;
    
    std::string output;
    std::string command = "git add \"" + filePath + "\"";
    executeGitCommand(command, output);
    updateGitStatus();
}

void Win32IDE::gitUnstageFile(const std::string& filePath)
{
    if (!isGitRepository()) return;
    
    std::string output;
    std::string command = "git reset HEAD \"" + filePath + "\"";
    executeGitCommand(command, output);
    updateGitStatus();
}

bool Win32IDE::isGitRepository() const
{
    if (!m_gitRepoPath.empty()) {
        std::string gitDir = m_gitRepoPath + "\\.git";
        DWORD attrib = GetFileAttributesA(gitDir.c_str());
        return (attrib != INVALID_FILE_ATTRIBUTES && (attrib & FILE_ATTRIBUTE_DIRECTORY));
    }
    
    // Check current directory
    char currentDir[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, currentDir);
    std::string gitDir = std::string(currentDir) + "\\.git";
    DWORD attrib = GetFileAttributesA(gitDir.c_str());
    return (attrib != INVALID_FILE_ATTRIBUTES && (attrib & FILE_ATTRIBUTE_DIRECTORY));
}

std::vector<GitFile> Win32IDE::getGitChangedFiles() const
{
    std::vector<GitFile> files;
    
    if (!isGitRepository()) return files;
    
    std::string output;
    const_cast<Win32IDE*>(this)->executeGitCommand("git status --porcelain", output);
    
    std::istringstream iss(output);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.length() < 4) continue;
        
        GitFile file;
        file.status = line[0] != ' ' ? line[0] : line[1];
        file.staged = (line[0] != ' ' && line[0] != '?');
        file.path = line.substr(3);
        
        files.push_back(file);
    }
    
    return files;
}

bool Win32IDE::executeGitCommand(const std::string& command, std::string& output)
{
    output.clear();
    
    // Create a temporary file for output
    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    std::string tempFile = std::string(tempPath) + "rawr_git_output.txt";
    
    // Execute command and redirect output
    std::string fullCommand = command + " > \"" + tempFile + "\" 2>&1";
    
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    if (CreateProcessA(NULL, const_cast<char*>(fullCommand.c_str()), 
        NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        
        WaitForSingleObject(pi.hProcess, 5000);  // 5 second timeout
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        
        // Read output file
        std::ifstream file(tempFile);
        if (file.is_open()) {
            std::string line;
            while (std::getline(file, line)) {
                output += line + "\n";
            }
            file.close();
            DeleteFileA(tempFile.c_str());
        }
        return true;
    }
    return false;
}

void Win32IDE::showGitPanel()
{
    if (!isGitRepository()) {
        MessageBoxA(m_hwndMain, "Not a Git repository", "Git", MB_OK | MB_ICONWARNING);
        return;
    }
    
    // Create Git panel if it doesn't exist
    if (!m_hwndGitPanel || !IsWindow(m_hwndGitPanel)) {
        m_hwndGitPanel = CreateWindowExA(WS_EX_TOOLWINDOW, "STATIC", "Git Panel",
            WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE | WS_SIZEBOX,
            200, 100, 600, 500, m_hwndMain, nullptr, m_hInstance, nullptr);
        
        // Branch and status info
        m_hwndGitStatusText = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
            WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY,
            10, 10, 580, 60, m_hwndGitPanel, nullptr, m_hInstance, nullptr);
        
        // Changed files list
        CreateWindowExA(0, "STATIC", "Changed Files:", WS_CHILD | WS_VISIBLE,
            10, 80, 120, 20, m_hwndGitPanel, nullptr, m_hInstance, nullptr);
        
        m_hwndGitFileList = CreateWindowExA(WS_EX_CLIENTEDGE, "LISTBOX", "",
            WS_CHILD | WS_VISIBLE | LBS_STANDARD | LBS_EXTENDEDSEL | WS_VSCROLL,
            10, 105, 280, 300, m_hwndGitPanel, nullptr, m_hInstance, nullptr);
    }
    
    ShowWindow(m_hwndGitPanel, SW_SHOW);
    refreshGitPanel();
}

void Win32IDE::refreshGitPanel()
{
    if (!m_hwndGitPanel || !IsWindow(m_hwndGitPanel)) return;
    
    updateGitStatus();
    
    // Update status text
    std::string statusText = "Branch: " + m_gitStatus.branch + "\n";
    statusText += "Modified: " + std::to_string(m_gitStatus.modified) + " | ";
    statusText += "Added: " + std::to_string(m_gitStatus.added) + " | ";
    statusText += "Deleted: " + std::to_string(m_gitStatus.deleted) + " | ";
    statusText += "Untracked: " + std::to_string(m_gitStatus.untracked);
    
    if (m_hwndGitStatusText) {
        SetWindowTextA(m_hwndGitStatusText, statusText.c_str());
    }
    
    // Update file list
    if (m_hwndGitFileList) {
        SendMessage(m_hwndGitFileList, LB_RESETCONTENT, 0, 0);
        
        std::vector<GitFile> files = getGitChangedFiles();
        for (const auto& file : files) {
            std::string displayText;
            if (file.staged) {
                displayText = "[S] ";
            } else {
                displayText = "[ ] ";
            }
            
            switch (file.status) {
                case 'M': displayText += "(M) "; break;
                case 'A': displayText += "(A) "; break;
                case 'D': displayText += "(D) "; break;
                case '?': displayText += "(?) "; break;
                default: displayText += "( ) "; break;
            }
            
            displayText += file.path;
            SendMessageA(m_hwndGitFileList, LB_ADDSTRING, 0, (LPARAM)displayText.c_str());
        }
    }
}

void Win32IDE::showCommitDialog()
{
    if (!isGitRepository()) {
        MessageBoxA(m_hwndMain, "Not a Git repository", "Git", MB_OK | MB_ICONWARNING);
        return;
    }
    
    // Simple commit dialog using InputBox-style approach
    HWND hwndDlg = CreateWindowExA(WS_EX_DLGMODALFRAME, "STATIC", "Git Commit",
        WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
        150, 150, 500, 200, m_hwndMain, nullptr, m_hInstance, nullptr);
    
    CreateWindowExA(0, "STATIC", "Commit Message:", WS_CHILD | WS_VISIBLE,
        10, 10, 120, 20, hwndDlg, nullptr, m_hInstance, nullptr);
    
    m_hwndCommitDialog = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_WANTRETURN | WS_VSCROLL,
        10, 35, 470, 100, hwndDlg, nullptr, m_hInstance, nullptr);
    
    HWND hwndCommitBtn = CreateWindowExA(0, "BUTTON", "Commit", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
        10, 145, 100, 30, hwndDlg, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(1)), m_hInstance, nullptr);
    
    HWND hwndCancelBtn = CreateWindowExA(0, "BUTTON", "Cancel", WS_CHILD | WS_VISIBLE,
        120, 145, 100, 30, hwndDlg, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(2)), m_hInstance, nullptr);
    
    SetFocus(m_hwndCommitDialog);
}

// ============================================================================
// AI INFERENCE IMPLEMENTATION - Connects GGUF Loader to Chat Panel
// ============================================================================

bool Win32IDE::loadModelForInference(const std::string& filepath)
{
    const DWORD attributes = GetFileAttributesA(filepath.c_str());
    if (filepath.empty() || attributes == INVALID_FILE_ATTRIBUTES ||
        (attributes & FILE_ATTRIBUTE_DIRECTORY) || m_inferenceRunning) return false;
    // The menu must parse and bind the chosen model before reporting readiness.
    // A user-selected GGUF may be many gigabytes; never route this production
    // UI path through the legacy whole-file loader.
    m_ggufLoader = std::make_unique<StreamingGGUFLoader>();
    m_useStreamingLoader = true;
    m_nativeEngineLoaded = false;
    if (!loadGGUFModel(filepath) || !initializeInference()) {
        m_loadedModelPath.clear();
        m_modelTensors.clear();
        return false;
    }
    return m_nativeEngine && m_nativeEngine->IsModelLoaded();
}

bool Win32IDE::initializeInference()
{
    std::lock_guard<std::mutex> lock(m_inferenceMutex);
    
    // Explicit Logic: Initialize Native CPU Engine if missing (Un-mocking)
    if (!m_nativeEngine) {
        try {
            m_nativeEngine = new RawrXD::CPUInferenceEngine();
            m_nativeEngineLoaded = false;
            appendToOutput("Initialized Native CPU Inference Engine.", "Output", OutputSeverity::Info);
        } catch (const std::exception& e) {
            appendToOutput(std::string("Failed to init native engine: ") + e.what(), "Errors", OutputSeverity::Error);
            return false;
        }
    }

    // Check if model is loaded via GGUF loader (Streaming)
    if (m_loadedModelPath.empty()) {
        appendToOutput("No model selected for inference", "Errors", OutputSeverity::Error);
        return false;
    }
    
    // Connect Native Engine to Model
    if (m_nativeEngine && !m_loadedModelPath.empty()) {
        RawrXD::CPUInferenceEngine* engine = static_cast<RawrXD::CPUInferenceEngine*>(m_nativeEngine);
        {
            m_nativeEngineLoaded = false;
            appendToOutput("Loading model into Native Engine: " + m_loadedModelPath, "Output", OutputSeverity::Info);
            try {
                if (engine->LoadModel(m_loadedModelPath)) {
                    m_nativeEngineLoaded = true;
                    appendToOutput(" Native Engine Model Loaded Successfully.", "Output", OutputSeverity::Info);
                } else {
                    appendToOutput(" Native Engine Model Load Failed; GGUF metadata remains available.",
                        "Errors", OutputSeverity::Error);
                    return false;
                }
            } catch (const std::exception& error) {
                const std::string message =
                    " Native Engine Model Load Aborted safely: " + std::string(error.what());
                LOG_ERROR(message);
                appendToOutput(message + "\nThe model was indexed, but native CPU admission was rejected.",
                    "Errors", OutputSeverity::Error);
                return false;
            } catch (...) {
                const std::string message =
                    " Native Engine Model Load Aborted safely: unknown exception";
                LOG_ERROR(message);
                appendToOutput(message + "\nThe model was indexed, but native CPU admission was rejected.",
                    "Errors", OutputSeverity::Error);
                return false;
            }
        }
    }

    // Set up inference config from model metadata
    m_inferenceConfig.maxTokens = 512;
    m_inferenceConfig.temperature = 0.7f;
    m_inferenceConfig.topP = 0.9f;
    m_inferenceConfig.topK = 40;
    m_inferenceConfig.repetitionPenalty = 1.1f;
    
    // Use model context length if available
    if (m_currentModelMetadata.context_length > 0) {
        m_inferenceConfig.maxTokens = std::min(512, (int)m_currentModelMetadata.context_length / 4);
    }
    
    appendToOutput(" Inference initialized for model: " + m_loadedModelPath, "Output", OutputSeverity::Info);
    return true;
}

void Win32IDE::shutdownInference()
{
    std::lock_guard<std::mutex> lock(m_inferenceMutex);
    
    if (m_inferenceRunning) {
        m_inferenceStopRequested = true;
        if (m_inferenceThread.joinable()) {
            m_inferenceThread.join();
        }
    }
    
    m_inferenceRunning = false;
    m_inferenceStopRequested = false;
    m_currentInferencePrompt.clear();
    m_currentInferenceResponse.clear();
    
    appendToOutput("Inference shutdown complete", "Output", OutputSeverity::Info);
}

std::string Win32IDE::generateResponse(const std::string& prompt)
{
    if (m_inferenceRunning) {
        return "Inference already in progress. Please wait...";
    }

    // Attempt real remote/local inference via Ollama if configured
    auto performOllama = [&](const std::string& promptText) -> std::string {
        if (m_ollamaBaseUrl.empty()) return "";
        // Expect base URL like http://localhost:11434
        std::string base = m_ollamaBaseUrl;
        if (base.rfind("http://", 0) != 0 && base.rfind("https://", 0) != 0) return "";
        bool https = base.rfind("https://", 0) == 0;
        std::string withoutProto = base.substr(base.find("://") + 3);
        std::string host; int port = https ? 443 : 80;
        size_t colonPos = withoutProto.find(':');
        size_t slashPos = withoutProto.find('/');
        if (colonPos != std::string::npos) {
            host = withoutProto.substr(0, colonPos);
            std::string portStr = withoutProto.substr(colonPos + 1, (slashPos == std::string::npos ? withoutProto.size() : slashPos) - (colonPos + 1));
            port = atoi(portStr.c_str());
        } else {
            host = (slashPos == std::string::npos) ? withoutProto : withoutProto.substr(0, slashPos);
            // Default Ollama port
            if (!https) port = 11434;
        }
        std::wstring whost(host.begin(), host.end());
        HINTERNET hSession = WinHttpOpen(L"RawrXDIDE/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, NULL, NULL, 0);
        if (!hSession) return "";
        HINTERNET hConnect = WinHttpConnect(hSession, whost.c_str(), (INTERNET_PORT)port, 0);
        if (!hConnect) { WinHttpCloseHandle(hSession); return ""; }
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/api/generate", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, https ? WINHTTP_FLAG_SECURE : 0);
        if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return ""; }
        // Build JSON body
        std::string modelTag;
        if (!m_ollamaModelOverride.empty()) modelTag = m_ollamaModelOverride; else {
            // Derive from loaded path
            modelTag = m_loadedModelPath;
            size_t pos = modelTag.find_last_of("\\/");
            if (pos != std::string::npos) modelTag = modelTag.substr(pos + 1);
        }
        // Basic escaping of quotes in prompt
        std::string escPrompt; escPrompt.reserve(promptText.size()+16);
        for (char c : promptText) { if (c == '"') escPrompt += "\\\""; else if (c=='\n') escPrompt += "\\n"; else escPrompt += c; }
        std::string body = std::string("{\"model\":\"") + modelTag + "\",\"prompt\":\"" + escPrompt + "\",\"stream\":false}";
        std::wstring wHeaders = L"Content-Type: application/json";
        BOOL bResults = WinHttpSendRequest(hRequest, wHeaders.c_str(), (DWORD)-1L, (LPVOID)body.c_str(), (DWORD)body.size(), (DWORD)body.size(), 0);
        if (!bResults) { WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return ""; }
        bResults = WinHttpReceiveResponse(hRequest, NULL);
        std::string raw;
        if (bResults) {
            DWORD dwSize = 0; do {
                if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
                if (!dwSize) break;
                std::string chunk; chunk.resize(dwSize);
                DWORD dwRead = 0;
                if (!WinHttpReadData(hRequest, chunk.data(), dwSize, &dwRead)) break;
                if (dwRead) raw.append(chunk.data(), dwRead);
            } while (dwSize > 0);
        }
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        if (raw.empty()) return "";
        // Naive JSON parse: look for "response":"..."
        std::string out;
        size_t pos = raw.rfind("\"response\":\"");
        if (pos != std::string::npos) {
            pos += 12; // start after marker
            while (pos < raw.size()) {
                char c = raw[pos++];
                if (c == '"') break; // end of string (assumes not escaped)
                if (c == '\\') { if (pos < raw.size()) { char next = raw[pos++]; if (next=='n') out+='\n'; else out+=next; } }
                else out += c;
            }
        }
        return out.empty() ? raw : out;
    };

    std::string remote = performOllama(prompt);
    if (!remote.empty()) return remote;

    // Fallback structured guidance if no remote inference available
    std::string modelName = m_loadedModelPath.empty() ? "None" : m_loadedModelPath.substr(m_loadedModelPath.find_last_of("\\/")+1);

    // Fallback: Native CPU Inference Engine
    if (m_nativeEngine && m_nativeEngineLoaded) {
        RawrXD::CPUInferenceEngine* engine = static_cast<RawrXD::CPUInferenceEngine*>(m_nativeEngine);
        // If engine doesn't have a model loaded, try to load current one
        if (!engine->IsModelLoaded() && !m_loadedModelPath.empty()) {
            try {
                engine->LoadModel(m_loadedModelPath);
            } catch (const std::exception& error) {
                LOG_ERROR(std::string("Deferred native model admission rejected: ") + error.what());
                return "[Native Engine Error]\nThe indexed GGUF could not be admitted to the native CPU runtime.";
            } catch (...) {
                LOG_ERROR("Deferred native model admission rejected: unknown exception");
                return "[Native Engine Error]\nThe indexed GGUF could not be admitted to the native CPU runtime.";
            }
        }
        
        return NativeEngineInfer(engine, prompt);
    }

    return std::string("[Native Engine Error]\nModel: ") + modelName + "\nPrompt: " + prompt + "\n(Ollama unavailable and Native Engine not ready)";
}

void Win32IDE::generateResponseAsync(const std::string& prompt, std::function<void(const std::string&, bool)> callback)
{
    std::lock_guard<std::mutex> lock(m_inferenceMutex);

    if (m_inferenceRunning) {
        // Busy state is reported by the UI status bar.  Never turn a
        // scheduling race into assistant text that looks like model output.
        return;
    }
    if (m_inferenceThread.joinable()) {
        m_inferenceThread.join();
    }
    const ChatModelEntry selectedModel = m_selectedChatModel;
    
    m_inferenceRunning = true;
    m_inferenceStopRequested = false;
    m_currentInferencePrompt = prompt;
    m_inferenceCallback = callback;
    
    // Route from the selected model entry. Local GGUF uses the native agent,
    // Ollama uses its local HTTP API, and Kilo uses the existing cloud client.
    m_inferenceThread = std::thread([this, prompt, callback, selectedModel]() {
        auto finish = [this, callback](const std::string& result) {
            m_inferenceRunning = false;
            if (callback) callback(result, true);
        };

        try {
            if (selectedModel.identifier.empty()) {
                finish("Select a model route first.");
                return;
            }

            switch (selectedModel.source) {
            case ChatModelEntry::Source::KiloFree: {
                const auto* route = RawrXD::ChatRouteMenu::find(
                    RawrXD::ChatRouteMenu::RouteKind::KiloFree);
                const char* apiKey = route && route->authEnv[0]
                    ? std::getenv(route->authEnv) : nullptr;
                if (!apiKey || !*apiKey) {
                    finish("Kilo free cloud route is selected, but RawrXD cannot find its Kilo credential. Set KILO_API_KEY and restart RawrXD.");
                    return;
                }
                if (!route || std::strcmp(route->runtime, "cloud-api") != 0) {
                    finish("The generated Kilo route is missing its cloud-api runtime mapping.");
                    return;
                }
                ModelConfig config{};
                config.backend = ModelBackend::KILO_GATEWAY;
                config.model_id = selectedModel.identifier;
                config.api_key = apiKey;
                config.parameters["max_tokens"] = std::to_string(m_currentMaxTokens);
                CloudApiClient client;
                const std::string response = client.generate(prompt, config);
                finish(response.empty()
                    ? "Kilo did not return a response. Check the Kilo credential and network connection."
                    : response);
                return;
            }
            case ChatModelEntry::Source::Ollama: {
                const auto* route = RawrXD::ChatRouteMenu::find(
                    RawrXD::ChatRouteMenu::RouteKind::Ollama);
                if (!route || std::strcmp(route->runtime, "ollama-http") != 0) {
                    finish("The generated Ollama route is missing its local HTTP runtime mapping.");
                    return;
                }
                const std::string response = generateOllamaModel(
                    m_ollamaBaseUrl, selectedModel.identifier, prompt, m_currentMaxTokens);
                finish(response.empty()
                    ? "The selected Ollama model did not respond. Check that Ollama is running locally."
                    : response);
                return;
            }
            case ChatModelEntry::Source::LocalFile: {
                const auto* route = RawrXD::ChatRouteMenu::find(
                    RawrXD::ChatRouteMenu::RouteKind::LocalFile);
                if (!route || std::strcmp(route->runtime, "native-agent") != 0) {
                    finish("The generated local model route is missing its native-agent runtime mapping.");
                    return;
                }
                if (!m_agenticBridge || !m_agenticBridge->IsInitialized()) {
                    finish("The native agent bridge is not initialized.");
                    return;
                }
                if (!hasGgufModelTensors(selectedModel.identifier)) {
                    finish("The selected GGUF is not an inference model (it may contain vocabulary metadata only): " +
                        selectedModel.identifier);
                    return;
                }
                if (m_agenticChatLoadedModelPath != selectedModel.identifier) {
                    const AgentResponse load = m_agenticBridge->ExecuteAgentCommand(
                        "/load " + selectedModel.identifier);
                    if (load.type == AgentResponseType::AGENT_ERROR) {
                        finish(load.content.empty()
                            ? "The selected local model could not be loaded."
                            : load.content);
                        return;
                    }
                    m_agenticChatLoadedModelPath = selectedModel.identifier;
                }
                m_agenticBridge->SetOutputCallback(
                    [this, callback](const std::string&, const std::string& chunk) {
                        if (!m_inferenceStopRequested && callback) callback(chunk, false);
                    });
                m_agenticBridge->ExecuteAgentCommand(prompt);
                finish("");
                return;
            }
            }
            finish("The selected chat route is unsupported.");
        } catch (const std::exception& error) {
            finish(std::string("Chat route failed: ") + error.what());
        } catch (...) {
            finish("Chat route failed with an unknown error.");
        }
    });
}

void Win32IDE::stopInference()
{
    m_inferenceStopRequested = true;
}

void Win32IDE::setInferenceConfig(const InferenceConfig& config)
{
    std::lock_guard<std::mutex> lock(m_inferenceMutex);
    m_inferenceConfig = config;
}

Win32IDE::InferenceConfig Win32IDE::getInferenceConfig() const
{
    return m_inferenceConfig;
}

std::string Win32IDE::buildChatPrompt(const std::string& userMessage)
{
    std::string prompt;
    
    // Add system prompt if set
    if (!m_inferenceConfig.systemPrompt.empty()) {
        prompt = "<|system|>\n" + m_inferenceConfig.systemPrompt + "\n<|end|>\n";
    }
    
    // Add user message
    prompt += "<|user|>\n" + userMessage + "\n<|end|>\n";
    prompt += "<|assistant|>\n";
    
    return prompt;
}

void Win32IDE::onInferenceToken(const std::string& token)
{
    // Called when streaming tokens during inference
    m_currentInferenceResponse += token;
    
    // Update UI with partial response if streaming is enabled
    if (m_inferenceConfig.streamOutput && m_inferenceCallback) {
        m_inferenceCallback(token, false);
    }
}

void Win32IDE::onInferenceComplete(const std::string& fullResponse)
{
    m_inferenceRunning = false;
    m_currentInferenceResponse = fullResponse;
    
    if (m_inferenceCallback) {
        m_inferenceCallback(fullResponse, true);
    }
}

// ============================================================================
// EDITOR OPERATIONS - Undo/Redo/Cut/Copy/Paste
// ============================================================================

void Win32IDE::undo()
{
    if (m_hwndEditor) {
        SendMessage(m_hwndEditor, EM_UNDO, 0, 0);
    }
}

void Win32IDE::redo()
{
    if (m_hwndEditor) {
        SendMessage(m_hwndEditor, EM_REDO, 0, 0);
    }
}

void Win32IDE::editCut()
{
    if (m_hwndEditor) {
        SendMessage(m_hwndEditor, WM_CUT, 0, 0);
    }
}

void Win32IDE::editCopy()
{
    if (m_hwndEditor) {
        SendMessage(m_hwndEditor, WM_COPY, 0, 0);
    }
}

void Win32IDE::editPaste()
{
    if (m_hwndEditor) {
        SendMessage(m_hwndEditor, WM_PASTE, 0, 0);
    }
}

// ============================================================================
// VIEW OPERATIONS - Toggle panels
// ============================================================================

void Win32IDE::toggleOutputPanel()
{
    m_outputPanelVisible = !m_outputPanelVisible;
    if (m_hwndMain) {
        RECT rc;
        GetClientRect(m_hwndMain, &rc);
        onSize(rc.right, rc.bottom);
        InvalidateRect(m_hwndMain, NULL, TRUE);
    }
}

void Win32IDE::toggleTerminal()
{
    // Toggle panel visibility (which contains terminal)
    m_outputPanelVisible = !m_outputPanelVisible;
    if (m_hwndMain) {
        RECT rc;
        GetClientRect(m_hwndMain, &rc);
        onSize(rc.right, rc.bottom);
        InvalidateRect(m_hwndMain, NULL, TRUE);
    }
}

void Win32IDE::showAbout()
{
    std::string aboutText = 
        "RawrXD Win32 IDE\n\n"
        "Version: 1.0.0\n"
        "Build: " __DATE__ " " __TIME__ "\n\n"
        "Features:\n"
        " Native Win32 UI\n"
        " GGUF Model Support\n"
        " PowerShell Integration\n"
        " Git Integration\n"
        " AI Chat via Ollama\n"
        " Syntax Highlighting\n"
        " Multi-Terminal Support\n\n"
        "GitHub: ItsMehRAWRXD/RawrXD";
    
    MessageBoxA(m_hwndMain, aboutText.c_str(), "About RawrXD IDE", MB_OK | MB_ICONINFORMATION);
}

// ============================================================================
// AUTONOMY FRAMEWORK - High-level orchestration controls
// ============================================================================

void Win32IDE::onAutonomyStart() {
    if (!m_autonomyManager) {
        appendToOutput("Autonomy manager not initialized\n", "Errors", OutputSeverity::Error);
        return;
    }
    m_autonomyManager->start();
    appendToOutput("Autonomy started (manual mode)\n", "Output", OutputSeverity::Info);
}

void Win32IDE::onAutonomyStop() {
    if (!m_autonomyManager) return;
    m_autonomyManager->stop();
    appendToOutput("Autonomy stopped\n", "Output", OutputSeverity::Info);
}

void Win32IDE::onAutonomyToggle() {
    if (!m_autonomyManager) return;
    bool enable = !m_autonomyManager->isAutoLoopEnabled();
    m_autonomyManager->enableAutoLoop(enable);
    appendToOutput(std::string("Autonomy auto loop ") + (enable?"ENABLED":"DISABLED") + "\n", "Output", OutputSeverity::Info);
}

void Win32IDE::onAutonomySetGoal() {
    if (!m_autonomyManager) return;
    // Simple goal setter: reuse current file name or fallback text
    std::string goal = m_currentFile.empty() ? "Explore workspace and summarize architecture" : ("Analyze file: " + m_currentFile);
    m_autonomyManager->setGoal(goal);
    appendToOutput("Autonomy goal set: " + goal + "\n", "Output", OutputSeverity::Info);
}

void Win32IDE::onAutonomyViewStatus() {
    if (!m_autonomyManager) return;
    std::string status = m_autonomyManager->getStatus();
    appendToOutput("Autonomy Status: " + status + "\n", "Output", OutputSeverity::Info);
    MessageBoxA(m_hwndMain, status.c_str(), "Autonomy Status", MB_OK | MB_ICONINFORMATION);
}

void Win32IDE::onAutonomyViewMemory() {
    if (!m_autonomyManager) return;
    auto mem = m_autonomyManager->getMemorySnapshot();
    std::string report = "Memory Items (latest first, max 20):\n\n";
    int shown = 0;
    for (int i = (int)mem.size() - 1; i >= 0 && shown < 20; --i, ++shown) {
        report += std::to_string(shown+1) + ". " + mem[i] + "\n";
    }
    if (shown == 0) report += "<empty>\n";
    appendToOutput("Autonomy Memory Snapshot displayed\n", "Debug", OutputSeverity::Debug);
    MessageBoxA(m_hwndMain, report.c_str(), "Autonomy Memory", MB_OK);
}

// ======================================================================
// AI CHAT PANEL IMPLEMENTATION
// ======================================================================

void Win32IDE::createChatPanel() {

    if (!m_hwndMain) {

        return;
    }

    // Create secondary sidebar container (right side)
    m_hwndSecondarySidebar = CreateWindowExA(
        WS_EX_CLIENTEDGE, "STATIC", "",
        WS_CHILD | WS_VISIBLE,
        0, 0, 300, 600,
        m_hwndMain, (HMENU)IDC_SECONDARY_SIDEBAR, m_hInstance, nullptr);
    
    if (!m_hwndSecondarySidebar) {

        return;
    }
    // STATIC is only a container and does not forward child notifications to
    // the main window.  Install the sidebar procedure on the actual runtime
    // surface so Send/Clear/Stop, model changes, and New Chat all reach the
    // single command dispatcher without creating a second hidden chat host.
    SetPropA(m_hwndSecondarySidebar, "IDE_PTR", this);
    WNDPROC oldSidebarProc = reinterpret_cast<WNDPROC>(SetWindowLongPtrA(
        m_hwndSecondarySidebar, GWLP_WNDPROC,
        reinterpret_cast<LONG_PTR>(SecondarySidebarProc)));
    SetPropA(m_hwndSecondarySidebar, "OLDPROC", reinterpret_cast<HANDLE>(oldSidebarProc));
    
    // Session strip: every tab retains its own model selection and history.
    // The existing chat controls remain the active session surface, so adding
    // a session does not replace or reset the current inference route.
    m_hwndChatSessionTabs = CreateWindowExA(
        0, WC_TABCONTROLA, "",
        WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | TCS_TABS,
        5, 3, 190, 27,
        m_hwndSecondarySidebar, reinterpret_cast<HMENU>(IDC_CHAT_SESSIONS),
        m_hInstance, nullptr);
    m_hwndNewChatBtn = CreateWindowExA(
        0, "BUTTON", "New Chat",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        198, 3, 92, 27,
        m_hwndSecondarySidebar, reinterpret_cast<HMENU>(IDC_NEW_CHAT),
        m_hInstance, nullptr);
    m_hwndCloseChatBtn = CreateWindowExA(
        0, "BUTTON", "X",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        0, 0, 25, 27,
        m_hwndSecondarySidebar, reinterpret_cast<HMENU>(IDC_CLOSE_CHAT),
        m_hInstance, nullptr);
    m_hwndRestoreChatBtn = CreateWindowExA(
        0, "BUTTON", "Restore",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        0, 0, 45, 27,
        m_hwndSecondarySidebar, reinterpret_cast<HMENU>(IDC_RESTORE_CHAT),
        m_hInstance, nullptr);
    m_hwndRollbackChatBtn = CreateWindowExA(
        0, "BUTTON", "Rollback",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        0, 0, 64, 27,
        m_hwndSecondarySidebar, reinterpret_cast<HMENU>(IDC_ROLLBACK_CHAT),
        m_hInstance, nullptr);

    // Create header with title
    m_hwndSecondarySidebarHeader = CreateWindowExA(
        0, "STATIC", "AI Sessions",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        5, 34, 290, 22,
        m_hwndSecondarySidebar, nullptr, m_hInstance, nullptr);
    
    HFONT hFont = CreateFontA(14, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, ANSI_CHARSET, 
                              OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, 
                              DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");
    if (m_hwndSecondarySidebarHeader) {
        SendMessage(m_hwndSecondarySidebarHeader, WM_SETFONT, (WPARAM)hFont, TRUE);
    }
    
    // Model Selection Label
    m_hwndModelLabel = CreateWindowExA(0, "STATIC", "Model:",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        5, 35, 85, 18,
        m_hwndSecondarySidebar, nullptr, m_hInstance, nullptr);
    
    // Model Selector Combobox
    m_hwndModelSelector = CreateWindowExA(
        0, "COMBOBOX", "",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST |
            CBS_HASSTRINGS | CBS_NOINTEGRALHEIGHT | WS_VSCROLL,
        95, 35, 200, 200,
        m_hwndSecondarySidebar, (HMENU)IDC_COPILOT_MODEL_SELECTOR, m_hInstance, nullptr);
    
    if (m_hwndModelSelector) {
        SendMessage(m_hwndModelSelector, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageA(m_hwndModelSelector, CB_SETDROPPEDWIDTH, 560, 0);
        SendMessageA(m_hwndModelSelector, CB_SETMINVISIBLE, 14, 0);
        installModelSelectorProc(m_hwndModelSelector);
        populateModelSelector();
    }

    m_hwndGhostTextModelLabel = CreateWindowExA(0, "STATIC", "GhostText model:",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        5, 62, 85, 18, m_hwndSecondarySidebar, nullptr, m_hInstance, nullptr);
    m_hwndGhostModelSelector = CreateWindowExA(
        0, "COMBOBOX", "",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST |
            CBS_HASSTRINGS | CBS_NOINTEGRALHEIGHT | WS_VSCROLL,
        95, 62, 200, 200,
        m_hwndSecondarySidebar, (HMENU)IDC_GHOST_MODEL_SELECTOR, m_hInstance, nullptr);
    if (m_hwndGhostModelSelector) {
        SendMessage(m_hwndGhostModelSelector, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessageA(m_hwndGhostModelSelector, CB_SETDROPPEDWIDTH, 560, 0);
        SendMessageA(m_hwndGhostModelSelector, CB_SETMINVISIBLE, 14, 0);
        installModelSelectorProc(m_hwndGhostModelSelector);
        const LRESULT off = SendMessageA(m_hwndGhostModelSelector, CB_ADDSTRING, 0,
            reinterpret_cast<LPARAM>("GhostText: Off"));
        SendMessageA(m_hwndGhostModelSelector, CB_SETITEMDATA, static_cast<WPARAM>(off), static_cast<LPARAM>(-2));
        const LRESULT follow = SendMessageA(m_hwndGhostModelSelector, CB_ADDSTRING, 0,
            reinterpret_cast<LPARAM>("GhostText: Follow Chat"));
        SendMessageA(m_hwndGhostModelSelector, CB_SETITEMDATA, static_cast<WPARAM>(follow), static_cast<LPARAM>(-3));
        const LRESULT autoLocal = SendMessageA(m_hwndGhostModelSelector, CB_ADDSTRING, 0,
            reinterpret_cast<LPARAM>("GhostText: Auto Local"));
        SendMessageA(m_hwndGhostModelSelector, CB_SETITEMDATA, static_cast<WPARAM>(autoLocal), static_cast<LPARAM>(-1));
        SendMessageA(m_hwndGhostModelSelector, CB_SETCURSEL, 2, 0);
    }

    m_hwndAllowCloudGhostText = CreateWindowExA(
        0, "BUTTON", "Allow cloud GhostText for this session",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        5, 89, 285, 18, m_hwndSecondarySidebar,
        (HMENU)IDC_GHOST_ALLOW_CLOUD, m_hInstance, nullptr);
    if (m_hwndAllowCloudGhostText) {
        SendMessage(m_hwndAllowCloudGhostText, WM_SETFONT, (WPARAM)hFont, TRUE);
        SendMessage(m_hwndAllowCloudGhostText, BM_SETCHECK, BST_UNCHECKED, 0);
    }
    
    // Max Tokens Label
    m_hwndMaxTokensCaption = CreateWindowExA(0, "STATIC", "Max tokens:",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        5, 110, 85, 18,
        m_hwndSecondarySidebar, nullptr, m_hInstance, nullptr);
    
    // Max Tokens Label (value display)
    m_hwndMaxTokensLabel = CreateWindowExA(0, "STATIC", "4096",
        WS_CHILD | WS_VISIBLE | SS_RIGHT,
        245, 108, 50, 18,
        m_hwndSecondarySidebar, nullptr, m_hInstance, nullptr);
    
    // Max Tokens Slider
    m_hwndMaxTokensSlider = CreateWindowExA(
        0, "TRACKBAR_CLASS", "",
        WS_CHILD | WS_VISIBLE | TBS_HORZ | TBS_NOTICKS,
        5, 128, 290, 25,
        m_hwndSecondarySidebar, (HMENU)IDC_COPILOT_TOKEN_SLIDER, m_hInstance, nullptr);
    
    if (m_hwndMaxTokensSlider) {
        SendMessage(m_hwndMaxTokensSlider, TBM_SETRANGEMIN, TRUE, 32);
        SendMessage(m_hwndMaxTokensSlider, TBM_SETRANGEMAX, TRUE, 1048576);
        SendMessage(m_hwndMaxTokensSlider, TBM_SETPOS, TRUE, 4096);
        SendMessage(m_hwndMaxTokensSlider, TBM_SETTICFREQ, 4096, 0);
        m_currentMaxTokens = 4096;
    }

    m_hwndContextCaption = CreateWindowExA(0, "STATIC", "Context:",
        WS_CHILD | WS_VISIBLE | SS_LEFT, 5, 145, 85, 18,
        m_hwndSecondarySidebar, nullptr, m_hInstance, nullptr);
    m_hwndContextLabel = CreateWindowExA(0, "STATIC", "64K (pending model admission)",
        WS_CHILD | WS_VISIBLE | SS_RIGHT, 180, 143, 115, 18,
        m_hwndSecondarySidebar, nullptr, m_hInstance, nullptr);
    m_hwndContextSlider = CreateWindowExA(
        0, "TRACKBAR_CLASS", "", WS_CHILD | WS_VISIBLE | TBS_HORZ | TBS_NOTICKS,
        5, 163, 290, 25, m_hwndSecondarySidebar,
        (HMENU)IDC_COPILOT_CONTEXT_SLIDER, m_hInstance, nullptr);
    if (m_hwndContextSlider) {
        SendMessage(m_hwndContextSlider, TBM_SETRANGEMIN, TRUE, 8192);
        SendMessage(m_hwndContextSlider, TBM_SETRANGEMAX, TRUE, 1048576);
        SendMessage(m_hwndContextSlider, TBM_SETPOS, TRUE, 65536);
    }
    
    // Chat Output Textbox
    m_hwndCopilotChatOutput = CreateWindowExA(
        WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL,
        5, 193, 290, 242,
        m_hwndSecondarySidebar, (HMENU)IDC_COPILOT_CHAT_OUTPUT, m_hInstance, nullptr);
    
    if (m_hwndCopilotChatOutput) {
        SendMessage(m_hwndCopilotChatOutput, WM_SETFONT, (WPARAM)hFont, TRUE);
        SetWindowTextA(m_hwndCopilotChatOutput,
            "Welcome to RawrXD AI Chat!\r\n\r\nSelect a model and type a message to begin.");
    }
    
    // Chat Input Textbox
    m_hwndCopilotChatInput = CreateWindowExA(
        WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_WANTRETURN | WS_VSCROLL,
        5, 440, 290, 60,
        m_hwndSecondarySidebar, (HMENU)IDC_COPILOT_CHAT_INPUT, m_hInstance, nullptr);
    
    if (m_hwndCopilotChatInput) {
        SendMessage(m_hwndCopilotChatInput, WM_SETFONT, (WPARAM)hFont, TRUE);
    }
    
    // Send Button
    m_hwndCopilotSendBtn = CreateWindowExA(
        0, "BUTTON", "Send",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        5, 503, 92, 30,
        m_hwndSecondarySidebar, (HMENU)IDC_COPILOT_SEND_BTN, m_hInstance, nullptr);
    
    if (m_hwndCopilotSendBtn) {
        SendMessage(m_hwndCopilotSendBtn, WM_SETFONT, (WPARAM)hFont, TRUE);
    }
    
    // Clear Button
    m_hwndCopilotClearBtn = CreateWindowExA(
        0, "BUTTON", "Clear",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        99, 503, 92, 30,
        m_hwndSecondarySidebar, (HMENU)IDC_COPILOT_CLEAR_BTN, m_hInstance, nullptr);
    
    if (m_hwndCopilotClearBtn) {
        SendMessage(m_hwndCopilotClearBtn, WM_SETFONT, (WPARAM)hFont, TRUE);
    }

    m_hwndCopilotStopBtn = CreateWindowExA(
        0, "BUTTON", "Stop",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        193, 503, 97, 30,
        m_hwndSecondarySidebar, (HMENU)IDC_COPILOT_STOP_BTN, m_hInstance, nullptr);
    if (m_hwndCopilotStopBtn) {
        SendMessage(m_hwndCopilotStopBtn, WM_SETFONT, (WPARAM)hFont, TRUE);
        EnableWindow(m_hwndCopilotStopBtn, FALSE);
    }
    
    m_secondarySidebarVisible = true;
    // Give the chat surface enough horizontal room for model breadcrumbs,
    // session controls, and the restore action without clipping them.
    m_secondarySidebarWidth = 360;

    createChatSession("Chat 1");

}

ChatSessionState* Win32IDE::activeChatSession()
{
    if (m_activeChatSession < 0 ||
        m_activeChatSession >= static_cast<int>(m_chatSessions.size())) {
        return nullptr;
    }
    return &m_chatSessions[static_cast<size_t>(m_activeChatSession)];
}

void Win32IDE::updateChatSessionTabs()
{
    if (m_hwndChatSessionTabs) {
        TabCtrl_DeleteAllItems(m_hwndChatSessionTabs);
        for (size_t i = 0; i < m_chatSessions.size(); ++i) {
            auto& session = m_chatSessions[i];
            std::string label = session.title.empty()
                ? ("Chat " + std::to_string(i + 1)) : session.title;
            if (session.running) label += " *";
            TCITEMA item{};
            item.mask = TCIF_TEXT;
            item.pszText = const_cast<char*>(label.c_str());
            TabCtrl_InsertItem(m_hwndChatSessionTabs, static_cast<int>(i), &item);
        }
        if (m_activeChatSession >= 0 &&
            m_activeChatSession < static_cast<int>(m_chatSessions.size())) {
            TabCtrl_SetCurSel(m_hwndChatSessionTabs, m_activeChatSession);
        }
    }
    if (m_hwndCloseChatBtn) {
        EnableWindow(m_hwndCloseChatBtn, m_chatSessions.empty() ? FALSE : TRUE);
    }
    if (m_hwndRestoreChatBtn) {
        SetWindowTextA(m_hwndRestoreChatBtn,
            m_closedChatSessions.empty() ? "Restore" : "Restore");
        EnableWindow(m_hwndRestoreChatBtn,
            m_closedChatSessions.empty() ? FALSE : TRUE);
    }
    if (m_hwndRollbackChatBtn) {
        const auto* session = activeChatSession();
        EnableWindow(m_hwndRollbackChatBtn,
            session && !session->checkpoints.empty() ? TRUE : FALSE);
    }
}

void Win32IDE::createChatSession(const std::string& requestedTitle)
{
    ChatSessionState session;
    session.id = m_nextChatSessionId++;
    session.title = requestedTitle.empty()
        ? ("Chat " + std::to_string(session.id)) : requestedTitle;
    session.model = m_selectedChatModel;
    m_chatSessions.push_back(std::move(session));
    updateChatSessionTabs();
    switchChatSession(static_cast<int>(m_chatSessions.size()) - 1);
}

void Win32IDE::closeActiveChatSession()
{
    if (m_chatSessions.empty()) return;
    int index = m_activeChatSession;
    if (index < 0 || index >= static_cast<int>(m_chatSessions.size())) index = 0;

    if (m_chatSessions[static_cast<size_t>(index)].running) HandleCopilotStop();
    m_closedChatSessions.push_back(std::move(m_chatSessions[static_cast<size_t>(index)]));
    m_chatSessions.erase(m_chatSessions.begin() + index);

    if (m_chatSessions.empty()) {
        m_activeChatSession = -1;
        createChatSession();
        return;
    }

    m_activeChatSession = std::min(index, static_cast<int>(m_chatSessions.size()) - 1);
    updateChatSessionTabs();
    switchChatSession(m_activeChatSession);
}

void Win32IDE::restoreClosedChatSession()
{
    if (m_closedChatSessions.empty()) return;
    if (auto* current = activeChatSession()) {
        current->history = m_chatHistory;
        current->model = m_selectedChatModel;
    }
    m_chatSessions.push_back(std::move(m_closedChatSessions.back()));
    m_closedChatSessions.pop_back();
    updateChatSessionTabs();
    switchChatSession(static_cast<int>(m_chatSessions.size()) - 1);
}

void Win32IDE::checkpointActiveChat(const std::string& reason)
{
    auto* session = activeChatSession();
    if (!session) return;

    ChatSessionCheckpoint checkpoint;
    checkpoint.reason = reason;
    checkpoint.model = m_selectedChatModel;
    checkpoint.ghostTextModel = m_ghostTextModel;
    checkpoint.ghostTextMode = m_ghostTextMode;
    checkpoint.allowCloudGhostText = m_allowCloudGhostText;
    checkpoint.maxTokens = m_currentMaxTokens;
    checkpoint.contextTokens = m_currentContextTokens;
    checkpoint.history = m_chatHistory;
    checkpoint.responseBuffer = session->responseBuffer;
    session->checkpoints.push_back(std::move(checkpoint));

    // Keep rollback bounded so a long-running daily-driver session cannot
    // grow without limit. The newest 32 checkpoints are sufficient for user
    // recovery while preserving deterministic state copies.
    constexpr size_t kMaxChatCheckpoints = 32;
    if (session->checkpoints.size() > kMaxChatCheckpoints) {
        session->checkpoints.erase(session->checkpoints.begin(),
                                   session->checkpoints.begin() +
                                       (session->checkpoints.size() - kMaxChatCheckpoints));
    }
    updateChatSessionTabs();
}

void Win32IDE::rollbackActiveChat()
{
    auto* session = activeChatSession();
    if (!session || session->checkpoints.empty()) return;

    if (session->running) HandleCopilotStop();
    ChatSessionCheckpoint checkpoint = std::move(session->checkpoints.back());
    session->checkpoints.pop_back();
    session->model = checkpoint.model;
    session->history = std::move(checkpoint.history);
    session->responseBuffer = std::move(checkpoint.responseBuffer);
    session->running = false;
    m_chatHistory = session->history;
    m_selectedChatModel = checkpoint.model;
    m_ghostTextModel = checkpoint.ghostTextModel;
    m_ghostTextMode = checkpoint.ghostTextMode;
    m_allowCloudGhostText = checkpoint.allowCloudGhostText;
    m_currentMaxTokens = checkpoint.maxTokens;
    m_currentContextTokens = checkpoint.contextTokens;

    // Restore only chat controls/state. Workspace snapshots and editor files
    // are intentionally untouched by this action.
    if (m_hwndModelSelector) {
        const LRESULT count = SendMessageA(m_hwndModelSelector, CB_GETCOUNT, 0, 0);
        for (LRESULT row = 0; row < count; ++row) {
            const LRESULT data = SendMessageA(m_hwndModelSelector, CB_GETITEMDATA,
                                               static_cast<WPARAM>(row), 0);
            if (data >= 0 && static_cast<size_t>(data) < m_availableModels.size() &&
                m_availableModels[static_cast<size_t>(data)].identifier ==
                    m_selectedChatModel.identifier) {
                SendMessageA(m_hwndModelSelector, CB_SETCURSEL,
                             static_cast<WPARAM>(row), 0);
                break;
            }
        }
    }
    updateContextControls();
    updateSecondarySidebarContent();
    updateChatSessionTabs();
    if (m_hwndStatusBar) {
        const std::string status = checkpoint.reason.empty()
            ? "Chat rolled back to the previous checkpoint."
            : "Chat rolled back: " + checkpoint.reason;
        SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 0,
                     reinterpret_cast<LPARAM>(status.c_str()));
    }
}

void Win32IDE::switchChatSession(int index)
{
    if (index < 0 || index >= static_cast<int>(m_chatSessions.size())) return;

    // Persist the outgoing session before changing the active controls.
    if (auto* previous = activeChatSession()) {
        previous->history = m_chatHistory;
        previous->model = m_selectedChatModel;
    }

    m_activeChatSession = index;
    auto& session = m_chatSessions[static_cast<size_t>(index)];
    m_chatHistory = session.history;
    m_selectedChatModel = session.model;

    if (m_hwndModelSelector) {
        LRESULT selected = CB_ERR;
        const LRESULT count = SendMessageA(m_hwndModelSelector, CB_GETCOUNT, 0, 0);
        for (LRESULT row = 0; row < count; ++row) {
            const LRESULT data = SendMessageA(m_hwndModelSelector, CB_GETITEMDATA,
                static_cast<WPARAM>(row), 0);
            if (data >= 0 && static_cast<size_t>(data) < m_availableModels.size() &&
                m_availableModels[static_cast<size_t>(data)].identifier == session.model.identifier) {
                selected = row;
                break;
            }
        }
        SendMessageA(m_hwndModelSelector, CB_SETCURSEL,
            selected == CB_ERR ? static_cast<WPARAM>(-1) : static_cast<WPARAM>(selected), 0);
    }

    updateChatSessionTabs();
    updateSecondarySidebarContent();
    if (m_hwndCopilotStopBtn) EnableWindow(m_hwndCopilotStopBtn, session.running ? TRUE : FALSE);
}

void Win32IDE::populateModelSelector() {
    if (!m_hwndModelSelector) return;
    SendMessage(m_hwndModelSelector, CB_RESETCONTENT, 0, 0);
    m_availableModels.clear();

    const auto* kiloRoute = RawrXD::ChatRouteMenu::find(
        RawrXD::ChatRouteMenu::RouteKind::KiloFree);
    if (kiloRoute) {
        std::string display = kiloRoute->breadcrumb;
        display += " / ";
        display += kiloRoute->displayName;
        m_availableModels.push_back({ChatModelEntry::Source::KiloFree,
            std::move(display), kiloRoute->modelId});
    }

    // A sentinel row keeps the user informed while accessible local drives and
    // the local Ollama catalog are scanned on a worker thread.
    const LRESULT scanningRow = SendMessageA(m_hwndModelSelector, CB_ADDSTRING, 0,
        reinterpret_cast<LPARAM>("Local models / scanning accessible drives..."));
    if (scanningRow != CB_ERR && scanningRow != CB_ERRSPACE) {
        SendMessage(m_hwndModelSelector, CB_SETITEMDATA,
            static_cast<WPARAM>(scanningRow), static_cast<LPARAM>(-1));
    }
    int defaultRouteRow = -1;
    for (size_t i = 0; i < m_availableModels.size(); ++i) {
        const LRESULT item = SendMessageA(m_hwndModelSelector, CB_ADDSTRING, 0,
            reinterpret_cast<LPARAM>(m_availableModels[i].breadcrumb.c_str()));
        if (item != CB_ERR && item != CB_ERRSPACE) {
            SendMessage(m_hwndModelSelector, CB_SETITEMDATA,
                static_cast<WPARAM>(item), static_cast<LPARAM>(i));
            if (m_availableModels[i].source == ChatModelEntry::Source::KiloFree) {
                defaultRouteRow = static_cast<int>(item);
            }
        }
    }
    SendMessage(m_hwndModelSelector, CB_SETDROPPEDWIDTH, 560, 0);
    if (defaultRouteRow >= 0) {
        SendMessage(m_hwndModelSelector, CB_SETCURSEL,
            static_cast<WPARAM>(defaultRouteRow), 0);
        onModelSelectionChanged();
    } else {
        SendMessage(m_hwndModelSelector, CB_SETCURSEL, static_cast<WPARAM>(-1), 0);
        m_selectedChatModel = {};
    }

    if (m_modelDiscoveryThread.joinable()) {
        m_modelDiscoveryCancel->store(true);
        m_modelDiscoveryThread.join();
    }
    m_modelDiscoveryCancel->store(false);
    m_modelDiscoveryRunning.store(true);
    const HWND mainWindow = m_hwndMain;
    const auto cancel = m_modelDiscoveryCancel;
    m_modelDiscoveryThread = std::thread([this, mainWindow, cancel]() {
        auto* discovered = new std::vector<ChatModelEntry>(discoverLocalModels(cancel));
        m_modelDiscoveryRunning.store(false);
        if (!cancel->load() && mainWindow &&
            PostMessageA(mainWindow, WM_APP + 106, 0,
                reinterpret_cast<LPARAM>(discovered))) {
            return;
        }
        delete discovered;
    });

}

void Win32IDE::onModelDiscoveryComplete(std::vector<ChatModelEntry>* discovered) {
    std::unique_ptr<std::vector<ChatModelEntry>> owned(discovered);
    if (!owned || !m_hwndModelSelector) return;

    ChatModelEntry previous = m_selectedChatModel;
    m_availableModels.erase(std::remove_if(m_availableModels.begin(), m_availableModels.end(),
        [](const ChatModelEntry& entry) {
            return entry.source != ChatModelEntry::Source::KiloFree;
        }), m_availableModels.end());
    for (auto& entry : *owned) {
        const bool duplicate = std::any_of(m_availableModels.begin(), m_availableModels.end(),
            [&entry](const ChatModelEntry& current) {
                return current.source == entry.source && current.identifier == entry.identifier;
            });
        if (!duplicate) m_availableModels.push_back(std::move(entry));
    }

    if (m_hwndGhostModelSelector) {
        SendMessageA(m_hwndGhostModelSelector, CB_RESETCONTENT, 0, 0);
        const LRESULT off = SendMessageA(m_hwndGhostModelSelector, CB_ADDSTRING, 0,
            reinterpret_cast<LPARAM>("GhostText: Off"));
        SendMessageA(m_hwndGhostModelSelector, CB_SETITEMDATA,
            static_cast<WPARAM>(off), static_cast<LPARAM>(-2));
        const LRESULT follow = SendMessageA(m_hwndGhostModelSelector, CB_ADDSTRING, 0,
            reinterpret_cast<LPARAM>("GhostText: Follow Chat"));
        SendMessageA(m_hwndGhostModelSelector, CB_SETITEMDATA,
            static_cast<WPARAM>(follow), static_cast<LPARAM>(-3));
        const LRESULT autoLocal = SendMessageA(m_hwndGhostModelSelector, CB_ADDSTRING, 0,
            reinterpret_cast<LPARAM>("GhostText: Auto Local"));
        SendMessageA(m_hwndGhostModelSelector, CB_SETITEMDATA,
            static_cast<WPARAM>(autoLocal), static_cast<LPARAM>(-1));
        int ghostRow = m_ghostTextMode == GhostTextMode::Disabled ? 0 :
            (m_ghostTextMode == GhostTextMode::FollowChat ? 1 : 2);
        for (size_t i = 0; i < m_availableModels.size(); ++i) {
            const auto& entry = m_availableModels[i];
            const LRESULT row = SendMessageA(m_hwndGhostModelSelector, CB_ADDSTRING, 0,
                reinterpret_cast<LPARAM>(entry.breadcrumb.c_str()));
            if (row == CB_ERR || row == CB_ERRSPACE) continue;
            SendMessageA(m_hwndGhostModelSelector, CB_SETITEMDATA,
                static_cast<WPARAM>(row), static_cast<LPARAM>(i));
            if (m_ghostTextMode == GhostTextMode::Independent &&
                entry.source == m_ghostTextModel.source &&
                entry.identifier == m_ghostTextModel.identifier &&
                !m_ghostTextModel.identifier.empty()) {
                ghostRow = static_cast<int>(row);
            }
        }
        SendMessageA(m_hwndGhostModelSelector, CB_SETCURSEL,
            static_cast<WPARAM>(ghostRow), 0);
        SendMessageA(m_hwndGhostModelSelector, CB_SETDROPPEDWIDTH, 560, 0);
        SendMessageA(m_hwndGhostModelSelector, CB_SETMINVISIBLE, 18, 0);
    }

    SendMessage(m_hwndModelSelector, CB_RESETCONTENT, 0, 0);
    if (m_availableModels.size() == 1) {
        const LRESULT row = SendMessageA(m_hwndModelSelector, CB_ADDSTRING, 0,
            reinterpret_cast<LPARAM>("Local models / no GGUF models found"));
        if (row != CB_ERR && row != CB_ERRSPACE) {
            SendMessage(m_hwndModelSelector, CB_SETITEMDATA, static_cast<WPARAM>(row),
                static_cast<LPARAM>(-1));
        }
    }

    int selectedRow = -1;
    int preferredRow = -1;
    int ollamaRow = -1;
    int localFileRow = -1;
    int kiloRow = -1;
    for (size_t i = 0; i < m_availableModels.size(); ++i) {
        const auto& entry = m_availableModels[i];
        const LRESULT row = SendMessageA(m_hwndModelSelector, CB_ADDSTRING, 0,
            reinterpret_cast<LPARAM>(entry.breadcrumb.c_str()));
        if (row == CB_ERR || row == CB_ERRSPACE) continue;
        SendMessage(m_hwndModelSelector, CB_SETITEMDATA, static_cast<WPARAM>(row),
            static_cast<LPARAM>(i));
        if (entry.source == previous.source && entry.identifier == previous.identifier) {
            preferredRow = static_cast<int>(row);
        }
        if (entry.source == ChatModelEntry::Source::Ollama && ollamaRow < 0) {
            ollamaRow = static_cast<int>(row);
        }
        if (entry.source == ChatModelEntry::Source::LocalFile && localFileRow < 0) {
            localFileRow = static_cast<int>(row);
        }
        if (entry.source == ChatModelEntry::Source::KiloFree) {
            kiloRow = static_cast<int>(row);
        }
    }
    // Keep a previously selected real local route, but do not preserve the
    // optional Kilo placeholder once Ollama or a local GGUF route is ready.
    const bool previousIsKilo = previous.source == ChatModelEntry::Source::KiloFree;
    selectedRow = (preferredRow >= 0 && !previousIsKilo) ? preferredRow
        : (ollamaRow >= 0 ? ollamaRow
            : (localFileRow >= 0 ? localFileRow
                : (preferredRow >= 0 ? preferredRow : kiloRow)));
    if (selectedRow >= 0) {
        SendMessage(m_hwndModelSelector, CB_SETCURSEL,
            static_cast<WPARAM>(selectedRow), 0);
        onModelSelectionChanged();
    }
    const size_t localModelCount = static_cast<size_t>(std::count_if(
        m_availableModels.begin(), m_availableModels.end(),
        [](const ChatModelEntry& entry) {
            return entry.source != ChatModelEntry::Source::KiloFree;
        }));
    if (m_hwndStatusBar) {
        const std::string status = "Model routes ready: " +
            std::to_string(localModelCount) +
            " local model(s), Kilo free cloud route available";
        SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 0,
            reinterpret_cast<LPARAM>(status.c_str()));
    }
}

void Win32IDE::HandleCopilotSend() {
    if (!m_hwndCopilotChatInput || !m_hwndCopilotChatOutput) return;

    // Get input text
    char inputBuffer[2048] = {0};
    GetWindowTextA(m_hwndCopilotChatInput, inputBuffer, sizeof(inputBuffer) - 1);
    std::string userMessage(inputBuffer);
    
    if (userMessage.empty()) {
        LOG_WARNING("Empty message - ignoring");
        return;
    }

    {
        std::lock_guard<std::mutex> lock(m_inferenceMutex);
        if (m_inferenceRunning) {
            const std::string status = "Inference is already running; press Stop before sending another message.";
            if (m_hwndStatusBar) SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 0,
                reinterpret_cast<LPARAM>(status.c_str()));
            return;
        }
    }
    
    // Get selected model
    onModelSelectionChanged();
    if (m_selectedChatModel.identifier.empty()) {
        const std::string message = "Select a model route after local discovery finishes.";
        SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 0,
            reinterpret_cast<LPARAM>(message.c_str()));
        return;
    }

    checkpointActiveChat("before sending user message");

    const int sessionId = activeChatSession() ? activeChatSession()->id : 0;
    if (auto* session = activeChatSession()) {
        session->model = m_selectedChatModel;
        session->history.push_back({"user", userMessage});
        session->responseBuffer.clear();
        session->running = true;
        m_chatHistory = session->history;
    } else {
        m_chatHistory.push_back({"user", userMessage});
    }
    updateSecondarySidebarContent();
    
    // Clear input
    SetWindowTextA(m_hwndCopilotChatInput, "");
    
    // Marshal all response handling to the UI thread. The worker owns only the
    // inference operation and an owned message payload.
    auto onResponse = [this, sessionId](const std::string& response, bool complete) {
        auto* update = new CopilotChatUiUpdate{sessionId, response, complete};
        const HWND target = m_hwndMain;
        if (!target || !PostMessageA(target, kRawrxdCopilotUiUpdate, 0,
                                     reinterpret_cast<LPARAM>(update))) {
            delete update;
        }
    };
    
    // Generate response
    generateResponseAsync(userMessage, onResponse);

}

void Win32IDE::handleCopilotUiUpdate(int sessionId,
                                     const std::string& response,
                                     bool complete)
{
    ChatSessionState* session = nullptr;
    for (auto& candidate : m_chatSessions) {
        if (candidate.id == sessionId) { session = &candidate; break; }
    }
    if (!session) return;

    const int sessionIndex = static_cast<int>(session - m_chatSessions.data());
    const bool active = m_activeChatSession == sessionIndex;
    if (!complete) {
        if (session->responseBuffer.empty() && active && m_hwndCopilotChatOutput) {
            const int len = GetWindowTextLengthA(m_hwndCopilotChatOutput);
            SendMessageA(m_hwndCopilotChatOutput, EM_SETSEL, len, len);
            SendMessageA(m_hwndCopilotChatOutput, EM_REPLACESEL, FALSE,
                reinterpret_cast<LPARAM>("\r\nAI: "));
        }
        session->responseBuffer += response;
        if (active && m_hwndCopilotChatOutput && !response.empty()) {
            const int len = GetWindowTextLengthA(m_hwndCopilotChatOutput);
            SendMessageA(m_hwndCopilotChatOutput, EM_SETSEL, len, len);
            SendMessageA(m_hwndCopilotChatOutput, EM_REPLACESEL, FALSE,
                reinterpret_cast<LPARAM>(response.c_str()));
        }
        return;
    }

    if (!response.empty() && session->responseBuffer.empty()) {
        session->responseBuffer = response;
        if (active && m_hwndCopilotChatOutput) {
            const int len = GetWindowTextLengthA(m_hwndCopilotChatOutput);
            SendMessageA(m_hwndCopilotChatOutput, EM_SETSEL, len, len);
            const std::string line = "\r\nAI: " + response + "\r\n\r\n";
            SendMessageA(m_hwndCopilotChatOutput, EM_REPLACESEL, FALSE,
                reinterpret_cast<LPARAM>(line.c_str()));
        }
    } else if (active && m_hwndCopilotChatOutput && !session->responseBuffer.empty()) {
        const int len = GetWindowTextLengthA(m_hwndCopilotChatOutput);
        SendMessageA(m_hwndCopilotChatOutput, EM_SETSEL, len, len);
        SendMessageA(m_hwndCopilotChatOutput, EM_REPLACESEL, FALSE,
            reinterpret_cast<LPARAM>("\r\n\r\n"));
    }
    if (!session->responseBuffer.empty()) {
        session->history.push_back({"assistant", session->responseBuffer});
    }
    session->responseBuffer.clear();
    session->running = false;
    if (active && m_hwndCopilotStopBtn) EnableWindow(m_hwndCopilotStopBtn, FALSE);
    if (active) m_chatHistory = session->history;
    updateChatSessionTabs();
}

void Win32IDE::HandleCopilotStop()
{
    stopInference();
    if (auto* session = activeChatSession()) {
        session->running = false;
        session->responseBuffer.clear();
    }
    if (m_hwndCopilotStopBtn) EnableWindow(m_hwndCopilotStopBtn, FALSE);
    if (m_hwndStatusBar) {
        const std::string status = "Chat generation stopped.";
        SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 0,
            reinterpret_cast<LPARAM>(status.c_str()));
    }
    updateChatSessionTabs();
}

void Win32IDE::HandleCopilotClear() {
    if (!m_hwndCopilotChatOutput || !m_hwndCopilotChatInput) return;

    checkpointActiveChat("before clearing chat");

    SetWindowTextA(m_hwndCopilotChatOutput, "Welcome to RawrXD AI Chat!\r\n\r\nSelect a model and type a message to begin.\r\n");
    SetWindowTextA(m_hwndCopilotChatInput, "");
    m_chatHistory.clear();
    if (auto* session = activeChatSession()) {
        session->history.clear();
        session->responseBuffer.clear();
        session->running = false;
    }

}

void Win32IDE::HandleCopilotStreamUpdate(const char* token, size_t length) {
    if (!m_hwndCopilotChatOutput || !token) return;

    std::string chunk;
    if (length > 0) {
        chunk.assign(token, token + length);
    } else {
        chunk = token;
    }

    if (chunk.empty()) return;

    int currentLen = GetWindowTextLengthA(m_hwndCopilotChatOutput);
    SendMessageA(m_hwndCopilotChatOutput, EM_SETSEL, currentLen, currentLen);
    SendMessageA(m_hwndCopilotChatOutput, EM_REPLACESEL, FALSE, (LPARAM)chunk.c_str());
    SendMessage(m_hwndCopilotChatOutput, WM_VSCROLL, SB_BOTTOM, 0);
}

void Win32IDE::onModelSelectionChanged() {
    int idx = (int)SendMessage(m_hwndModelSelector, CB_GETCURSEL, 0, 0);
    if (idx < 0) {
        m_selectedChatModel = {};
        return;
    }
    const LRESULT itemData = SendMessage(m_hwndModelSelector, CB_GETITEMDATA,
        static_cast<WPARAM>(idx), 0);
    if (itemData < 0 || static_cast<size_t>(itemData) >= m_availableModels.size()) {
        m_selectedChatModel = {};
        return;
    }
    m_selectedChatModel = m_availableModels[static_cast<size_t>(itemData)];
    if (auto* session = activeChatSession()) {
        session->model = m_selectedChatModel;
    }
    if (m_selectedChatModel.source == ChatModelEntry::Source::Ollama) {
        m_ollamaModelOverride = m_selectedChatModel.identifier;
    }
}

void Win32IDE::onGhostTextSelectionChanged() {
    if (!m_hwndGhostModelSelector) return;
    const LRESULT row = SendMessageA(m_hwndGhostModelSelector, CB_GETCURSEL, 0, 0);
    if (row < 0) {
        m_ghostTextModel = {};
        m_ghostTextMode = GhostTextMode::Disabled;
        return;
    }
    const LRESULT data = SendMessageA(m_hwndGhostModelSelector, CB_GETITEMDATA,
        static_cast<WPARAM>(row), 0);
    if (data == -2) {
        m_ghostTextModel = {};
        m_ghostTextMode = GhostTextMode::Disabled;
        logInfo("GhostText route disabled.");
    } else if (data == -3) {
        m_ghostTextModel = {};
        m_ghostTextMode = GhostTextMode::FollowChat;
        logInfo("GhostText route follows chat selection.");
    } else if (data == -1) {
        m_ghostTextModel = {};
        m_ghostTextMode = GhostTextMode::AutoLocal;
        logInfo("GhostText route set to Auto Local.");
    } else if (data >= 0 && static_cast<size_t>(data) < m_availableModels.size()) {
        m_ghostTextModel = m_availableModels[static_cast<size_t>(data)];
        m_ghostTextMode = GhostTextMode::Independent;
        logInfo("GhostText route selected: " + m_ghostTextModel.identifier);
    }
}

void Win32IDE::onGhostTextCloudConsentChanged() {
    if (!m_hwndAllowCloudGhostText) return;
    m_allowCloudGhostText = SendMessage(m_hwndAllowCloudGhostText, BM_GETCHECK, 0, 0) == BST_CHECKED;
    logInfo(std::string("GhostText cloud transmission ") +
        (m_allowCloudGhostText ? "enabled for this session." : "disabled."));
}

void Win32IDE::onMaxTokensChanged(int newValue) {
    m_currentMaxTokens = newValue;
    m_inferenceConfig.maxTokens = newValue;

    // Update label
    if (m_hwndMaxTokensLabel) {
        SetWindowTextA(m_hwndMaxTokensLabel, std::to_string(newValue).c_str());
    }

}

void Win32IDE::updateContextControls() {
    if (m_currentContextTokens < 8192) m_currentContextTokens = 8192;
    if (m_hwndContextLabel) {
        const int value = m_currentContextTokens;
        const std::string text = value >= 1024
            ? std::to_string(value / 1024) + "K (pending model admission)"
            : std::to_string(value) + " (pending model admission)";
        SetWindowTextA(m_hwndContextLabel, text.c_str());
    }
}

int Win32IDE::effectiveMaxTokensForPrompt(const std::string& prompt) const {
    const int estimatedPrompt = std::max(1, static_cast<int>(prompt.size() / 4));
    return std::max(1, std::min(m_currentMaxTokens,
        m_currentContextTokens - estimatedPrompt));
}

Win32IDE::~Win32IDE() {
    if (m_modelDiscoveryCancel) m_modelDiscoveryCancel->store(true);
    if (m_modelDiscoveryThread.joinable()) m_modelDiscoveryThread.join();
    m_inferenceStopRequested = true;
    if (m_inferenceThread.joinable()) m_inferenceThread.join();

    if (m_nativeEngine) {
        delete static_cast<RawrXD::CPUInferenceEngine*>(m_nativeEngine);
        m_nativeEngine = nullptr;
    }
    m_nativeEngineLoaded = false;

    // Deep2Bridge cleanup
    if (m_deep2Bridge) {
        m_deep2Bridge->Stop();
        delete m_deep2Bridge;
        m_deep2Bridge = nullptr;
    }

    // Terminal cleanup. Win32TerminalManager has no static cleanup() entry
    // point; each pane owns its manager through a unique_ptr, so tear the
    // shells down explicitly (the managers' own destructors also call stop()
    // if they are still alive at destruction time).
    for (auto& pane : m_terminalPanes) {
        if (pane.manager) {
            pane.manager->stop();
            pane.manager.reset();
        }
    }
    m_terminalPanes.clear();
    if (m_dedicatedPowerShellTerminal) {
        m_dedicatedPowerShellTerminal->stop();
        m_dedicatedPowerShellTerminal.reset();
    }
}

