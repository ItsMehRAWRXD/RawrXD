// Agent menu implementation for Win32IDE
// Implements all agentic framework menu commands and integrations

#include "Win32IDE.h"
#include "Win32IDE_AgenticBridge.h"
#include "Win32IDE_Deep2Bridge.h"
#include "Win32IDE_AgenticLoopBridge.h"
#include "ModelConnection.h"
#include "IDELogger.h"
#include <sstream>
#include <cstdlib>
#include <filesystem>

namespace {

// The CLI's structured [ESP] records are already rendered by the ESP panel.
// Keep them in the raw evidence log, but do not append the same records again
// through the progress-text path into Output/Chat.
std::string FilterStructuredEspLines(const std::string& raw)
{
    std::string visible;
    size_t cursor = 0;
    while (cursor < raw.size()) {
        const size_t end = raw.find_first_of("\r\n", cursor);
        const size_t length = (end == std::string::npos) ? raw.size() - cursor : end - cursor;
        const std::string line = raw.substr(cursor, length);
        size_t first = 0;
        while (first < line.size() && (line[first] == ' ' || line[first] == '\t')) ++first;
        if (line.compare(first, 5, "[ESP]") != 0 && !line.empty()) {
            visible.append(line);
            visible.append("\r\n");
        }
        if (end == std::string::npos) break;
        cursor = end + 1;
        if (cursor < raw.size() && raw[end] == '\r' && raw[cursor] == '\n') ++cursor;
    }
    return visible;
}

}

// Initialize the Agentic Bridge
void Win32IDE::initializeAgenticBridge() {
    // This bridge remains available for the legacy native chat commands. It
    // is intentionally isolated from autonomous tasks: those always use the
    // lifecycle-safe AgenticLoopBridge, which owns process recovery, timeout
    // handling, and durable transaction cleanup.
    LOG_INFO("Initializing legacy Agentic Bridge (isolated from autonomous loop)");
    
    if (!m_agenticBridge) {
        m_agenticBridge = std::make_unique<AgenticBridge>(this);
        
        // Set output callback to send agent responses to Copilot Chat
        m_agenticBridge->SetOutputCallback([this](const std::string& title, const std::string& content) {
            appendToOutput(title + ":\n" + content + "\n", "Output", OutputSeverity::Info);
            
            // Also send to Copilot Chat if available
            if (m_hwndCopilotChatOutput) {
                std::string formatted = " " + title + "\n" + content + "\n\n";
                appendCopilotChatUtf8(formatted);
            }
        });
        
        // Initialize with default framework path
        if (m_agenticBridge->Initialize("", "bigdaddyg-personalized-agentic:latest")) {
            LOG_INFO("Legacy Agentic Bridge initialized successfully; autonomous tasks use AgenticLoopBridge");
            appendToOutput(" Agentic Framework initialized\n", "Output", OutputSeverity::Info);
        } else {
            LOG_ERROR("Failed to initialize Agentic Bridge");
            appendToOutput(" Failed to initialize Agentic Framework\n", "Errors", OutputSeverity::Error);
            MessageBoxA(m_hwndMain, 
                "Failed to initialize Agentic Framework.\nMake sure Agentic-Framework.ps1 is in the Powershield folder.", 
                "Agent Error", MB_OK | MB_ICONERROR);
        }
    }
}

// Start Agent Loop - multi-turn agentic conversation
void Win32IDE::onAgentStartLoop() {
    LOG_INFO("onAgentStartLoop called");
    
    if (!m_agenticBridge) {
        initializeAgenticBridge();
    }
    
    if (!m_agenticBridge || !m_agenticBridge->IsInitialized()) {
        MessageBoxA(m_hwndMain, "Agentic Framework not initialized", "Agent Error", MB_OK | MB_ICONERROR);
        return;
    }
    
    // Show input dialog for user prompt
    char prompt[1024] = {0};
    if (DialogBoxParamA(m_hInstance, "AGENT_PROMPT_DLG", m_hwndMain, 
        [](HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) -> INT_PTR {
            switch (msg) {
                case WM_INITDIALOG: {
                    SetWindowTextA(GetDlgItem(hwnd, 101), "Enter your task for the agent:");
                    return TRUE;
                }
                case WM_COMMAND:
                    if (LOWORD(wp) == IDOK) {
                        GetDlgItemTextA(hwnd, 102, (char*)lp, 1024);
                        EndDialog(hwnd, IDOK);
                        return TRUE;
                    } else if (LOWORD(wp) == IDCANCEL) {
                        EndDialog(hwnd, IDCANCEL);
                        return TRUE;
                    }
                    break;
            }
            return FALSE;
        }, (LPARAM)prompt) != IDOK) {
        return;
    }
    
    // Fallback to simple input box if dialog fails
    if (strlen(prompt) == 0) {
        strcpy_s(prompt, "Analyze the current file and suggest improvements");
    }
    
    std::string promptStr(prompt);
    
    // Start agent loop in background thread
    appendToOutput(" Starting Agent Loop: " + promptStr + "\n", "Output", OutputSeverity::Info);
    
    std::thread([this, promptStr]() {
        if (m_agenticBridge->StartAgentLoop(promptStr, 10)) {
            LOG_INFO("Agent loop completed successfully");
        } else {
            LOG_ERROR("Agent loop failed");
        }
    }).detach();
}

// Execute single agent command
void Win32IDE::onAgentExecuteCommand() {
    LOG_INFO("onAgentExecuteCommand called");
    
    if (!m_agenticBridge) {
        initializeAgenticBridge();
    }
    
    if (!m_agenticBridge || !m_agenticBridge->IsInitialized()) {
        MessageBoxA(m_hwndMain, "Agentic Framework not initialized", "Agent Error", MB_OK | MB_ICONERROR);
        return;
    }
    
    // Get command from Copilot Chat input
    if (m_hwndCopilotChatInput) {
        char input[2048] = {0};
        GetWindowTextA(m_hwndCopilotChatInput, input, sizeof(input));
        
        if (strlen(input) == 0) {
            MessageBoxA(m_hwndMain, "Enter a command in the Copilot Chat input box", "Agent", MB_OK | MB_ICONINFORMATION);
            return;
        }
        
        std::string command(input);
        appendToOutput(" Executing Agent Command: " + command + "\n", "Output", OutputSeverity::Info);
        
        // Execute in background
        std::thread([this, command]() {
            AgentResponse response = m_agenticBridge->ExecuteAgentCommand(command);
            
            std::string output = "Agent Response:\n";
            output += "Type: " + std::to_string((int)response.type) + "\n";
            output += "Content: " + response.content + "\n";
            
            if (!response.toolName.empty()) {
                output += "Tool: " + response.toolName + "\n";
                output += "Args: " + response.toolArgs + "\n";
            }
            
            appendToOutput(output, "Output", OutputSeverity::Info);
        }).detach();
        
        // Clear input
        SetWindowTextW(m_hwndCopilotChatInput, L"");
    } else {
        MessageBoxA(m_hwndMain, "Copilot Chat input not available", "Agent Error", MB_OK | MB_ICONERROR);
    }
}

#if 0
// Configure AI model (legacy nested modal implementation; retained for reference)
void Win32IDE::onAgentConfigureModel() {
    LOG_INFO("onAgentConfigureModel called");
    
    if (!m_agenticBridge) {
        initializeAgenticBridge();
    }
    
    if (!m_agenticBridge) {
        return;
    }
    
    // Retrieve available models from the local model service (fallback to defaults)
    std::vector<std::string> availableModels;
    try {
        ModelConnection connection;
        availableModels = connection.getAvailableModels();
    } catch (...) {
        availableModels.clear();
    }

    if (availableModels.empty()) {
        availableModels = {
            "bigdaddyg-personalized-agentic:latest",
            "codestral:latest",
            "llama3.3:latest"
        };
    }

    // Ensure current model is present and pre-selected
    const std::string currentModel = m_agenticBridge->GetCurrentModel();
    if (std::find(availableModels.begin(), availableModels.end(), currentModel) == availableModels.end()) {
        availableModels.insert(availableModels.begin(), currentModel);
    }

    // Create a lightweight modal selection dialog (no resource template required)
    const int dlgWidth = 480;
    const int dlgHeight = 240;
    RECT parentRect{};
    GetWindowRect(m_hwndMain, &parentRect);
    HMONITOR monitor = MonitorFromWindow(m_hwndMain, MONITOR_DEFAULTTONEAREST);
    MONITORINFO monitorInfo{sizeof(monitorInfo)};
    RECT workArea = parentRect;
    if (monitor && GetMonitorInfoA(monitor, &monitorInfo)) {
        workArea = monitorInfo.rcWork;
    }
    const int availableWidth = workArea.right - workArea.left;
    const int availableHeight = workArea.bottom - workArea.top;
    const int dlgX = (std::max)(workArea.left,
        workArea.left + ((availableWidth - dlgWidth) / 2));
    const int dlgY = (std::max)(workArea.top,
        workArea.top + ((availableHeight - dlgHeight) / 2));

    EnableWindow(m_hwndMain, FALSE);

    HWND hwndDlg = CreateWindowExA(WS_EX_DLGMODALFRAME | WS_EX_CONTROLPARENT,
        "STATIC", "Select Agent Model",
        WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE | WS_CLIPCHILDREN,
        dlgX, dlgY, dlgWidth, dlgHeight, m_hwndMain, nullptr, m_hInstance, nullptr);

    if (!hwndDlg) {
        EnableWindow(m_hwndMain, TRUE);
        MessageBoxA(m_hwndMain, "Failed to create model selection dialog", "Agent", MB_OK | MB_ICONERROR);
        return;
    }

    HWND hwndPrompt = CreateWindowExA(0, "STATIC", "Choose an available model:",
        WS_CHILD | WS_VISIBLE | SS_LEFTNOWORDWRAP,
        18, 14, dlgWidth - 36, 24, hwndDlg, nullptr, m_hInstance, nullptr);

    HWND hwndCombo = CreateWindowExA(WS_EX_CLIENTEDGE, "COMBOBOX", "",
        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
        18, 48, dlgWidth - 36, 112, hwndDlg,
        reinterpret_cast<HMENU>(static_cast<UINT_PTR>(1001)), m_hInstance, nullptr);

    int selectedIndex = 0;
    for (size_t i = 0; i < availableModels.size(); ++i) {
        const auto& model = availableModels[i];
        SendMessageA(hwndCombo, CB_ADDSTRING, 0, (LPARAM)model.c_str());
        if (model == currentModel) {
            selectedIndex = static_cast<int>(i);
        }
    }
    SendMessageA(hwndCombo, CB_SETCURSEL, selectedIndex, 0);
    HFONT dialogFont = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));
    if (hwndPrompt) SendMessageA(hwndPrompt, WM_SETFONT,
        reinterpret_cast<WPARAM>(dialogFont), TRUE);
    SendMessageA(hwndCombo, WM_SETFONT, reinterpret_cast<WPARAM>(dialogFont), TRUE);

    HWND hwndOk = CreateWindowExA(0, "BUTTON", "Use Model",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
        dlgWidth - 220, dlgHeight - 68, 96, 32, hwndDlg,
        (HMENU)IDOK, m_hInstance, nullptr);
    HWND hwndCancel = CreateWindowExA(0, "BUTTON", "Cancel",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        dlgWidth - 114, dlgHeight - 68, 96, 32, hwndDlg,
        (HMENU)IDCANCEL, m_hInstance, nullptr);
    if (hwndOk) SendMessageA(hwndOk, WM_SETFONT,
        reinterpret_cast<WPARAM>(dialogFont), TRUE);
    if (hwndCancel) SendMessageA(hwndCancel, WM_SETFONT,
        reinterpret_cast<WPARAM>(dialogFont), TRUE);

    // The popup is owned by the IDE, but the main window is disabled while it
    // is active.  Explicitly raise and focus it so it can never appear behind
    // the disabled IDE and look like a frozen application.
    SetWindowPos(hwndDlg, HWND_TOP, dlgX, dlgY, dlgWidth, dlgHeight,
                 SWP_SHOWWINDOW);
    SetForegroundWindow(hwndDlg);
    SetActiveWindow(hwndDlg);
    SetFocus(hwndCombo);

    bool accepted = false;
    std::string selectedModel = currentModel;

    MSG msg{};
    while (IsWindow(hwndDlg) && GetMessage(&msg, nullptr, 0, 0) > 0) {
        // A STATIC-class popup has no dialog procedure of its own.  Handle
        // close/escape here before dispatching so the disabled IDE is always
        // released even when the user clicks the title-bar X or presses Esc.
        if ((msg.message == WM_CLOSE && msg.hwnd == hwndDlg) ||
            (msg.message == WM_SYSCOMMAND && msg.hwnd == hwndDlg &&
             (msg.wParam & 0xFFF0u) == SC_CLOSE) ||
            (msg.message == WM_KEYDOWN && msg.wParam == VK_ESCAPE &&
             (msg.hwnd == hwndDlg || IsChild(hwndDlg, msg.hwnd)))) {
            DestroyWindow(hwndDlg);
            break;
        }
        if (msg.message == WM_COMMAND) {
            const WORD cmdId = LOWORD(msg.wParam);
            const WORD cmdCode = HIWORD(msg.wParam);
            HWND sender = (HWND)msg.hwnd;

            if (cmdId == IDOK && cmdCode == BN_CLICKED) {
                int sel = (int)SendMessageA(hwndCombo, CB_GETCURSEL, 0, 0);
                if (sel != CB_ERR) {
                    char buffer[256] = {0};
                    SendMessageA(hwndCombo, CB_GETLBTEXT, sel, (LPARAM)buffer);
                    selectedModel = buffer;
                    accepted = true;
                }
                DestroyWindow(hwndDlg);
                break;
            } else if (cmdId == IDCANCEL && cmdCode == BN_CLICKED) {
                DestroyWindow(hwndDlg);
                break;
            }
        }

        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    EnableWindow(m_hwndMain, TRUE);
    SetForegroundWindow(m_hwndMain);

    if (accepted && !selectedModel.empty()) {
        m_agenticBridge->SetModel(selectedModel);
        appendToOutput(" Agent model set to: " + selectedModel + "\n", "Output", OutputSeverity::Info);
        MessageBoxA(m_hwndMain, ("Model updated to: " + selectedModel).c_str(), "Agent Model", MB_OK | MB_ICONINFORMATION);
    }
}

#endif

LRESULT CALLBACK Win32IDE::AgentModelDialogProc(HWND hwnd, UINT message,
                                                 WPARAM wParam, LPARAM lParam)
{
    auto* ide = reinterpret_cast<Win32IDE*>(
        GetWindowLongPtrA(hwnd, GWLP_USERDATA));

    if (message == WM_NCCREATE) {
        const auto* create = reinterpret_cast<const CREATESTRUCTA*>(lParam);
        ide = static_cast<Win32IDE*>(create->lpCreateParams);
        SetWindowLongPtrA(hwnd, GWLP_USERDATA,
                          reinterpret_cast<LONG_PTR>(ide));
    }

    switch (message) {
    case WM_CREATE: {
        if (!ide) return -1;
        constexpr int kComboId = 1001;
        constexpr int kDialogWidth = 460;
        constexpr int kDialogHeight = 220;
        const HFONT font = static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));

        HWND label = CreateWindowExA(
            0, "STATIC", "Choose an available agent model:",
            WS_CHILD | WS_VISIBLE, 14, 14, kDialogWidth - 28, 22,
            hwnd, nullptr, ide->m_hInstance, nullptr);
        HWND combo = CreateWindowExA(
            WS_EX_CLIENTEDGE, "COMBOBOX", "",
            WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL |
                CBS_HASSTRINGS,
            // Keep the closed combo inside the dialog.  The previous 400px
            // control height covered the action buttons and made the popup
            // appear to freeze the IDE when its list was opened.
            14, 42, kDialogWidth - 28, 112, hwnd,
            reinterpret_cast<HMENU>(static_cast<UINT_PTR>(kComboId)),
            ide->m_hInstance, nullptr);
        HWND use = CreateWindowExA(
            0, "BUTTON", "Use Model",
            WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
            kDialogWidth - 205, kDialogHeight - 54, 90, 30, hwnd,
            reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDOK)),
            ide->m_hInstance, nullptr);
        HWND cancel = CreateWindowExA(
            0, "BUTTON", "Cancel",
            WS_CHILD | WS_VISIBLE,
            kDialogWidth - 105, kDialogHeight - 54, 90, 30, hwnd,
            reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDCANCEL)),
            ide->m_hInstance, nullptr);

        for (HWND child : {label, combo, use, cancel}) {
            if (child) SendMessageA(child, WM_SETFONT,
                                    reinterpret_cast<WPARAM>(font), TRUE);
        }

        int selectedIndex = 0;
        for (size_t i = 0; i < ide->m_agentModelDialogModels.size(); ++i) {
            const auto& model = ide->m_agentModelDialogModels[i];
            SendMessageA(combo, CB_ADDSTRING, 0,
                         reinterpret_cast<LPARAM>(model.c_str()));
            if (model == ide->m_agentModelDialogCurrent) {
                selectedIndex = static_cast<int>(i);
            }
        }
        SendMessageA(combo, CB_SETCURSEL, selectedIndex, 0);
        SetFocus(combo);
        return 0;
    }

    case WM_COMMAND: {
        const WORD commandId = LOWORD(wParam);
        const WORD notification = HIWORD(wParam);
        if (!ide || notification != BN_CLICKED ||
            (commandId != IDOK && commandId != IDCANCEL)) {
            break;
        }

        if (commandId == IDOK && ide->m_agenticBridge) {
            HWND combo = GetDlgItem(hwnd, 1001);
            const LRESULT selected = SendMessageA(combo, CB_GETCURSEL, 0, 0);
            if (selected != CB_ERR) {
                const LRESULT length = SendMessageA(
                    combo, CB_GETLBTEXTLEN, selected, 0);
                if (length > 0 && length < 4096) {
                    std::string model(static_cast<size_t>(length) + 1, '\0');
                    SendMessageA(combo, CB_GETLBTEXT, selected,
                                 reinterpret_cast<LPARAM>(model.data()));
                    model.resize(static_cast<size_t>(length));
                    ide->m_agenticBridge->SetModel(model);
                    ide->appendToOutput(
                        " Agent model set to: " + model + "\n",
                        "Output", Win32IDE::OutputSeverity::Info);
                    ide->m_agentModelDialogCurrent = model;
                }
            }
        }
        DestroyWindow(hwnd);
        return 0;
    }

    case WM_KEYDOWN:
        if (wParam == VK_ESCAPE) {
            DestroyWindow(hwnd);
            return 0;
        }
        if (wParam == VK_RETURN) {
            SendMessageA(hwnd, WM_COMMAND,
                         MAKEWPARAM(IDOK, BN_CLICKED), 0);
            return 0;
        }
        break;

    case WM_CLOSE:
        DestroyWindow(hwnd);
        return 0;

    case WM_NCDESTROY:
        if (ide && ide->m_hwndAgentModelDialog == hwnd) {
            ide->m_hwndAgentModelDialog = nullptr;
        }
        SetWindowLongPtrA(hwnd, GWLP_USERDATA, 0);
        break;
    }

    return DefWindowProcA(hwnd, message, wParam, lParam);
}

// Configure the agent model without blocking the IDE UI thread.
void Win32IDE::onAgentConfigureModel()
{
    LOG_INFO("onAgentConfigureModel called");

    if (!m_agenticBridge) {
        initializeAgenticBridge();
    }
    if (!m_agenticBridge) {
        appendToOutput("Agent model configuration unavailable: bridge is not initialized.\n",
                       "Errors", OutputSeverity::Error);
        return;
    }

    if (m_hwndAgentModelDialog && IsWindow(m_hwndAgentModelDialog)) {
        SetForegroundWindow(m_hwndAgentModelDialog);
        return;
    }

    // Use the already-fenced model-discovery cache. The previous synchronous
    // /api/tags request could freeze the UI while Ollama was unavailable.
    m_agentModelDialogModels.clear();
    for (const auto& entry : m_availableModels) {
        if (!entry.identifier.empty() &&
            std::find(m_agentModelDialogModels.begin(),
                      m_agentModelDialogModels.end(),
                      entry.identifier) == m_agentModelDialogModels.end()) {
            m_agentModelDialogModels.push_back(entry.identifier);
        }
    }
    if (m_agentModelDialogModels.empty()) {
        m_agentModelDialogModels = {
            "bigdaddyg-personalized-agentic:latest",
            "codestral:latest",
            "llama3.3:latest"
        };
    }

    m_agentModelDialogCurrent = m_agenticBridge->GetCurrentModel();
    if (m_agentModelDialogCurrent.empty()) {
        m_agentModelDialogCurrent = m_agentModelDialogModels.front();
    }
    if (std::find(m_agentModelDialogModels.begin(),
                  m_agentModelDialogModels.end(),
                  m_agentModelDialogCurrent) == m_agentModelDialogModels.end()) {
        m_agentModelDialogModels.insert(m_agentModelDialogModels.begin(),
                                        m_agentModelDialogCurrent);
    }

    constexpr char kDialogClass[] = "RawrXD.AgentModelDialog";
    WNDCLASSA existing{};
    if (!GetClassInfoA(m_hInstance, kDialogClass, &existing)) {
        WNDCLASSA dialogClass{};
        dialogClass.lpfnWndProc = &Win32IDE::AgentModelDialogProc;
        dialogClass.hInstance = m_hInstance;
        dialogClass.hCursor = LoadCursor(nullptr, IDC_ARROW);
        dialogClass.hbrBackground =
            reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
        dialogClass.lpszClassName = kDialogClass;
        if (!RegisterClassA(&dialogClass)) {
            appendToOutput("Agent model configuration unavailable: dialog registration failed.\n",
                           "Errors", OutputSeverity::Error);
            return;
        }
    }

    RECT parentRect{};
    GetWindowRect(m_hwndMain, &parentRect);
    constexpr int kDialogWidth = 460;
    constexpr int kDialogHeight = 220;
    HMONITOR monitor = MonitorFromWindow(m_hwndMain, MONITOR_DEFAULTTONEAREST);
    MONITORINFO monitorInfo{sizeof(monitorInfo)};
    RECT workArea = parentRect;
    if (monitor && GetMonitorInfoA(monitor, &monitorInfo)) {
        workArea = monitorInfo.rcWork;
    }
    const int dialogX = (std::max)(workArea.left,
        workArea.left + ((workArea.right - workArea.left - kDialogWidth) / 2));
    const int dialogY = (std::max)(workArea.top,
        workArea.top + ((workArea.bottom - workArea.top - kDialogHeight) / 2));

    m_hwndAgentModelDialog = CreateWindowExA(
        WS_EX_DLGMODALFRAME | WS_EX_TOOLWINDOW,
        kDialogClass, "Select Agent Model",
        WS_POPUP | WS_CAPTION | WS_SYSMENU,
        dialogX, dialogY, kDialogWidth, kDialogHeight,
        m_hwndMain, nullptr, m_hInstance, this);
    if (!m_hwndAgentModelDialog) {
        appendToOutput("Agent model configuration unavailable: dialog creation failed.\n",
                       "Errors", OutputSeverity::Error);
        return;
    }

    ShowWindow(m_hwndAgentModelDialog, SW_SHOWNORMAL);
    UpdateWindow(m_hwndAgentModelDialog);
    SetWindowPos(m_hwndAgentModelDialog, HWND_TOP, dialogX, dialogY,
                 kDialogWidth, kDialogHeight, SWP_SHOWWINDOW);
    SetForegroundWindow(m_hwndAgentModelDialog);
    SetActiveWindow(m_hwndAgentModelDialog);
}

// View available agent tools
void Win32IDE::onAgentViewTools() {
    LOG_INFO("onAgentViewTools called");
    
    if (!m_agenticBridge) {
        initializeAgenticBridge();
    }
    
    if (!m_agenticBridge || !m_agenticBridge->IsInitialized()) {
        MessageBoxA(m_hwndMain, "Agentic Framework not initialized", "Agent Error", MB_OK | MB_ICONERROR);
        return;
    }
    
    std::vector<std::string> tools = m_agenticBridge->GetAvailableTools();
    
    std::stringstream toolsList;
    toolsList << "Available Agent Tools:\n\n";
    
    for (const auto& tool : tools) {
        toolsList << " " << tool << "\n";
    }
    
    toolsList << "\nThese tools can be invoked by the agent to perform tasks.\n";
    toolsList << "Example: TOOL:shell:{\"cmd\":\"Get-Process\"}";
    
    MessageBoxA(m_hwndMain, toolsList.str().c_str(), "Agent Tools", MB_OK | MB_ICONINFORMATION);
    
    // Also log to output
    appendToOutput(toolsList.str() + "\n", "Output", OutputSeverity::Info);
}

// View agent status
void Win32IDE::onAgentViewStatus() {
    LOG_INFO("onAgentViewStatus called");
    
    if (!m_agenticBridge) {
        appendToOutput("Agentic Bridge not initialized\n", "Output", OutputSeverity::Warning);
        MessageBoxA(m_hwndMain, "Agentic Framework not initialized.\nUse Agent > Start Loop to initialize.", "Agent Status", MB_OK | MB_ICONINFORMATION);
        return;
    }
    
    std::string status = m_agenticBridge->GetAgentStatus();
    appendToOutput("=== Agent Status ===\n" + status + "\n", "Output", OutputSeverity::Info);
    MessageBoxA(m_hwndMain, status.c_str(), "Agent Status", MB_OK | MB_ICONINFORMATION);
}

// Stop agent loop
void Win32IDE::onAgentStop() {
    LOG_INFO("onAgentStop called");
    
    if (!m_agenticBridge) {
        return;
    }
    
    if (m_agenticBridge->IsAgentLoopRunning()) {
        m_agenticBridge->StopAgentLoop();
        appendToOutput(" Agent loop stopped\n", "Output", OutputSeverity::Warning);
        MessageBoxA(m_hwndMain, "Agent loop stopped", "Agent", MB_OK | MB_ICONINFORMATION);
    } else {
        MessageBoxA(m_hwndMain, "No agent loop is currently running", "Agent", MB_OK | MB_ICONINFORMATION);
    }
}

// ============================================================================
// Deep2 Inference Bridge Implementation
// ============================================================================

// Initialize the Deep2 Bridge
void Win32IDE::initializeDeep2Bridge() {
    LOG_INFO("Initializing Deep2 Bridge");
    
    if (!m_deep2Bridge) {
        m_deep2Bridge = new Deep2Bridge(this);
        
        // Connect ESP bus
        m_deep2Bridge->SetESPBus(&m_espBus, m_espRequestId++);
        
        // Set output callback to send responses to output panel and Copilot Chat
        m_deep2Bridge->SetOutputCallback([this](const std::string& title, const std::string& content) {
            appendToOutput(title + ":\n" + content + "\n", "Output", OutputSeverity::Info);
            
            // Also send to Copilot Chat if available
            if (m_hwndCopilotChatOutput) {
                std::string formatted = " " + title + "\n" + content + "\n\n";
                appendCopilotChatUtf8(formatted);
            }
        });
        
        // Prefer an explicitly configured or already selected model.  Never
        // bind the IDE to a developer-specific checkout path during startup.
        std::string defaultModel;
        if (const char* configuredModel = std::getenv("RAWRXD_DEFAULT_DEEP2_MODEL")) {
            if (*configuredModel) defaultModel = configuredModel;
        }
        if (defaultModel.empty() && !m_loadedModelPath.empty()) {
            defaultModel = m_loadedModelPath;
        }

        if (!defaultModel.empty() &&
            GetFileAttributesA(defaultModel.c_str()) != INVALID_FILE_ATTRIBUTES &&
            m_deep2Bridge->Initialize(defaultModel)) {
            LOG_INFO("Deep2 Bridge initialized successfully with model: " + defaultModel);
            appendToOutput(" Deep2 Engine initialized: " + defaultModel + "\n", "Output", OutputSeverity::Info);
        } else {
            LOG_WARNING("Deep2 Bridge initialized without model (model can be loaded later)");
            appendToOutput(" Deep2 Engine initialized (no model loaded)\n", "Output", OutputSeverity::Warning);
        }
    }
}

// Load a model into Deep2
void Win32IDE::onDeep2LoadModel() {
    LOG_INFO("onDeep2LoadModel called");
    
    if (!m_deep2Bridge) {
        initializeDeep2Bridge();
    }
    
    if (!m_deep2Bridge) {
        MessageBoxA(m_hwndMain, "Deep2 Bridge not initialized", "Deep2 Error", MB_OK | MB_ICONERROR);
        return;
    }
    
    // File dialog for GGUF model
    char modelPath[MAX_PATH] = {};
    OPENFILENAMEA dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = m_hwndMain;
    dialog.lpstrFile = modelPath;
    dialog.nMaxFile = MAX_PATH;
    dialog.lpstrFilter = "GGUF Models (*.gguf)\0*.gguf\0All Files\0*.*\0";
    dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    dialog.lpstrTitle = "Select GGUF Model for Deep2";
    
    if (GetOpenFileNameA(&dialog)) {
        appendToOutput(" Loading model: " + std::string(modelPath) + "\n", "Output", OutputSeverity::Info);
        
        // Run in background thread
        std::thread([this, modelPath]() {
            if (m_deep2Bridge->LoadModel(modelPath)) {
                std::string info = m_deep2Bridge->GetModelInfo();
                appendToOutput(" Model loaded successfully:\n" + info + "\n", "Output", OutputSeverity::Info);
            } else {
                appendToOutput(" Failed to load model: " + std::string(modelPath) + "\n", "Errors", OutputSeverity::Error);
            }
        }).detach();
    }
}

// Generate text using Deep2
void Win32IDE::onDeep2Generate() {
    LOG_INFO("onDeep2Generate called");
    
    if (!m_deep2Bridge) {
        initializeDeep2Bridge();
    }
    
    if (!m_deep2Bridge || !m_deep2Bridge->IsInitialized()) {
        MessageBoxA(m_hwndMain, "Deep2 Bridge not initialized", "Deep2 Error", MB_OK | MB_ICONERROR);
        return;
    }
    
    if (!m_deep2Bridge->IsModelLoaded()) {
        MessageBoxA(m_hwndMain, "No model loaded. Use Deep2 > Load Model first.", "Deep2 Error", MB_OK | MB_ICONERROR);
        return;
    }
    
    // Get prompt from Copilot Chat input
    if (m_hwndCopilotChatInput) {
        const std::string prompt = getWindowTextUtf8(m_hwndCopilotChatInput);

        if (prompt.empty()) {
            MessageBoxA(m_hwndMain, "Enter a prompt in the Copilot Chat input box", "Deep2", MB_OK | MB_ICONINFORMATION);
            return;
        }
        appendToOutput(" Generating with Deep2: " + prompt + "\n", "Output", OutputSeverity::Info);
        
        // Clear input
        SetWindowTextW(m_hwndCopilotChatInput, L"");
        
        // Stream generation in background
        std::thread([this, prompt]() {
            m_deep2Bridge->GenerateStream(prompt,
                [this](const std::string& token, bool isComplete) {
                    // This callback runs on the generation thread
                    // Post to UI thread for safe UI updates
                    if (!token.empty()) {
                        PostMessageA(m_hwndMain, WM_APP + 101, 0, (LPARAM)new std::string(token));
                    }
                    if (isComplete) {
                        PostMessageA(m_hwndMain, WM_APP + 102, 0, 0);
                    }
                    return true; // Continue generation
                },
                2048,  // max tokens
                0.7f,  // temperature
                0.9f,  // topP
                40     // topK
            );
        }).detach();
    } else {
        MessageBoxA(m_hwndMain, "Copilot Chat input not available", "Deep2 Error", MB_OK | MB_ICONERROR);
    }
}

// Cancel Deep2 generation
void Win32IDE::onDeep2Cancel() {
    LOG_INFO("onDeep2Cancel called");
    
    if (!m_deep2Bridge) {
        return;
    }
    
    m_deep2Bridge->Cancel();
    appendToOutput(" Generation cancelled\n", "Output", OutputSeverity::Warning);
    MessageBoxA(m_hwndMain, "Generation cancelled", "Deep2", MB_OK | MB_ICONINFORMATION);
}

// Show model info
void Win32IDE::onDeep2ModelInfo() {
    LOG_INFO("onDeep2ModelInfo called");
    
    if (!m_deep2Bridge) {
        initializeDeep2Bridge();
    }
    
    if (!m_deep2Bridge) {
        MessageBoxA(m_hwndMain, "Deep2 Bridge not initialized", "Deep2 Error", MB_OK | MB_ICONERROR);
        return;
    }
    
    std::string info = m_deep2Bridge->GetModelInfo();
    appendToOutput(" Deep2 Model Info:\n" + info + "\n", "Output", OutputSeverity::Info);
    MessageBoxA(m_hwndMain, info.c_str(), "Deep2 Model Info", MB_OK | MB_ICONINFORMATION);
}

// Configure Deep2 generation parameters
void Win32IDE::onDeep2Configure() {
    LOG_INFO("onDeep2Configure called");
    
    if (!m_deep2Bridge) {
        initializeDeep2Bridge();
    }
    
    if (!m_deep2Bridge) {
        MessageBoxA(m_hwndMain, "Deep2 Bridge not initialized", "Deep2 Error", MB_OK | MB_ICONERROR);
        return;
    }
    
    // Create configuration dialog
    RECT parentRect{};
    GetWindowRect(m_hwndMain, &parentRect);
    
    const int dlgWidth = 350;
    const int dlgHeight = 280;
    const int dlgX = parentRect.left + ((parentRect.right - parentRect.left) - dlgWidth) / 2;
    const int dlgY = parentRect.top + ((parentRect.bottom - parentRect.top) - dlgHeight) / 2;
    
    EnableWindow(m_hwndMain, FALSE);
    
    HWND hwndDlg = CreateWindowExA(WS_EX_DLGMODALFRAME, "STATIC", "Deep2 Generation Config",
        WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
        dlgX, dlgY, dlgWidth, dlgHeight, m_hwndMain, nullptr, m_hInstance, nullptr);
    
    if (!hwndDlg) {
        EnableWindow(m_hwndMain, TRUE);
        MessageBoxA(m_hwndMain, "Failed to create config dialog", "Deep2", MB_OK | MB_ICONERROR);
        return;
    }
    
    // Max Tokens
    CreateWindowExA(0, "STATIC", "Max Tokens:", WS_CHILD | WS_VISIBLE,
        10, 15, 100, 20, hwndDlg, nullptr, m_hInstance, nullptr);
    HWND hwndMaxTokens = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "2048",
        WS_CHILD | WS_VISIBLE | ES_NUMBER,
        120, 15, 80, 22, hwndDlg, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(1001)), m_hInstance, nullptr);
    
    // Temperature
    CreateWindowExA(0, "STATIC", "Temperature:", WS_CHILD | WS_VISIBLE,
        10, 50, 100, 20, hwndDlg, nullptr, m_hInstance, nullptr);
    HWND hwndTemp = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "0.7",
        WS_CHILD | WS_VISIBLE,
        120, 50, 80, 22, hwndDlg, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(1002)), m_hInstance, nullptr);
    
    // Top-P
    CreateWindowExA(0, "STATIC", "Top-P:", WS_CHILD | WS_VISIBLE,
        10, 85, 100, 20, hwndDlg, nullptr, m_hInstance, nullptr);
    HWND hwndTopP = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "0.9",
        WS_CHILD | WS_VISIBLE,
        120, 85, 80, 22, hwndDlg, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(1003)), m_hInstance, nullptr);
    
    // Top-K
    CreateWindowExA(0, "STATIC", "Top-K:", WS_CHILD | WS_VISIBLE,
        10, 120, 100, 20, hwndDlg, nullptr, m_hInstance, nullptr);
    HWND hwndTopK = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "40",
        WS_CHILD | WS_VISIBLE | ES_NUMBER,
        120, 120, 80, 22, hwndDlg, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(1004)), m_hInstance, nullptr);
    
    HWND hwndOk = CreateWindowExA(0, "BUTTON", "Apply", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
        dlgWidth - 200, dlgHeight - 50, 90, 30, hwndDlg, (HMENU)IDOK, m_hInstance, nullptr);
    HWND hwndCancel = CreateWindowExA(0, "BUTTON", "Cancel", WS_CHILD | WS_VISIBLE,
        dlgWidth - 100, dlgHeight - 50, 80, 30, hwndDlg, (HMENU)IDCANCEL, m_hInstance, nullptr);
    
    bool accepted = false;
    int maxTokens = 2048;
    float temperature = 0.7f;
    float topP = 0.9f;
    int topK = 40;
    
    MSG msg{};
    while (IsWindow(hwndDlg) && GetMessage(&msg, nullptr, 0, 0)) {
        if (msg.message == WM_COMMAND) {
            const WORD cmdId = LOWORD(msg.wParam);
            const WORD cmdCode = HIWORD(msg.wParam);
            
            if (cmdId == IDOK && cmdCode == BN_CLICKED) {
                char buf[64] = {0};
                GetWindowTextA(hwndMaxTokens, buf, sizeof(buf));
                maxTokens = std::atoi(buf);
                GetWindowTextA(hwndTemp, buf, sizeof(buf));
                temperature = (float)std::atof(buf);
                GetWindowTextA(hwndTopP, buf, sizeof(buf));
                topP = (float)std::atof(buf);
                GetWindowTextA(hwndTopK, buf, sizeof(buf));
                topK = std::atoi(buf);
                accepted = true;
                DestroyWindow(hwndDlg);
                break;
            } else if (cmdId == IDCANCEL && cmdCode == BN_CLICKED) {
                DestroyWindow(hwndDlg);
                break;
            }
        }
        
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    EnableWindow(m_hwndMain, TRUE);
    SetForegroundWindow(m_hwndMain);
    
    if (accepted) {
        m_deep2Bridge->SetGenerationConfig(maxTokens, temperature, topP, topK);
        appendToOutput(" Deep2 config updated: maxTokens=" + std::to_string(maxTokens) + 
                       ", temp=" + std::to_string(temperature) + 
                       ", topP=" + std::to_string(topP) + 
                       ", topK=" + std::to_string(topK) + "\n", "Output", OutputSeverity::Info);
        MessageBoxA(m_hwndMain, "Deep2 configuration updated", "Deep2", MB_OK | MB_ICONINFORMATION);
    }
}

// ============================================================================
// Agentic Loop Bridge Implementation
// ============================================================================

// Initialize the Agentic Loop Bridge
void Win32IDE::initializeAgenticLoopBridge() {
    LOG_INFO("Initializing Agentic Loop Bridge");
    
    if (!m_agenticLoopBridge) {
        m_agenticLoopBridge = std::make_unique<AgenticLoopBridge>(this);
        
        // Connect ESP bus
        m_agenticLoopBridge->SetESPBus(&m_espBus, m_espRequestId++);
        
        LOG_INFO("Agentic Loop Bridge initialized");
        appendToOutput(" Agentic Loop Bridge initialized\n", "Output", OutputSeverity::Info);
    }
}

// Run an autonomous task via the agentic loop
void Win32IDE::onAgenticLoopRunTask() {
    LOG_INFO("onAgenticLoopRunTask called");
    
    if (!m_agenticLoopBridge) {
        initializeAgenticLoopBridge();
    }
    
    if (!m_agenticLoopBridge) {
        MessageBoxA(m_hwndMain, "Agentic Loop Bridge not initialized", "Agentic Loop", MB_OK | MB_ICONERROR);
        return;
    }
    
    if (m_agenticLoopBridge->IsRunning()) {
        MessageBoxA(m_hwndMain, "A task is already running. Cancel it first.", "Agentic Loop", MB_OK | MB_ICONINFORMATION);
        return;
    }
    
    // Get task from Copilot Chat input
    if (m_hwndCopilotChatInput) {
        const std::string task = getWindowTextUtf8(m_hwndCopilotChatInput);

        if (task.empty()) {
            MessageBoxA(m_hwndMain, "Enter a task description in the Copilot Chat input box", "Agentic Loop", MB_OK | MB_ICONINFORMATION);
            return;
        }

        SetWindowTextW(m_hwndCopilotChatInput, L"");
        
        // Route the selected model explicitly. Ollama entries contain a
        // model ID (for example qwen3:8b), while local entries contain a GGUF
        // path. Never apply filesystem validation to an Ollama ID.
        const bool useOllama =
            m_selectedChatModel.source == ChatModelEntry::Source::Ollama;
        const bool useLocalFile =
            m_selectedChatModel.source == ChatModelEntry::Source::LocalFile;
        std::string modelPath;
        if (useOllama || useLocalFile) {
            // The selector is authoritative for both Ollama IDs and GGUF
            // paths.  Falling back to the previously loaded Deep2 model for
            // a newly selected local entry silently ran the wrong model.
            modelPath = m_selectedChatModel.identifier;
        } else {
            if (m_deep2Bridge && m_deep2Bridge->IsModelLoaded()) {
                modelPath = m_deep2Bridge->GetCurrentModel();
            }
            if (modelPath.empty() && !m_loadedModelPath.empty()) {
                modelPath = m_loadedModelPath;
            }
            if (modelPath.empty()) {
                if (const char* configuredModel = std::getenv("RAWRXD_DEFAULT_DEEP2_MODEL")) {
                    if (*configuredModel) modelPath = configuredModel;
                }
            }
        }
        if (modelPath.empty() ||
            (useLocalFile && GetFileAttributesA(modelPath.c_str()) == INVALID_FILE_ATTRIBUTES)) {
            appendToOutput("Agent task rejected: select or configure a valid local model first.\n",
                           "Errors", OutputSeverity::Error);
            return;
        }

        if (m_selectedChatModel.source == ChatModelEntry::Source::KiloFree) {
            appendToOutput("Agent task rejected: KiloFree is a chat-only route; select an Ollama or local GGUF model for tools.\n",
                           "Errors", OutputSeverity::Error);
            return;
        }
        
        // Resolve the agent workspace from the active explorer/file context
        // first, then from the executable's checkout marker.  A GUI launched
        // from a shell/desktop can have a process CWD inside the host app
        // (for example WindowsApps), which is not a valid RawrXD workspace
        // and prevents MOTD authorization from finding .cursor/rules.
        std::string workDirStr;
        auto directoryForPath = [](const std::string& path) -> std::string {
            if (path.empty()) return {};
            const DWORD attributes = GetFileAttributesA(path.c_str());
            if (attributes != INVALID_FILE_ATTRIBUTES &&
                (attributes & FILE_ATTRIBUTE_DIRECTORY)) {
                return path;
            }
            const size_t slash = path.find_last_of("\\/");
            return slash == std::string::npos ? std::string{} : path.substr(0, slash);
        };
        auto findWorkspaceRoot = [](const std::string& path) -> std::string {
            if (path.empty()) return {};
            std::error_code ec;
            std::filesystem::path probe(path);
            if (!std::filesystem::is_directory(probe, ec)) probe = probe.parent_path();
            for (int depth = 0; !probe.empty() && depth < 12; ++depth) {
                ec.clear();
                const bool gitRoot = std::filesystem::exists(probe / ".git", ec);
                ec.clear();
                const bool policyRoot = std::filesystem::is_regular_file(
                    probe / ".cursor" / "rules" / "PassiveRoleNotRoleplay.mdc", ec) ||
                    std::filesystem::is_regular_file(
                        probe / ".cursor" / "rules" / "PassiveRoleNotRoleplay.md", ec);
                if (gitRoot || policyRoot) return probe.string();
                const auto parent = probe.parent_path();
                if (parent == probe) break;
                probe = parent;
            }
            return {};
        };
        workDirStr = findWorkspaceRoot(m_currentExplorerPath);
        if (workDirStr.empty()) workDirStr = findWorkspaceRoot(m_currentFile);

        if (workDirStr.empty()) {
            char modulePath[MAX_PATH] = {};
            const DWORD moduleLength = GetModuleFileNameA(nullptr, modulePath, MAX_PATH);
            if (moduleLength > 0 && moduleLength < MAX_PATH) {
                std::error_code ec;
                std::filesystem::path probe(std::string(modulePath, moduleLength));
                probe = probe.parent_path();
                for (int depth = 0; !probe.empty() && depth < 10; ++depth) {
                    const auto gitMarker = probe / ".git";
                    const auto motdMarker = probe / ".cursor" / "rules" /
                        "PassiveRoleNotRoleplay.mdc";
                    const auto motdMarkdown = probe / ".cursor" / "rules" /
                        "PassiveRoleNotRoleplay.md";
                    if (std::filesystem::exists(gitMarker, ec) ||
                        std::filesystem::is_regular_file(motdMarker, ec) ||
                        std::filesystem::is_regular_file(motdMarkdown, ec)) {
                        workDirStr = probe.string();
                        break;
                    }
                    ec.clear();
                    const auto parent = probe.parent_path();
                    if (parent == probe) break;
                    probe = parent;
                }
            }
        }

        if (workDirStr.empty()) {
            char workDir[MAX_PATH] = {};
            if (GetCurrentDirectoryA(MAX_PATH, workDir) > 0) workDirStr.assign(workDir);
        }
        
        // Build task config
        AgenticLoopBridge::TaskConfig config;
        config.provider = useOllama ? "ollama-cli" : "local";
        config.modelPath = modelPath;
        config.workDir = workDirStr;
        config.task = task;
        config.maxSteps = 8;
        config.maxNewTokens = 512;
        config.maxRetries = 2;
        config.maxWallTimeSec = 300;
        config.maxTotalTokens = 8192;
        config.quiet = true;
        // Ollama chat tasks use the same canonical `rawr run` path as the
        // CLI smoke-tested backend.  Keep GUI chat read-only by default; an
        // explicit environment opt-in is required before this UI route can
        // authorize mutations.
        config.useCliAgent = useOllama;
        const char* approveGuiMutations = std::getenv("RAWRXD_GUI_APPROVE_MUTATIONS");
        config.approveMutations = approveGuiMutations &&
            std::string(approveGuiMutations) == "YES";
        config.readOnly = !config.approveMutations;

        if (auto* session = activeChatSession()) {
            m_agenticChatSessionId = session->id;
        }
        
        // Also check if there's an open file to use as target
        if (!m_currentFile.empty()) {
            config.targetFile = m_currentFile;
        }
        
        appendToOutput(" Starting agentic task: " + task + "\n", "Output", OutputSeverity::Info);
        appendToOutput(" Provider: " + config.provider + "\n", "Output", OutputSeverity::Info);
        appendToOutput(" Model: " + modelPath + "\n", "Output", OutputSeverity::Info);
        appendToOutput(" Work dir: " + workDirStr + "\n", "Output", OutputSeverity::Info);
        
        // Start the task
        const bool started = m_agenticLoopBridge->StartTask(config,
            [this](const std::string& progressMsg) {
                // Progress callback - runs on worker thread, post to UI
                PostMessageA(m_hwndMain, WM_APP + 103, 0, (LPARAM)new std::string(progressMsg));
            },
            [this](const AgenticLoopBridge::ToolResult& toolResult) {
                // Tool callback - runs on worker thread, post to UI
                PostMessageA(m_hwndMain, WM_APP + 104, 0, (LPARAM)new AgenticLoopBridge::ToolResult(toolResult));
            },
            [this](bool success, const std::string& summary) {
                // Complete callback - runs on worker thread, post to UI
                PostMessageA(m_hwndMain, WM_APP + 105, success ? 1 : 0, (LPARAM)new std::string(summary));
            }
        );
        if (!started) {
            m_agenticChatSessionId = 0;
            appendToOutput("Agent task could not be started.\n", "Errors", OutputSeverity::Error);
        }
    } else {
        MessageBoxA(m_hwndMain, "Copilot Chat input not available", "Agentic Loop", MB_OK | MB_ICONERROR);
    }
}

// Cancel running agentic task
void Win32IDE::onAgenticLoopCancel() {
    LOG_INFO("onAgenticLoopCancel called");
    
    if (!m_agenticLoopBridge) {
        return;
    }
    
    if (m_agenticLoopBridge->IsRunning()) {
        m_agenticLoopBridge->Cancel();
        appendToOutput(" Agentic task cancelled\n", "Output", OutputSeverity::Warning);
        MessageBoxA(m_hwndMain, "Agentic task cancelled", "Agentic Loop", MB_OK | MB_ICONINFORMATION);
    } else {
        MessageBoxA(m_hwndMain, "No task is currently running", "Agentic Loop", MB_OK | MB_ICONINFORMATION);
    }
}

// Show agentic loop status
void Win32IDE::onAgenticLoopStatus() {
    LOG_INFO("onAgenticLoopStatus called");
    
    if (!m_agenticLoopBridge) {
        initializeAgenticLoopBridge();
    }
    
    if (!m_agenticLoopBridge) {
        MessageBoxA(m_hwndMain, "Agentic Loop Bridge not initialized", "Agentic Loop", MB_OK | MB_ICONERROR);
        return;
    }
    
    std::string status = m_agenticLoopBridge->GetStatus();
    appendToOutput(" Agentic Loop Status: " + status + "\n", "Output", OutputSeverity::Info);
    MessageBoxA(m_hwndMain, status.c_str(), "Agentic Loop Status", MB_OK | MB_ICONINFORMATION);
}

// Handle agentic loop progress message (WM_APP + 103)
LRESULT Win32IDE::handleAgenticLoopProgress(WPARAM wParam, LPARAM lParam) {
    if (lParam) {
        std::string* msg = reinterpret_cast<std::string*>(lParam);
        const std::string visible = FilterStructuredEspLines(*msg);
        if (!visible.empty()) {
            appendToOutput(visible, "Output", OutputSeverity::Info);
        }
        if (m_agenticChatSessionId != 0 && !visible.empty()) {
            handleCopilotUiUpdate(m_agenticChatSessionId,
                                  "\r\n[agent] " + visible + "\r\n", false);
        }
        delete msg;
    }
    return 0;
}

// Handle agentic loop tool result (WM_APP + 104)
LRESULT Win32IDE::handleAgenticLoopToolResult(WPARAM wParam, LPARAM lParam) {
    if (lParam) {
        AgenticLoopBridge::ToolResult* result = reinterpret_cast<AgenticLoopBridge::ToolResult*>(lParam);
        
        std::string output = " TOOL: " + result->toolName + " " + result->target + 
                            " [exit=" + std::to_string(result->exitCode) + "]";
        if (!result->output.empty()) {
            output += "\n" + result->output;
        }
        output += "\n";
        
        appendToOutput(output, "Output", result->success ? OutputSeverity::Info : OutputSeverity::Error);
        if (m_agenticChatSessionId != 0) {
            handleCopilotUiUpdate(m_agenticChatSessionId,
                                  "\r\n[tool] " + output, false);
        }
        
        // Also send to ESP panel
        if (m_hwndESPList) {
            // ESP events already published via bridge
        }
        
        delete result;
    }
    return 0;
}

// Handle agentic loop completion (WM_APP + 105)
LRESULT Win32IDE::handleAgenticLoopComplete(WPARAM wParam, LPARAM lParam) {
    bool success = (wParam != 0);
    if (lParam) {
        std::string* summary = reinterpret_cast<std::string*>(lParam);
        
        std::string output = "\n=== TASK " + std::string(success ? "COMPLETED" : "FAILED") + " ===\n";
        output += *summary + "\n";
        
        appendToOutput(output, "Output", success ? OutputSeverity::Info : OutputSeverity::Error);
        if (m_agenticChatSessionId != 0) {
            const int sessionId = m_agenticChatSessionId;
            handleCopilotUiUpdate(sessionId, *summary + "\r\n", true);
            m_agenticChatSessionId = 0;
        }
        
        delete summary;
    }
    return 0;
}
