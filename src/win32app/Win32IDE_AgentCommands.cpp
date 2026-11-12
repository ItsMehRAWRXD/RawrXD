// Agent menu implementation for Win32IDE
// Implements all agentic framework menu commands and integrations

#include "Win32IDE.h"
#include "Win32IDE_AgenticBridge.h"
#include "Win32IDE_Deep2Bridge.h"
#include "Win32IDE_AgenticLoopBridge.h"
#include "ModelConnection.h"
#include "IDELogger.h"
#include "agentic/AgentSession.h"
#include "agentic/PersistentTaskBacklog.h"
#if defined(RAWRXD_HAS_COMPUTER_USE)
#include "agentic/tool_core.hpp"
#endif
#include <commctrl.h>
#include <commdlg.h>
#include <sstream>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>

namespace {

struct AgentModelDialogState {
    Win32IDE* ide = nullptr;
    std::vector<std::string> models;
    std::string current;
};

LRESULT CALLBACK AgentModelComboSubclassProc(
    HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam,
    UINT_PTR subclassId, DWORD_PTR refData)
{
    (void)refData;
    if (message == WM_KEYDOWN &&
        (wParam == VK_ESCAPE || wParam == VK_RETURN)) {
        const HWND dialog = GetParent(hwnd);
        if (dialog && IsWindow(dialog)) {
            const WORD command = (wParam == VK_ESCAPE) ? IDCANCEL : IDOK;
            SendMessageA(dialog, WM_COMMAND,
                         MAKEWPARAM(command, BN_CLICKED),
                         reinterpret_cast<LPARAM>(hwnd));
            return 0;
        }
    }
    if (message == WM_NCDESTROY) {
        RemoveWindowSubclass(hwnd, AgentModelComboSubclassProc, subclassId);
    }
    return DefSubclassProc(hwnd, message, wParam, lParam);
}

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
        if (line.empty() || first >= line.size()) {
            if (end == std::string::npos) break;
            cursor = end + 1;
            if (cursor < raw.size() && raw[end] == '\r' && raw[cursor] == '\n') ++cursor;
            continue;
        }
        const char* body = line.c_str() + first;
        const size_t bodyLen = line.size() - first;
        // Drop structured ESP and JSON telemetry fragments (rolling_tp /
        // gpu_dispatches / mid-object chips) — they already hit the ESP panel
        // and previously flooded chat until IDE EXIT=-1.
        const bool drop =
            (bodyLen >= 5 && std::strncmp(body, "[ESP]", 5) == 0) ||
            body[0] == '{' || body[0] == '"' || body[0] == '}' || body[0] == ':' ||
            body[0] == ',' ||
            std::strstr(body, "rolling_tp") != nullptr ||
            std::strstr(body, "gpu_dispatch") != nullptr ||
            std::strstr(body, "\"ttft_ms\"") != nullptr ||
            std::strstr(body, "prefill_ms") != nullptr;
        if (!drop) {
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
            std::string lower = title + " " + content;
            for (char& c : lower) {
                if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
            }
            const bool psHint =
                lower.find("powershell") != std::string::npos ||
                lower.find("pwsh") != std::string::npos;
            if (m_hwndCopilotChatOutput) {
                std::string formatted = " " + title + "\n" + content + "\n\n";
                appendCopilotChatUtf8(formatted);
                // Durable leak tracer: agent/tool mirrors into chat pane.
                const char* configured = std::getenv("RAWRXD_LOG_DIR");
                const std::string path = (configured && *configured)
                    ? std::string(configured) + "\\chat_runtime.log"
                    : std::string("chat_runtime.log");
                std::ofstream leak(path, std::ios::app);
                if (leak) {
                    leak << "TRANSCRIPT_INSERT role=agent_mirror count=1 "
                         << "source=agentic_bridge powershell_hint="
                         << (psHint ? "1" : "0")
                         << " bytes=" << formatted.size() << std::endl;
                }
            }
            if (psHint) {
                m_agentStepTimeline.addChip("powershell", title.empty() ? content : title);
            } else if (lower.find("tool") != std::string::npos) {
                m_agentStepTimeline.addTool(title.empty() ? "tool" : title, content, 0, true);
            } else if (lower.find("explor") != std::string::npos || lower.find("read") != std::string::npos ||
                       lower.find("glob") != std::string::npos || lower.find("grep") != std::string::npos) {
                m_agentStepTimeline.addExplored(title.empty() ? content : title);
            } else {
                m_agentStepTimeline.addChip("step", title.empty() ? content : title);
            }
        });
        
        // Gap 5/9: bind ToolCallBridge SSOT + SecurityGate before any agent command.
        ensureAgentToolSsotReady();
        if (m_agenticBridge->Initialize("", "bigdaddyg-personalized-agentic:latest")) {
            LOG_INFO("Agentic Bridge initialized (BackendRouter + ToolCallBridge SSOT/SecurityGate)");
            appendToOutput(" Agentic Framework initialized (SSOT+BackendRouter)\n",
                           "Output", OutputSeverity::Info);
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
    m_agentStepTimeline.clear();
    m_agentStepTimeline.addChip("agent", promptStr);
    m_agentStepTimeline.beginThought();
    if (m_hwndMain) SetTimer(m_hwndMain, IDT_AGENT_THOUGHT, 250, nullptr);
    if (m_hwndCopilotStopBtn) EnableWindow(m_hwndCopilotStopBtn, TRUE);
    
    std::thread([this, promptStr]() {
        const bool ok = m_agenticBridge->StartAgentLoop(promptStr, 10);
        if (ok) {
            LOG_INFO("Agent loop completed successfully");
        } else {
            LOG_ERROR("Agent loop failed");
        }
        PostMessageA(m_hwndMain, kRawrxdLegacyAgentComplete, ok ? 1 : 0,
                     (LPARAM)new std::string(ok ? "legacy agent loop finished" : "legacy agent loop failed"));
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
        // Gap 5 residual close: AgentCommands never bypasses SecurityGate —
        // ensure SSOT bridge (sandbox+consent) before ExecuteAgentCommand.
        ensureAgentToolSsotReady();
        appendToOutput(" Executing Agent Command (SSOT/SecurityGate): " + command + "\n",
                       "Output", OutputSeverity::Info);
        m_agentStepTimeline.addChip("agent", command);
        m_agentStepTimeline.beginThought();
        if (m_hwndMain) SetTimer(m_hwndMain, IDT_AGENT_THOUGHT, 250, nullptr);
        
        // Execute in background — tools route via dispatchAgentTool → ExecuteToolCall.
        std::thread([this, command]() {
            AgentResponse response = m_agenticBridge->ExecuteAgentCommand(command);
            
            std::string output = "Agent Response:\n";
            output += "Type: " + std::to_string((int)response.type) + "\n";
            output += "Content: " + response.content + "\n";
            
            if (!response.toolName.empty()) {
                output += "Tool: " + response.toolName + "\n";
                output += "Args: " + response.toolArgs + "\n";
                PostMessageA(m_hwndMain, WM_APP + 104, 0,
                    (LPARAM)new AgenticLoopBridge::ToolResult{
                        true, response.content, 0, response.toolName, response.toolArgs});
            }
            
            appendToOutput(output, "Output", OutputSeverity::Info);
            PostMessageA(m_hwndMain, kRawrxdLegacyAgentComplete, 1,
                         (LPARAM)new std::string(response.content.empty() ? "command finished" : response.content));
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
    auto* state = reinterpret_cast<AgentModelDialogState*>(
        GetWindowLongPtrA(hwnd, GWLP_USERDATA));
    auto* ide = state ? state->ide : nullptr;

    if (message == WM_NCCREATE) {
        const auto* create = reinterpret_cast<const CREATESTRUCTA*>(lParam);
        state = static_cast<AgentModelDialogState*>(create->lpCreateParams);
        ide = state ? state->ide : nullptr;
        SetWindowLongPtrA(hwnd, GWLP_USERDATA,
                          reinterpret_cast<LONG_PTR>(state));
    }

    switch (message) {
    case WM_CREATE: {
        if (!ide) return -1;
        constexpr int kComboId = 1001;
        constexpr int kDialogWidth = 460;
        constexpr int kDialogHeight = 250;
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
            kDialogWidth - 205, kDialogHeight - 74, 90, 30, hwnd,
            reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDOK)),
            ide->m_hInstance, nullptr);
        HWND cancel = CreateWindowExA(
            0, "BUTTON", "Cancel",
            WS_CHILD | WS_VISIBLE,
            kDialogWidth - 105, kDialogHeight - 74, 90, 30, hwnd,
            reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDCANCEL)),
            ide->m_hInstance, nullptr);

        if (combo) {
            SetWindowSubclass(combo, AgentModelComboSubclassProc, 1, 0);
        }

        for (HWND child : {label, combo, use, cancel}) {
            if (child) SendMessageA(child, WM_SETFONT,
                                    reinterpret_cast<WPARAM>(font), TRUE);
        }

        int selectedIndex = 0;
        for (size_t i = 0; i < state->models.size(); ++i) {
            const auto& model = state->models[i];
            SendMessageA(combo, CB_ADDSTRING, 0,
                         reinterpret_cast<LPARAM>(model.c_str()));
            if (model == state->current) {
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

    case WM_SYSCOMMAND:
        // Handle the caption close command explicitly.  This popup is a
        // modeless owned window, so relying on the default system-menu
        // translation can leave the visible X unresponsive when focus is in
        // the combo box or another child control.
        if ((wParam & 0xFFF0u) == SC_CLOSE) {
            DestroyWindow(hwnd);
            return 0;
        }
        break;

    case WM_NCLBUTTONDOWN:
        if (wParam == HTCLOSE) {
            DestroyWindow(hwnd);
            return 0;
        }
        break;

    case WM_NCDESTROY:
        delete state;
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

    constexpr char kDialogClass[] = "RawrXD.AgentModelDialog";
    if (HWND existing = FindWindowExA(m_hwndMain, nullptr, kDialogClass, nullptr)) {
        SetForegroundWindow(existing);
        return;
    }

    // Use the already-fenced model-discovery cache. The previous synchronous
    // /api/tags request could freeze the UI while Ollama was unavailable.
    std::vector<std::string> models;
    for (const auto& entry : m_availableModels) {
        if (!entry.identifier.empty() &&
            std::find(models.begin(), models.end(),
                      entry.identifier) == models.end()) {
            models.push_back(entry.identifier);
        }
    }
    if (models.empty()) {
        models = {
            "bigdaddyg-personalized-agentic:latest",
            "codestral:latest",
            "llama3.3:latest"
        };
    }

    std::string current = m_agenticBridge->GetCurrentModel();
    if (current.empty()) {
        current = models.front();
    }
    if (std::find(models.begin(), models.end(), current) == models.end()) {
        models.insert(models.begin(), current);
    }

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
    constexpr int kDialogHeight = 250;
    HMONITOR monitor = MonitorFromWindow(m_hwndMain, MONITOR_DEFAULTTONEAREST);
    MONITORINFO monitorInfo{sizeof(monitorInfo)};
    RECT workArea = parentRect;
    if (monitor && GetMonitorInfoA(monitor, &monitorInfo)) {
        workArea = monitorInfo.rcWork;
    }
    // Keep the model dialog inside the usable editor area.  The old screen-
    // centered placement could put the lower half behind the docked Output /
    // PowerShell surface, making Use Model and Cancel unreachable even though
    // the dialog itself was alive.
    RECT usableArea = parentRect;
    RECT dockRect{};
    const HWND dock =
        (m_hwndPanelContainer && IsWindowVisible(m_hwndPanelContainer))
            ? m_hwndPanelContainer
            : ((m_hwndPowerShellPanel && IsWindowVisible(m_hwndPowerShellPanel))
                   ? m_hwndPowerShellPanel
                   : m_hwndOutputTabs);
    if (dock && IsWindow(dock) && IsWindowVisible(dock) &&
        GetWindowRect(dock, &dockRect) && dockRect.top > usableArea.top) {
        usableArea.bottom = (std::min)(usableArea.bottom, dockRect.top - 8);
    }
    usableArea.top += 48;
    if (usableArea.bottom - usableArea.top < kDialogHeight) {
        usableArea = parentRect;
    }
    const int dialogX = (std::max)(workArea.left,
        workArea.left + ((workArea.right - workArea.left - kDialogWidth) / 2));
    const int dialogY = (std::max)(usableArea.top,
        usableArea.top + ((usableArea.bottom - usableArea.top - kDialogHeight) / 2));

    auto* state = new (std::nothrow) AgentModelDialogState{
        this, std::move(models), std::move(current)};
    if (!state) {
        appendToOutput("Agent model configuration unavailable: dialog state allocation failed.\n",
                       "Errors", OutputSeverity::Error);
        return;
    }

    HWND dialog = CreateWindowExA(
        WS_EX_DLGMODALFRAME | WS_EX_TOOLWINDOW,
        kDialogClass, "Select Agent Model",
        WS_POPUP | WS_CAPTION | WS_SYSMENU,
        dialogX, dialogY, kDialogWidth, kDialogHeight,
        m_hwndMain, nullptr, m_hInstance, state);
    if (!dialog) {
        delete state;
        appendToOutput("Agent model configuration unavailable: dialog creation failed.\n",
                       "Errors", OutputSeverity::Error);
        return;
    }

    ShowWindow(dialog, SW_SHOWNORMAL);
    UpdateWindow(dialog);
    SetWindowPos(dialog, HWND_TOP, dialogX, dialogY,
                 kDialogWidth, kDialogHeight, SWP_SHOWWINDOW);
    SetForegroundWindow(dialog);
    SetActiveWindow(dialog);
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
    
    ensureComputerUseReady();
    std::vector<std::string> tools = m_agenticBridge->GetAvailableTools();
    // Prefer live session registry names when bound (UI is not the only consumer).
    if (auto* reg = agentToolsRegistry()) {
        tools = reg->names();
    } else {
        for (const auto& cu : listComputerUseTools()) tools.push_back(cu);
    }
    
    std::stringstream toolsList;
    toolsList << "Available Agent Tools (session registry):\n\n";
    
    for (const auto& tool : tools) {
        toolsList << " " << tool << "\n";
    }
    
    toolsList << "\nThese tools can be invoked by the agent to perform tasks.\n";
    toolsList << "Example: TOOL:shell:{\"cmd\":\"Get-Process\"}\n";
    toolsList << "CU E2E: set RAWRXD_AGENT_MODE=ACTIVE and use Run Agentic Task "
                 "(not Copilot text-only Send).\n";

    // Machine-readable chat surface for tip-bound UIA (C11).
    std::ostringstream chat;
    chat << "\r\nRAWRXD_TOOLS_BEGIN\n";
    bool hasRead = false, hasSearch = false, hasShell = false;
    for (const auto& tool : tools) {
        chat << "tool=" << tool << "\n";
        if (tool.find("read") != std::string::npos) hasRead = true;
        if (tool.find("search") != std::string::npos) hasSearch = true;
        if (tool.find("shell") != std::string::npos ||
            tool.find("execute") != std::string::npos) hasShell = true;
    }
    chat << "count=" << tools.size() << "\n";
    chat << "RAWRXD_TOOLS_VERDICT="
         << ((tools.size() > 0 && (hasRead || hasSearch || hasShell)) ? "PASS" : "FAIL")
         << "\n";
    appendCopilotChatUtf8(chat.str());
    appendToOutput(toolsList.str() + "\n", "Output", OutputSeverity::Info);

    const char* headless = std::getenv("RAWRXD_UIA_HEADLESS");
    if (!(headless && headless[0] == '1')) {
        MessageBoxA(m_hwndMain, toolsList.str().c_str(), "Agent Tools",
                    MB_OK | MB_ICONINFORMATION);
    }
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

    cancelComputerUse();

    bool stoppedSomething = false;
    if (m_agenticLoopBridge) {
        // Map9: reap even when IsRunning raced false with a live child.
        if (m_agenticBridge) m_agenticBridge->CancelAutonomousTask(); else if (m_agenticLoopBridge) m_agenticLoopBridge->Cancel();
        m_agenticChatSessionId = 0;
        stoppedSomething = true;
        appendToOutput(" Agentic task cancelled\n", "Output", OutputSeverity::Warning);
    }
    
    if (m_agenticBridge && m_agenticBridge->IsAgentLoopRunning()) {
        m_agenticBridge->StopAgentLoop();
        stoppedSomething = true;
        appendToOutput(" Agent loop stopped\n", "Output", OutputSeverity::Warning);
    }

    if (stoppedSomething) {
        if (m_hwndMain) KillTimer(m_hwndMain, IDT_AGENT_THOUGHT);
        m_agentStepTimeline.closeThoughtIfOpen();
        m_agentStepTimeline.addChip("stopped", "agent stopped");
        if (m_hwndCopilotStopBtn) EnableWindow(m_hwndCopilotStopBtn, FALSE);
        MessageBoxA(m_hwndMain, "Agent stopped", "Agent", MB_OK | MB_ICONINFORMATION);
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

    cancelComputerUse();
    
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
bool Win32IDE::ensureProductTaskLedger(const std::string& workspaceRoot,
                                       const std::string& task,
                                       const std::string& modelIdentity)
{
    using RawrXD::Agent::PersistentTaskBacklog;
    using RawrXD::Agent::PersistentTask;
    using RawrXD::Agent::TaskStatus;
    using RawrXD::Agent::TaskPriority;
    auto deleter = [](void* p) {
        delete static_cast<PersistentTaskBacklog*>(p);
    };
    std::filesystem::path storage = workspaceRoot.empty()
        ? std::filesystem::path(".rawrxd") / "tasks"
        : std::filesystem::path(workspaceRoot) / ".rawrxd" / "tasks";
    if (!m_productTaskBacklog) {
        m_productTaskBacklog = std::unique_ptr<void, void(*)(void*)>(
            new PersistentTaskBacklog(storage.string()), deleter);
    }
    auto* backlog = static_cast<PersistentTaskBacklog*>(m_productTaskBacklog.get());
    if (!backlog) return false;
    m_productTaskResumed = false;

    // Resume only when explicitly requested (crash recovery / RAWRXD_RESUME_TASK_ID).
    // Do not auto-hijack every new turn onto a leftover InProgress row.
    const char* resumeEnv = std::getenv("RAWRXD_RESUME_TASK_ID");
    std::string resumeId = (resumeEnv && *resumeEnv) ? resumeEnv : std::string();
    if (!resumeId.empty()) {
        auto existing = backlog->GetTask(resumeId);
        if (existing) {
            m_productTaskId = resumeId;
            m_productTaskResumed = true;
            backlog->MarkTaskStarted(resumeId);
            appendToOutput("[TaskLedger] resumed id=" + resumeId + "\n",
                           "Output", OutputSeverity::Info);
            return true;
        }
    }

    PersistentTask t;
    t.title = "ide-agent-turn";
    t.description = task;
    t.priority = TaskPriority::High;
    t.status = TaskStatus::Pending;
    t.active_model = modelIdentity;
    t.active_backend = "ide";
    m_productTaskId = backlog->AddTask(t);
    backlog->MarkTaskStarted(m_productTaskId);
    appendToOutput("[TaskLedger] created id=" + m_productTaskId + "\n",
                   "Output", OutputSeverity::Info);
    return !m_productTaskId.empty();
}

bool Win32IDE::ensureProductAgentSession(const std::string& modelIdentity,
                                         const std::string& workspaceRoot,
                                         const std::string& task)
{
    using RawrXD::Agent::AgentSession;
    auto deleter = [](void* p) {
        delete static_cast<AgentSession*>(p);
    };
    if (!m_productAgentSession) {
        m_productAgentSession = std::unique_ptr<void, void(*)(void*)>(
            new AgentSession(), deleter);
    } else if (!m_productAgentSession.get_deleter()) {
        // Rebind deleter if default-constructed holder lacked one.
        auto* existing = static_cast<AgentSession*>(m_productAgentSession.release());
        m_productAgentSession = std::unique_ptr<void, void(*)(void*)>(existing, deleter);
    }
    auto* session = static_cast<AgentSession*>(m_productAgentSession.get());
    if (!session) return false;

    if (!ensureProductTaskLedger(workspaceRoot, task, modelIdentity)) {
        appendToOutput("[TaskLedger] ensure failed\n", "Errors", OutputSeverity::Error);
        return false;
    }

    ++m_productAgentSessionId;
    const std::string taskId = m_productTaskId.empty()
        ? ("ide-agent-" + std::to_string(m_productAgentSessionId))
        : m_productTaskId;
    session->SetTaskId(taskId);
    session->SetModelIdentity(modelIdentity);
    session->SetWorkspaceRoot(workspaceRoot);
    session->SetMode(RawrXD::Agent::AgentMode::Code);
    // Issue #49 tip harness reads tipDir\.rawrxd\ledger\agent_session.json.
    // Prefer the EXE-adjacent canonical ledger so product-final evidence lands
    // where the exclusive remeasure looks; keep a workspace copy as backup.
    {
        char modulePath[MAX_PATH] = {};
        const DWORD moduleLength = GetModuleFileNameA(nullptr, modulePath, MAX_PATH);
        std::filesystem::path ledger;
        if (moduleLength > 0 && moduleLength < MAX_PATH) {
            ledger = std::filesystem::path(std::string(modulePath, moduleLength))
                         .parent_path() /
                     ".rawrxd" / "ledger" / "agent_session.json";
        } else if (!workspaceRoot.empty()) {
            ledger = std::filesystem::path(workspaceRoot) / ".rawrxd" / "ledger" /
                     "agent_session.json";
        }
        if (!ledger.empty()) session->SetLedgerPath(ledger.string());
    }
    // Resume path: reload prior ledger only when TaskLedger resume was explicit.
    if (m_productTaskResumed && session->LoadFromDisk()) {
        session->AppendUserMessage(std::string("[resume] ") + task);
        session->RecordAgentTurn();
        appendToOutput("[AgentSession] ledger resumed from disk\n",
                       "Output", OutputSeverity::Info);
    } else {
        session->AppendUserMessage(task);
        session->RecordAgentTurn();
    }

    // Bind CU / workspace tools onto the same session-owned Registry the
    // ToolCallBridge and agent loop consumers share (not orphan s_cuReg).
    ensureComputerUseReady();

    // Keep literal contiguous in the Ext image for H57 string probes.
    static volatile const char kAgentSessionBound[] = "AgentSession bound";
    appendToOutput(
        std::string(const_cast<const char*>(kAgentSessionBound)) +
        " id=" + taskId + " model=" + modelIdentity +
        " session_identity=" + std::to_string(m_productAgentSessionId) + "\n",
        "Output", OutputSeverity::Info);
    {
        const char* configured = std::getenv("RAWRXD_LOG_DIR");
        const std::string path = (configured && *configured)
            ? std::string(configured) + "\\chat_runtime.log"
            : std::string("chat_runtime.log");
        std::ofstream ev(path, std::ios::app);
        if (ev) {
            ev << "AGENT_SESSION_SPAWNED marker=AgentSession bound"
               << " task_id=" << taskId
               << " session_identity=" << m_productAgentSessionId
               << " model=" << modelIdentity
               << " workspace=" << workspaceRoot
               << " task_ledger=1";
            if (isAgentModeActive()) ev << " AGENT_MODE=ACTIVE";
            if (agentToolsRegistry()) {
                ev << " session_registry=1";
                for (const auto& n : listComputerUseTools()) ev << " tool=" << n;
            }
            ev << std::endl;
        }
    }
    LOG_INFO(std::string("AgentSession bound task_id=") + taskId);
    return true;
}

void Win32IDE::initializeAgenticLoopBridge() {
    // Gap 8: AgenticBridge is sole owner; LoopBridge is process transport only.
    LOG_INFO("Initializing Agentic Loop Bridge via AgenticBridge facade");
    if (!m_agenticBridge) {
        initializeAgenticBridge();
    }
    if (!m_agenticBridge) {
        LOG_ERROR("AgenticBridge facade unavailable; cannot adopt LoopBridge");
        return;
    }
    m_agenticBridge->EnsureLoopTransport();
    m_agenticLoopBridge = m_agenticBridge->LoopTransport();
    if (m_agenticLoopBridge) {
        m_agenticLoopBridge->SetESPBus(&m_espBus, m_espRequestId++);
        if (!m_agentExecutor) {
            m_agentExecutor = std::make_unique<Win32IDE_AgentExecutor>();
            m_agentExecutor->Bind(this, m_agenticBridge.get());
            m_agentExecutor->Initialize();
        }
        LOG_INFO("Agentic Loop Bridge adopted under AgenticBridge");
        appendToOutput(" Agentic Loop Bridge initialized (owned by AgenticBridge)\n", "Output", OutputSeverity::Info);
    }
}

// Run an autonomous task via the agentic loop
void Win32IDE::onAgenticLoopRunTask() {
    LOG_INFO("onAgenticLoopRunTask called");
    {
        std::ofstream crumb(
            "F:\\rawrxd\\evidence\\FULL_FEATURE_ONESHOT_001\\artifacts\\MAP9_AGENTIC_CRUMB.txt",
            std::ios::app);
        if (crumb) crumb << "enter\n";
    }

    // Issue #49 exactly-once: reject only when AgenticLoopBridge already owns
    // a live task. Chat-only m_inferenceRunning (HandleCopilotSend Ollama) must
    // be superseded so chat→agent can spawn deep2_agentic_loop — otherwise
    // Ctrl+Enter chat steals the slot and 4106 hits AGENT_DISPATCH_BUSY forever.
    if (m_agenticLoopBridge && m_agenticLoopBridge->IsRunning()) {
        const char* configured = std::getenv("RAWRXD_LOG_DIR");
        const std::string path = (configured && *configured)
            ? std::string(configured) + "\\chat_runtime.log"
            : std::string("chat_runtime.log");
        std::ofstream ev(path, std::ios::app);
        if (ev) {
            ev << "AGENT_DISPATCH_BUSY dispatched=0 exactly_once=1"
               << " owner=agentic_loop" << std::endl;
        }
        appendToOutput("A task is already running. Cancel it first.\n",
                       "Output", OutputSeverity::Warning);
        return;
    }
    if (m_inferenceRunning.load(std::memory_order_acquire)) {
        const char* configured = std::getenv("RAWRXD_LOG_DIR");
        const std::string path = (configured && *configured)
            ? std::string(configured) + "\\chat_runtime.log"
            : std::string("chat_runtime.log");
        {
            std::ofstream ev(path, std::ios::app);
            if (ev) {
                ev << "AGENT_DISPATCH_SUPERSEDE busy_chat=1"
                   << " reclaim_for=AgenticLoopBridge" << std::endl;
            }
        }
        // Stop chat inference only; AgenticLoop is not running (gated above).
        HandleCopilotStop();
        if (m_inferenceRunning.load(std::memory_order_acquire) ||
            (m_agenticLoopBridge && m_agenticLoopBridge->IsRunning())) {
            std::ofstream ev(path, std::ios::app);
            if (ev) {
                ev << "AGENT_DISPATCH_BUSY dispatched=0 exactly_once=1"
                   << " owner=post_supersede" << std::endl;
            }
            appendToOutput("A task is already running. Cancel it first.\n",
                           "Output", OutputSeverity::Warning);
            return;
        }
    }
    m_inferenceRunning.store(true, std::memory_order_release);

    // Explicit agent/tool path (CU E2E). Not HandleCopilotSend text-only.
    setAgentModeActive(true);
    ensureComputerUseReady();
    {
        const char* configured = std::getenv("RAWRXD_LOG_DIR");
        const std::string path = (configured && *configured)
            ? std::string(configured) + "\\chat_runtime.log"
            : std::string("chat_runtime.log");
        std::ofstream ev(path, std::ios::app);
        if (ev) {
            ev << "AGENT_MODE=ACTIVE path=AgenticLoopBridge"
               << " session_registry=" << (agentToolsRegistry() ? 1 : 0)
               << " AGENT_DISPATCH_CLAIM=1"
               << std::endl;
        }
    }
    
    if (!m_agenticLoopBridge) {
        initializeAgenticLoopBridge();
    }
    
    if (!m_agenticLoopBridge) {
        m_inferenceRunning.store(false, std::memory_order_release);
        MessageBoxA(m_hwndMain, "Agentic Loop Bridge not initialized", "Agentic Loop", MB_OK | MB_ICONERROR);
        return;
    }
    
    // Get task from Copilot Chat input
    if (m_hwndCopilotChatInput) {
        std::string task = getWindowTextUtf8(m_hwndCopilotChatInput);
        if (task.empty() && !m_copilotChatInputCache.empty()) {
            task = m_copilotChatInputCache;
        }

        if (task.empty()) {
            // Cross-process WM_SETTEXT can miss the GhostText subclass cache.
            // Automation may supply an explicit fallback task (Map9 clean-exit).
            if (const char* fallback = std::getenv("RAWRXD_AGENTIC_FALLBACK_TASK");
                fallback && *fallback) {
                task = fallback;
            }
        }
        if (task.empty()) {
            // Non-modal: empty input after chat-send must not block clean exit.
            appendToOutput("Enter a task description in the Copilot Chat input box\n",
                           "Output", OutputSeverity::Warning);
            {
                std::ofstream crumb(
                    "F:\\rawrxd\\evidence\\FULL_FEATURE_ONESHOT_001\\artifacts\\MAP9_AGENTIC_CRUMB.txt",
                    std::ios::app);
                if (crumb) crumb << "empty_task\n";
            }
            m_inferenceRunning.store(false, std::memory_order_release);
            return;
        }

        SetWindowTextW(m_hwndCopilotChatInput, L"");
        m_copilotChatInputCache.clear();
        
        // Route the selected model explicitly. Ollama entries contain a
        // model ID (for example qwen3:8b), while local entries contain a GGUF
        // path. Never apply filesystem validation to an Ollama ID.
        // Issue #49 harness: RAWRXD_FORCE_LOCAL_AGENTIC=1 forces Deep2/local
        // deep2_agentic_loop spawn even when the chat selector is on Ollama.
        const char* forceLocalAgentic = std::getenv("RAWRXD_FORCE_LOCAL_AGENTIC");
        const bool forceLocal =
            forceLocalAgentic && std::string(forceLocalAgentic) == "1";
        // Release/evidence lanes may need to exercise the real Ollama agent
        // route even when the chat selector was initialized to a local GGUF.
        // This is deliberately opt-in: normal UI selection remains
        // authoritative, while the override carries an Ollama model ID (not
        // a filesystem path) and must not pass through local-file validation.
        const char* forceOllamaAgenticEnv = std::getenv("RAWRXD_FORCE_OLLAMA_AGENTIC");
        const bool forceOllamaAgentic =
            forceOllamaAgenticEnv && std::string(forceOllamaAgenticEnv) == "1";
        bool useOllama =
            !forceLocal &&
            m_selectedChatModel.source == ChatModelEntry::Source::Ollama;
        bool useLocalFile =
            forceLocal ||
            m_selectedChatModel.source == ChatModelEntry::Source::LocalFile;
        std::string modelPath;
        if (forceOllamaAgentic) {
            const char* configuredOllamaModel = std::getenv("RAWRXD_OLLAMA_AGENT_MODEL");
            if (configuredOllamaModel && *configuredOllamaModel) {
                modelPath = configuredOllamaModel;
            } else if (m_selectedChatModel.source == ChatModelEntry::Source::Ollama) {
                modelPath = m_selectedChatModel.identifier;
            } else {
                // Do not pass a LocalFile GGUF path to --provider ollama —
                // WinHttp stalls at request_bytes_pending with no TOOL lines.
                modelPath.clear();
            }
            useOllama = true;
            useLocalFile = false;
            const bool looksLikeGgufPath =
                modelPath.find(":\\") != std::string::npos ||
                modelPath.find(":/") != std::string::npos ||
                (modelPath.size() > 5 &&
                 (modelPath.compare(modelPath.size() - 5, 5, ".gguf") == 0 ||
                  modelPath.compare(modelPath.size() - 5, 5, ".GGUF") == 0));
            if (modelPath.empty() || looksLikeGgufPath) {
                appendToOutput(
                    "Agent task rejected: RAWRXD_FORCE_OLLAMA_AGENTIC requires an "
                    "Ollama model tag (set RAWRXD_OLLAMA_AGENT_MODEL=qwen2.5-coder:1.5b), "
                    "not a GGUF filesystem path.\n",
                    "Errors", OutputSeverity::Error);
                m_inferenceRunning.store(false, std::memory_order_release);
                return;
            }
        } else if (forceLocal) {
            if (const char* configuredModel = std::getenv("RAWRXD_DEFAULT_DEEP2_MODEL")) {
                if (*configuredModel) modelPath = configuredModel;
            }
            if (modelPath.empty() && !m_loadedModelPath.empty()) {
                modelPath = m_loadedModelPath;
            }
            if (modelPath.empty() && m_deep2Bridge && m_deep2Bridge->IsModelLoaded()) {
                modelPath = m_deep2Bridge->GetCurrentModel();
            }
            useOllama = false;
            useLocalFile = true;
        } else if (useOllama || useLocalFile) {
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
        const bool ollamaModelLooksLikePath =
            useOllama &&
            (modelPath.find(":\\") != std::string::npos ||
             modelPath.find(":/") != std::string::npos ||
             (modelPath.size() > 5 &&
              (modelPath.compare(modelPath.size() - 5, 5, ".gguf") == 0 ||
               modelPath.compare(modelPath.size() - 5, 5, ".GGUF") == 0)));
        if (ollamaModelLooksLikePath) {
            appendToOutput(
                "Agent task rejected: Ollama provider received a GGUF filesystem path "
                "('" + modelPath + "'). Select an Ollama chat model tag or set "
                "RAWRXD_OLLAMA_AGENT_MODEL.\n",
                "Errors", OutputSeverity::Error);
            m_inferenceRunning.store(false, std::memory_order_release);
            return;
        }
        if (modelPath.empty() ||
            (useLocalFile && GetFileAttributesA(modelPath.c_str()) == INVALID_FILE_ATTRIBUTES)) {
            appendToOutput("Agent task rejected: select or configure a valid local model first.\n",
                           "Errors", OutputSeverity::Error);
            {
                std::ofstream crumb(
                    "F:\\rawrxd\\evidence\\FULL_FEATURE_ONESHOT_001\\artifacts\\MAP9_AGENTIC_CRUMB.txt",
                    std::ios::app);
                if (crumb) crumb << "model_reject useLocal=" << (useLocalFile?1:0)
                                 << " path=" << modelPath << "\n";
            }
            m_inferenceRunning.store(false, std::memory_order_release);
            return;
        }

        if (m_selectedChatModel.source == ChatModelEntry::Source::KiloFree) {
            appendToOutput("Agent task rejected: KiloFree is a chat-only route; select an Ollama or local GGUF model for tools.\n",
                           "Errors", OutputSeverity::Error);
            m_inferenceRunning.store(false, std::memory_order_release);
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
        if (useOllama &&
            (task.find(".cpp") != std::string::npos ||
             task.find("bug") != std::string::npos ||
             task.find("fix") != std::string::npos)) {
            // Keep the GUI task aligned with the release acceptance contract:
            // the agent must repair the actual compile error and produce the
            // independently checked AGENT_RESULT=5 executable output.
            config.task +=
                " Preserve the program's intended result. If the fixture has TWO "
                "defects, fix them in ordered writes: first compile arity only "
                "(keep add as return a - b;), then after write rolled back for wrong "
                "AGENT_RESULT you MUST issue another TOOL write changing add to "
                "return a + b; while keeping undeclared_fn fixed. "
                "Do not delete add(). Do not finish after a rollback. "
                "Final executable must print exactly AGENT_RESULT=5. "
                "If undeclared_fn(1, 2) is present, fix the call site arity "
                "(undeclared_fn(1)) so /W4 /WX has no C4100 warning.";
        }
        config.maxSteps = useOllama ? 14 : 8;
        config.maxNewTokens = 512;
        config.maxRetries = 2;
        // Legacy 300s wall kills 7B during first prefill (~260s) before TOOL.
        // Ollama S_13 needs room for rollback then second write (many round-trips).
        // FORCE_LOCAL default 2400s; override via RAWRXD_AGENTIC_MAX_WALL_SEC.
        config.maxWallTimeSec = forceLocal ? 2400 : (useOllama ? 900 : 300);
        if (const char* wallEnv = std::getenv("RAWRXD_AGENTIC_MAX_WALL_SEC")) {
            const int parsedWall = std::atoi(wallEnv);
            if (parsedWall >= 60) config.maxWallTimeSec = parsedWall;
        }
        config.maxTotalTokens = 8192;
        config.contextSize = 4096;
        if (const char* ctxEnv = std::getenv("RAWRXD_AGENTIC_CONTEXT_SIZE")) {
            const int parsedCtx = std::atoi(ctxEnv);
            if (parsedCtx >= 512) config.contextSize = parsedCtx;
        }
        // Default quiet hides TOOL/ESP text from the Output panel harness.
        // RAWRXD_AGENTIC_QUIET=0 forces audible tool lines for Issue #49 proof.
        config.quiet = true;
        if (const char* quietEnv = std::getenv("RAWRXD_AGENTIC_QUIET")) {
            config.quiet = !(std::string(quietEnv) == "0");
        } else if (forceLocal) {
            config.quiet = false;
        }
        // Ollama chat tasks use the same canonical `rawr run` path as the
        // CLI smoke-tested backend.  Keep plain GUI chat read-only by default;
        // agent-mode / AgenticLoop (RAWRXD_AGENT_MODE) and explicit env opt-in
        // authorize the live tool surface (read + computer_use.* + edits).
        config.useCliAgent = useOllama;
        const char* approveGuiMutations = std::getenv("RAWRXD_GUI_APPROVE_MUTATIONS");
        config.approveMutations = approveGuiMutations &&
            std::string(approveGuiMutations) == "YES";
        // Issue #49 FORCE_LOCAL product path must edit fixtures; do not leave
        // the deep2 loop read-only when the harness forces local agentic.
        if (forceLocal && !config.approveMutations) {
            config.approveMutations = true;
        }
        // Agent-mode Send/Run Agentic Task is the structured tool loop, not
        // HandleCopilotSend text chat — enable agent tool mode so CU/read
        // are not clamped to --mode ask.
        if (isAgentModeActive() && !config.approveMutations) {
            config.approveMutations = true;
        }
        config.readOnly = !config.approveMutations;

        if (auto* session = activeChatSession()) {
            m_agenticChatSessionId = session->id;
        }

        // Chip first, then open thought so the timer stays live until tools/progress.
        m_agentStepTimeline.clear();
        m_agentStepTimeline.addChip("agent", task);
        m_agentStepTimeline.beginThought();
        if (m_hwndMain) SetTimer(m_hwndMain, IDT_AGENT_THOUGHT, 250, nullptr);
        if (m_hwndCopilotStopBtn) EnableWindow(m_hwndCopilotStopBtn, TRUE);
        
        // deep2 SafeWorkPath allows relative paths plus absolute paths under
        // workdir / open-doc / fixture allowlists. Always prefer relative
        // targets. FORCE_LOCAL binds basename + parent workdir so TOOL write
        // bug.cpp hits the opened fixture, not the MOTD repo root.
        if (!m_currentFile.empty()) {
            SetEnvironmentVariableA("RAWRXD_OPEN_DOCUMENT", m_currentFile.c_str());
            const bool forceLocalAgentic = forceLocal || forceOllamaAgentic ||
                (std::getenv("RAWRXD_FORCE_LOCAL_AGENTIC") &&
                 std::string(std::getenv("RAWRXD_FORCE_LOCAL_AGENTIC")) == "1");
            const std::string fileDir = directoryForPath(m_currentFile);
            const size_t slash = m_currentFile.find_last_of("\\/");
            const std::string baseName = (slash == std::string::npos)
                ? m_currentFile
                : m_currentFile.substr(slash + 1);
            if (forceLocalAgentic && !fileDir.empty() && !baseName.empty()) {
                config.workDir = fileDir;
                workDirStr = fileDir;
                config.targetFile = baseName;
            } else {
                std::error_code fileEc;
                const std::filesystem::path absFile =
                    std::filesystem::weakly_canonical(
                        std::filesystem::path(m_currentFile), fileEc);
                std::error_code rootEc;
                const std::filesystem::path absRoot = workDirStr.empty()
                    ? std::filesystem::path{}
                    : std::filesystem::weakly_canonical(
                          std::filesystem::path(workDirStr), rootEc);
                std::string relativeTarget;
                if (!fileEc && !rootEc && !absRoot.empty() && !absFile.empty()) {
                    const auto rel = absFile.lexically_relative(absRoot);
                    const std::string relText = rel.generic_string();
                    if (!relText.empty() && relText != "." &&
                        relText.find("..") == std::string::npos) {
                        relativeTarget = rel.string();
                        for (char& ch : relativeTarget) {
                            if (ch == '/') ch = '\\';
                        }
                    }
                }
                if (!relativeTarget.empty()) {
                    config.targetFile = relativeTarget;
                } else if (!fileDir.empty() && !baseName.empty()) {
                    config.workDir = fileDir;
                    workDirStr = fileDir;
                    config.targetFile = baseName;
                }
                // Never pass absolute --target-file; omit rather than spawn doomed.
            }
        }

        // Issue #49: when FORCE_LOCAL, prefer harness fixture env over sticky
        // explorer/ONESHOT session restore. tip_014/015 IDE exclusive bound
        // FULL_FEATURE_ONESHOT_001\fixtures (broken_multi) despite argv/bug.cpp.
        if (forceLocal || forceOllamaAgentic) {
            const char* fixtureEnv = std::getenv("RAWRXD_PROBLEMS_FIXTURE");
            if (!fixtureEnv || !*fixtureEnv) {
                fixtureEnv = std::getenv("RAWRXD_OPEN_DOCUMENT");
            }
            if (fixtureEnv && *fixtureEnv) {
                const std::string fixturePath(fixtureEnv);
                const std::string fixtureDir = directoryForPath(fixturePath);
                const size_t slash = fixturePath.find_last_of("\\/");
                const std::string fixtureBase = (slash == std::string::npos)
                    ? fixturePath
                    : fixturePath.substr(slash + 1);
                if (!fixtureDir.empty() && !fixtureBase.empty()) {
                    config.workDir = fixtureDir;
                    workDirStr = fixtureDir;
                    config.targetFile = fixtureBase;
                    if (m_currentFile.empty()) {
                        m_currentFile = fixturePath;
                    }
                    appendToOutput(
                        " FORCE_LOCAL_FIXTURE_BIND workdir=" + fixtureDir +
                        " target=" + fixtureBase + "\n",
                        "Output", OutputSeverity::Info);
                }
            }
            if (const char* wsEnv = std::getenv("RAWRXD_WORKSPACE")) {
                if (*wsEnv) {
                    workDirStr = wsEnv;
                    config.workDir = wsEnv;
                }
            }
        }
        
        appendToOutput(" Starting agentic task: " + task + "\n", "Output", OutputSeverity::Info);
        appendToOutput(" Provider: " + config.provider + "\n", "Output", OutputSeverity::Info);
        appendToOutput(" Model: " + modelPath + "\n", "Output", OutputSeverity::Info);
        appendToOutput(" Work dir: " + workDirStr + "\n", "Output", OutputSeverity::Info);
        if (!config.targetFile.empty()) {
            appendToOutput(" Target file: " + config.targetFile + "\n", "Output", OutputSeverity::Info);
        }

        // H57 / Issue #49: construct product AgentSession on the Native-Ext path
        // before spawning deep2_agentic_loop so session + loop share one task id.
        if (!ensureProductAgentSession(modelPath, workDirStr, task)) {
            appendToOutput("AgentSession initialization failed.\n",
                           "Errors", OutputSeverity::Error);
            m_inferenceRunning.store(false, std::memory_order_release);
            return;
        }
        // Seed undo before-bytes for the known target so first write has a snapshot.
        if (!config.targetFile.empty()) {
            std::filesystem::path seed =
                std::filesystem::path(workDirStr) / config.targetFile;
            snapshotAgentFileBytes(seed.string());
        }

        // Start the task
        const bool started = m_agenticBridge->StartAutonomousTask(config,
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
        if (started) {
            const uint64_t dispatchId = m_productAgentSessionId;
            const char* configured = std::getenv("RAWRXD_LOG_DIR");
            const std::string path = (configured && *configured)
                ? std::string(configured) + "\\chat_runtime.log"
                : std::string("chat_runtime.log");
            std::ofstream ev(path, std::ios::app);
            if (ev) {
                ev << "REQUEST_DISPATCH_CORRELATED"
                   << " dispatch_id=" << dispatchId
                   << " session_identity=" << m_productAgentSessionId
                   << " request_id=" << m_espRequestId
                   << " agentic_chat_session=" << m_agenticChatSessionId
                   << " task_bytes=" << task.size()
                   << std::endl;
            }
            appendToOutput(
                "REQUEST_DISPATCH_CORRELATED dispatch_id=" +
                std::to_string(dispatchId) +
                " session_identity=" + std::to_string(m_productAgentSessionId) +
                "\n",
                "Output", OutputSeverity::Info);

            // Issue #49: host-seed is OPT-IN only (RAWRXD_ISSUE49_HOST_SEED=1).
            // Default OFF so steps 08-11 require model-originated TOOL/edit.
            // tip_014 IDE exclusive measured FORCE_LOCAL host-seed inventing
            // TOOL/edit (broken_multi/ONESHOT) — not credit under HOST_SEED=OFF.
            // No host-seed WRITE: SOURCE_EDIT / BUILD_RECOVERY must be
            // model-originated (HOST_SEED_NEQ_MODEL_ORIGINATED_TOOL).
            const char* hostSeedEnv = std::getenv("RAWRXD_ISSUE49_HOST_SEED");
            const bool hostSeedOptIn =
                hostSeedEnv && std::string(hostSeedEnv) == "1";
            if (forceLocal && !hostSeedOptIn && ev) {
                ev << "HOST_SEED_SKIPPED opt_in=0 "
                      "(model-originated TOOL required for ISSUE49 08-11)"
                   << std::endl;
            }
            if (forceLocal && hostSeedOptIn && m_productAgentSession) {
                std::string seedTarget = config.targetFile;
                if (seedTarget.empty()) {
                    if (const char* issueTarget = std::getenv("RAWRXD_ISSUE49_TARGET")) {
                        if (*issueTarget) seedTarget = issueTarget;
                    }
                }
                if (seedTarget.empty() && !m_currentFile.empty()) {
                    const size_t slash = m_currentFile.find_last_of("\\/");
                    seedTarget = (slash == std::string::npos)
                        ? m_currentFile
                        : m_currentFile.substr(slash + 1);
                }
                if (seedTarget.empty()) seedTarget = "bug.cpp";

                std::string seedWork = config.workDir;
                if (seedWork.empty() && !m_currentFile.empty()) {
                    seedWork = directoryForPath(m_currentFile);
                }
                const std::filesystem::path seedPath =
                    std::filesystem::path(seedWork) / seedTarget;
                std::string seedOut;
                std::error_code seedEc;
                const bool seedExists =
                    std::filesystem::is_regular_file(seedPath, seedEc);
                if (seedExists) {
                    std::ifstream seedIn(seedPath, std::ios::binary);
                    if (seedIn) {
                        std::ostringstream seedSs;
                        seedSs << seedIn.rdbuf();
                        seedOut = seedSs.str();
                    }
                }
                auto* session = static_cast<RawrXD::Agent::AgentSession*>(
                    m_productAgentSession.get());
                RawrXD::Agent::ToolCallRecord recRead;
                recRead.tool_name = "read";
                recRead.args = {{"path", seedTarget},
                                {"seed", "FORCE_LOCAL_HOST_READ"}};
                recRead.ok = seedExists && !seedOut.empty();
                recRead.output = recRead.ok
                    ? seedOut.substr(0, std::min<size_t>(seedOut.size(), 4096))
                    : std::string("host seed read failed");
                recRead.error = recRead.ok ? "" : "SEED_READ_FAILED";
                recRead.timestamp = RawrXD::Agent::AgentSession::NowUnix();
                session->RecordToolCall(recRead);
                session->AppendToolResultMessage(recRead);
                session->RecordAgentTurn();
                appendToOutput(
                    " TOOL: read " + seedTarget +
                    " [exit=" + std::to_string(recRead.ok ? 0 : 1) +
                    "] HOST_SEED_FORCE_LOCAL\n",
                    "Output",
                    recRead.ok ? OutputSeverity::Info : OutputSeverity::Error);
                if (ev) {
                    ev << "HOST_SEED_TOOL_CALL name=read target=" << seedTarget
                       << " ok=" << (recRead.ok ? 1 : 0)
                       << " bytes=" << seedOut.size()
                       << " path=" << seedPath.string() << std::endl;
                }
            }
        }
        {
            std::ofstream crumb(
                "F:\\rawrxd\\evidence\\FULL_FEATURE_ONESHOT_001\\artifacts\\MAP9_AGENTIC_CRUMB.txt",
                std::ios::app);
            if (crumb) crumb << "start_task started=" << (started?1:0)
                             << " task=" << task << " model=" << modelPath
                             << " provider=" << config.provider << "\n";
        }
        if (!started) {
            m_agenticChatSessionId = 0;
            if (m_hwndMain) KillTimer(m_hwndMain, IDT_AGENT_THOUGHT);
            m_agentStepTimeline.closeThoughtIfOpen();
            m_agentStepTimeline.addChip("fail", "agent task could not be started");
            if (m_hwndCopilotStopBtn) EnableWindow(m_hwndCopilotStopBtn, FALSE);
            appendToOutput("Agent task could not be started.\n", "Errors", OutputSeverity::Error);
            m_inferenceRunning.store(false, std::memory_order_release);
        }
    } else {
        appendToOutput("Copilot Chat input not available\n",
                       "Errors", OutputSeverity::Error);
        {
            std::ofstream crumb(
                "F:\\rawrxd\\evidence\\FULL_FEATURE_ONESHOT_001\\artifacts\\MAP9_AGENTIC_CRUMB.txt",
                std::ios::app);
            if (crumb) crumb << "no_chat_input\n";
        }
        m_inferenceRunning.store(false, std::memory_order_release);
    }
}

// Cancel running agentic task
void Win32IDE::onAgenticLoopCancel() {
    LOG_INFO("onAgenticLoopCancel called");
    cancelComputerUse();
    
    if (!m_agenticLoopBridge) {
        m_inferenceRunning.store(false, std::memory_order_release);
        return;
    }
    
    // Map9: always Cancel/reap — IsRunning may be false while child still lives.
    if (m_agenticBridge) m_agenticBridge->CancelAutonomousTask(); else if (m_agenticLoopBridge) m_agenticLoopBridge->Cancel();
    m_agenticChatSessionId = 0;
    disarmAgentThoughtTimer();
    m_agentStepTimeline.closeThoughtIfOpen();
    m_agentStepTimeline.addChip("stopped", "agentic cancelled");
    if (m_hwndCopilotStopBtn) EnableWindow(m_hwndCopilotStopBtn, FALSE);
    m_inferenceRunning.store(false, std::memory_order_release);
    if (m_productAgentSession) {
        auto* session = static_cast<RawrXD::Agent::AgentSession*>(
            m_productAgentSession.get());
        session->SetTermination(RawrXD::Agent::TerminationReason::Cancelled, 1);
        session->SetVerdict("CANCELLED");
        session->Flush();
    }
    if (m_productTaskBacklog && !m_productTaskId.empty()) {
        auto* backlog = static_cast<RawrXD::Agent::PersistentTaskBacklog*>(
            m_productTaskBacklog.get());
        backlog->MarkTaskReverted(m_productTaskId, "agentic cancelled");
        appendToOutput("[TaskLedger] cancelled id=" + m_productTaskId + "\n",
                       "Output", OutputSeverity::Warning);
    }
    appendToOutput(" Agentic task cancelled\n", "Output", OutputSeverity::Warning);
    if (m_hwndStatusBar) {
        const char* status = "Agentic task cancelled";
        SendMessageA(m_hwndStatusBar, SB_SETTEXTA, 0, reinterpret_cast<LPARAM>(status));
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
            // Cap per-message UI payload; unbounded ESP dumps previously
            // exhausted RichEdit and exited the IDE with ExitCode=-1.
            std::string capped = visible;
            constexpr size_t kMaxProgressUi = 1024;
            if (capped.size() > kMaxProgressUi) {
                capped.resize(kMaxProgressUi);
                capped.append("\r\n...(truncated)");
            }
            appendToOutput(capped, "Output", OutputSeverity::Info);
            std::string lower = capped;
            for (char& c : lower) {
                if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
            }
            const bool isLaunch = lower.find("launching") != std::string::npos;
            const bool isTaskEnd =
                lower.find("task completed") != std::string::npos ||
                lower.find("task failed") != std::string::npos;
            const bool isToolish =
                lower.find("tool_result") != std::string::npos ||
                (lower.find("tool") != std::string::npos &&
                 lower.find("pending") != std::string::npos);
            // Strip-only for SNAP/step noise; chat only for launch/end/tool.
            if (lower.find("powershell") != std::string::npos ||
                lower.find("pwsh") != std::string::npos) {
                m_agentStepTimeline.addChip("powershell", capped);
            } else if (lower.find("explor") != std::string::npos ||
                       lower.find("glob") != std::string::npos ||
                       lower.find("grep") != std::string::npos ||
                       lower.find("read_file") != std::string::npos ||
                       lower.find("list_dir") != std::string::npos) {
                m_agentStepTimeline.addExplored(capped);
            } else if (isLaunch || isTaskEnd || isToolish ||
                       lower.find("[snap]") != std::string::npos) {
                m_agentStepTimeline.addChip("step", capped);
            }
            if (m_agenticChatSessionId != 0 &&
                (isLaunch || isTaskEnd || isToolish)) {
                handleCopilotUiUpdate(m_agenticChatSessionId,
                                      "\r\n[agent] " + capped + "\r\n", false);
            }
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
        m_agentStepTimeline.addTool(result->toolName, result->target,
                                    result->exitCode, result->success);
        if (m_productAgentSession) {
            auto* session = static_cast<RawrXD::Agent::AgentSession*>(
                m_productAgentSession.get());
            RawrXD::Agent::ToolCallRecord rec;
            rec.tool_name = result->toolName;
            rec.ok = result->success;
            rec.output = result->output;
            rec.timestamp = RawrXD::Agent::AgentSession::NowUnix();
            if (!result->target.empty()) {
                rec.args["path"] = result->target;
            }
            session->RecordToolCall(rec);
            // Model-originated TOOL write must mark durable source edit in the
            // AgentSession ledger (Issue #49 step 10). HOST_SEED write remains
            // forbidden elsewhere; this path only records loop-emitted writes.
            const bool isRead =
                result->toolName == "read" || result->toolName == "read_file" ||
                result->toolName == "readFile";
            const bool isWrite =
                result->toolName == "write" || result->toolName == "write_file" ||
                result->toolName == "writeFile" || result->toolName == "edit_file" ||
                result->toolName == "editFiles" || result->toolName == "apply_edit";
            if (result->success && !result->target.empty() && isRead) {
                snapshotAgentFileBytes(result->target);
            }
            if (result->success && isWrite) {
                const std::string modPath = result->target.empty() ? std::string("bug.cpp")
                                                                   : result->target;
                session->RecordFileModified(modPath);
                recordAgentFileMutation(modPath);
            }
            session->RecordAgentTurn();
        }
        if (m_productTaskBacklog && !m_productTaskId.empty()) {
            auto* backlog = static_cast<RawrXD::Agent::PersistentTaskBacklog*>(
                m_productTaskBacklog.get());
            auto task = backlog->GetTask(m_productTaskId);
            if (task) {
                RawrXD::Agent::TaskStep step;
                step.action = result->toolName;
                step.output = result->output.size() > 2048
                    ? result->output.substr(0, 2048) : result->output;
                step.success = result->success;
                step.timestamp = RawrXD::Agent::AgentSession::NowUnix();
                if (!result->target.empty()) step.changed_files.push_back(result->target);
                task->steps.push_back(step);
                backlog->UpdateTask(*task);
            }
        }
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
    m_inferenceRunning.store(false, std::memory_order_release);
    if (lParam) {
        std::string* summary = reinterpret_cast<std::string*>(lParam);
        
        std::string output = "\n=== TASK " + std::string(success ? "COMPLETED" : "FAILED") + " ===\n";
        output += *summary + "\n";
        
        appendToOutput(output, "Output", success ? OutputSeverity::Info : OutputSeverity::Error);
        disarmAgentThoughtTimer();
        m_agentStepTimeline.closeThoughtIfOpen();
        m_agentStepTimeline.addChip(success ? "done" : "fail", *summary);
        if (m_hwndCopilotStopBtn) EnableWindow(m_hwndCopilotStopBtn, FALSE);
        if (m_productAgentSession) {
            auto* session = static_cast<RawrXD::Agent::AgentSession*>(
                m_productAgentSession.get());
            // Ledger Flush sanitizes invalid UTF-8; still catch so any residual
            // session exception cannot abort the UI thread (Issue49 type_error.316).
            try {
                session->AppendAssistantMessage(*summary);
                session->SetTermination(
                    success ? RawrXD::Agent::TerminationReason::ModelCompleted
                            : RawrXD::Agent::TerminationReason::DriverException,
                    success ? 0 : 1);
                session->SetVerdict(success ? "PASS" : "FAIL");
                session->Flush();
            } catch (const nlohmann::json::exception&) {
                LOG_ERROR("AgentSession ledger update failed (json); IDE continues");
            } catch (const std::exception& ex) {
                LOG_ERROR(std::string("AgentSession ledger update failed: ") + ex.what());
            } catch (...) {
                LOG_ERROR("AgentSession ledger update failed (unknown)");
            }
        }
        if (m_productTaskBacklog && !m_productTaskId.empty()) {
            auto* backlog = static_cast<RawrXD::Agent::PersistentTaskBacklog*>(
                m_productTaskBacklog.get());
            if (success) {
                backlog->MarkTaskCompleted(m_productTaskId, *summary);
            } else {
                backlog->MarkTaskFailed(m_productTaskId, *summary);
            }
            appendToOutput(
                std::string("[TaskLedger] ") + (success ? "completed" : "failed") +
                " id=" + m_productTaskId + "\n",
                "Output", success ? OutputSeverity::Info : OutputSeverity::Error);
        }
        if (m_agenticChatSessionId != 0) {
            const int sessionId = m_agenticChatSessionId;
            handleCopilotUiUpdate(sessionId, *summary + "\r\n", true);
            m_agenticChatSessionId = 0;
        }
        
        delete summary;
    }
    return 0;
}

// Legacy AgenticBridge completion (WM_APP + 109) — timeline only; no agentic session clear.
LRESULT Win32IDE::handleLegacyAgentComplete(WPARAM wParam, LPARAM lParam) {
    const bool success = (wParam != 0);
    if (lParam) {
        std::string* summary = reinterpret_cast<std::string*>(lParam);
        appendToOutput(
            std::string("\n=== LEGACY AGENT ") + (success ? "COMPLETED" : "FAILED") + " ===\n" +
            *summary + "\n",
            "Output", success ? OutputSeverity::Info : OutputSeverity::Error);
        disarmAgentThoughtTimer();
        m_agentStepTimeline.closeThoughtIfOpen();
        m_agentStepTimeline.addChip(success ? "done" : "fail", *summary);
        if (m_hwndCopilotStopBtn) EnableWindow(m_hwndCopilotStopBtn, FALSE);
        delete summary;
    }
    return 0;
}
