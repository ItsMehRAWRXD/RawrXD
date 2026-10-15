// Agent menu implementation for Win32IDE
// Implements all agentic framework menu commands and integrations

#include "Win32IDE.h"
#include "Win32IDE_AgenticBridge.h"
#include "Win32IDE_Deep2Bridge.h"
#include "Win32IDE_AgenticLoopBridge.h"
#include "ModelConnection.h"
#include "IDELogger.h"
#include <sstream>

// Initialize the Agentic Bridge
void Win32IDE::initializeAgenticBridge() {
    LOG_INFO("Initializing Agentic Bridge");
    
    if (!m_agenticBridge) {
        m_agenticBridge = std::make_unique<AgenticBridge>(this);
        
        // Set output callback to send agent responses to Copilot Chat
        m_agenticBridge->SetOutputCallback([this](const std::string& title, const std::string& content) {
            appendToOutput(title + ":\n" + content + "\n", "Output", OutputSeverity::Info);
            
            // Also send to Copilot Chat if available
            if (m_hwndCopilotChatOutput) {
                std::string formatted = " " + title + "\n" + content + "\n\n";
                SendMessageA(m_hwndCopilotChatOutput, EM_SETSEL, -1, -1);
                SendMessageA(m_hwndCopilotChatOutput, EM_REPLACESEL, FALSE, (LPARAM)formatted.c_str());
            }
        });
        
        // Initialize with default framework path
        if (m_agenticBridge->Initialize("", "bigdaddyg-personalized-agentic:latest")) {
            LOG_INFO("Agentic Bridge initialized successfully");
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
        SetWindowTextA(m_hwndCopilotChatInput, "");
    } else {
        MessageBoxA(m_hwndMain, "Copilot Chat input not available", "Agent Error", MB_OK | MB_ICONERROR);
    }
}

// Configure AI model
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
    RECT parentRect{};
    GetWindowRect(m_hwndMain, &parentRect);

    const int dlgWidth = 420;
    const int dlgHeight = 200;
    const int dlgX = parentRect.left + ((parentRect.right - parentRect.left) - dlgWidth) / 2;
    const int dlgY = parentRect.top + ((parentRect.bottom - parentRect.top) - dlgHeight) / 2;

    EnableWindow(m_hwndMain, FALSE);

    HWND hwndDlg = CreateWindowExA(WS_EX_DLGMODALFRAME, "STATIC", "Select Agent Model",
        WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
        dlgX, dlgY, dlgWidth, dlgHeight, m_hwndMain, nullptr, m_hInstance, nullptr);

    if (!hwndDlg) {
        EnableWindow(m_hwndMain, TRUE);
        MessageBoxA(m_hwndMain, "Failed to create model selection dialog", "Agent", MB_OK | MB_ICONERROR);
        return;
    }

    CreateWindowExA(0, "STATIC", "Choose an available model:", WS_CHILD | WS_VISIBLE,
        10, 10, dlgWidth - 20, 20, hwndDlg, nullptr, m_hInstance, nullptr);

    HWND hwndCombo = CreateWindowExA(WS_EX_CLIENTEDGE, "COMBOBOX", "",
        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
        10, 35, dlgWidth - 40, 140, hwndDlg, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(1001)), m_hInstance, nullptr);

    int selectedIndex = 0;
    for (size_t i = 0; i < availableModels.size(); ++i) {
        const auto& model = availableModels[i];
        SendMessageA(hwndCombo, CB_ADDSTRING, 0, (LPARAM)model.c_str());
        if (model == currentModel) {
            selectedIndex = static_cast<int>(i);
        }
    }
    SendMessageA(hwndCombo, CB_SETCURSEL, selectedIndex, 0);

    HWND hwndOk = CreateWindowExA(0, "BUTTON", "Use Model", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
        dlgWidth - 200, dlgHeight - 50, 90, 30, hwndDlg, (HMENU)IDOK, m_hInstance, nullptr);
    HWND hwndCancel = CreateWindowExA(0, "BUTTON", "Cancel", WS_CHILD | WS_VISIBLE,
        dlgWidth - 100, dlgHeight - 50, 80, 30, hwndDlg, (HMENU)IDCANCEL, m_hInstance, nullptr);

    bool accepted = false;
    std::string selectedModel = currentModel;

    MSG msg{};
    while (IsWindow(hwndDlg) && GetMessage(&msg, nullptr, 0, 0)) {
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
                SendMessageA(m_hwndCopilotChatOutput, EM_SETSEL, -1, -1);
                SendMessageA(m_hwndCopilotChatOutput, EM_REPLACESEL, FALSE, (LPARAM)formatted.c_str());
            }
        });
        
        // Try to initialize with default model if available
        std::string defaultModel = "F:\\rawrxd\\models\\deepseek-coder-v2-lite-instruct.Q4_K_M.gguf";
        if (m_deep2Bridge->Initialize(defaultModel)) {
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
        char input[4096] = {0};
        GetWindowTextA(m_hwndCopilotChatInput, input, sizeof(input));
        
        if (strlen(input) == 0) {
            MessageBoxA(m_hwndMain, "Enter a prompt in the Copilot Chat input box", "Deep2", MB_OK | MB_ICONINFORMATION);
            return;
        }
        
        std::string prompt(input);
        appendToOutput(" Generating with Deep2: " + prompt + "\n", "Output", OutputSeverity::Info);
        
        // Clear input
        SetWindowTextA(m_hwndCopilotChatInput, "");
        
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
        char input[4096] = {0};
        GetWindowTextA(m_hwndCopilotChatInput, input, sizeof(input));
        
        if (strlen(input) == 0) {
            MessageBoxA(m_hwndMain, "Enter a task description in the Copilot Chat input box", "Agentic Loop", MB_OK | MB_ICONINFORMATION);
            return;
        }
        
        std::string task(input);
        SetWindowTextA(m_hwndCopilotChatInput, "");
        
        // Get model path (use Deep2 model if loaded, otherwise prompt)
        std::string modelPath = "F:\\rawrxd\\models\\qwen2.5-coder_1.5b-base.gguf";
        if (m_deep2Bridge && m_deep2Bridge->IsModelLoaded()) {
            modelPath = m_deep2Bridge->GetCurrentModel();
        }
        
        // Get work directory
        char workDir[MAX_PATH];
        GetCurrentDirectoryA(MAX_PATH, workDir);
        std::string workDirStr(workDir);
        
        // Build task config
        AgenticLoopBridge::TaskConfig config;
        config.modelPath = modelPath;
        config.workDir = workDirStr;
        config.task = task;
        config.maxSteps = 8;
        config.maxNewTokens = 512;
        config.maxRetries = 2;
        config.maxWallTimeSec = 300;
        config.maxTotalTokens = 8192;
        config.quiet = true;
        
        // Also check if there's an open file to use as target
        if (!m_currentFile.empty()) {
            config.targetFile = m_currentFile;
        }
        
        appendToOutput(" Starting agentic task: " + task + "\n", "Output", OutputSeverity::Info);
        appendToOutput(" Model: " + modelPath + "\n", "Output", OutputSeverity::Info);
        appendToOutput(" Work dir: " + workDirStr + "\n", "Output", OutputSeverity::Info);
        
        // Start the task
        m_agenticLoopBridge->StartTask(config,
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
        appendToOutput(*msg, "Output", OutputSeverity::Info);
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
        
        // Publish ESP event
        m_espBus.publish(rawrxd::esp::Kind::Finished, success ? "PASS" : "FAIL", m_espRequestId++);
        
        delete summary;
    }
    return 0;
}
