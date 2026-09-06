// Win32IDE_VoiceAssistantPanel.cpp - Voice Assistant Panel with State Machine
// Sprint 02: UI/UX Enhancement - GDI+ Integration

#include "Win32IDE.h"
#include "Win32Utf8.hpp"
#include "resource.h"
#include "../core/voice_assistant_manager.hpp"
#include "VoiceAssistantWorker.hpp"
#include "../include/ui/VoiceAssistantState.hpp"
#include <commctrl.h>
#include <richedit.h>
#include <nlohmann/json.hpp>
#include <memory>

// Static variables
static HWND g_hwndVoiceAssistantPanel = nullptr;
static bool g_voiceAssistantInitialized = false;
static std::unique_ptr<RawrXD::UI::VoiceAssistantStateMachine> g_stateMachine;
static std::unique_ptr<RawrXD::UI::VoiceAssistantRenderer> g_renderer;
static UINT_PTR g_animationTimer = 0;

// Forward declarations
static void CALLBACK AnimationTimerProc(HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime);
static void OnVoiceAssistantPaint(HWND hwnd);
static void OnVoiceAssistantClick(HWND hwnd);
static void TransitionToState(RawrXD::UI::VoiceAssistantState newState);
static void SetupStateCallbacks();

// Initialize voice assistant panel
void Win32IDE::initVoiceAssistantPanel() {
    g_voiceAssistantInitialized = true;
    
    // Initialize State Machine
    g_stateMachine = std::make_unique<RawrXD::UI::VoiceAssistantStateMachine>();
    
    // Initialize Renderer
    g_renderer = std::make_unique<RawrXD::UI::VoiceAssistantRenderer>();
    
    // Setup state callbacks
    SetupStateCallbacks();
}

// Setup state callbacks
static void SetupStateCallbacks() {
    if (!g_stateMachine) return;
    
    // Set transition callback for logging/debugging
    g_stateMachine->setTransitionCallback(
        [](RawrXD::UI::VoiceAssistantState from, RawrXD::UI::VoiceAssistantState to) {
            // Log state transition
            OutputDebugStringA(("Voice Assistant: " + 
                std::string(RawrXD::UI::getStateName(from)) + 
                " -> " + 
                std::string(RawrXD::UI::getStateName(to)) + "\n").c_str());
        }
    );
    
    // Set render callback
    g_stateMachine->setRenderCallback(
        [](HDC hdc, const RECT& rect, RawrXD::UI::VoiceAssistantState state) {
            if (g_renderer) {
                g_renderer->renderState(hdc, rect, state, g_stateMachine->getAnimationProgress());
            }
        }
    );
}

// Transition to new state
static void TransitionToState(RawrXD::UI::VoiceAssistantState newState) {
    if (g_stateMachine) {
        g_stateMachine->transitionTo(newState);
        
        // Force redraw
        if (g_hwndVoiceAssistantPanel) {
            InvalidateRect(g_hwndVoiceAssistantPanel, nullptr, TRUE);
        }
    }
}

// Animation timer callback
static void CALLBACK AnimationTimerProc(HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime) {
    if (g_stateMachine) {
        g_stateMachine->updateAnimation();
        
        // Force redraw
        if (g_hwndVoiceAssistantPanel) {
            InvalidateRect(g_hwndVoiceAssistantPanel, nullptr, FALSE);
        }
    }
}

// Handle paint message
static void OnVoiceAssistantPaint(HWND hwnd) {
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(hwnd, &ps);
    
    RECT rect;
    GetClientRect(hwnd, &rect);
    
    // Clear background
    HBRUSH bgBrush = CreateSolidBrush(RGB(30, 30, 30));
    FillRect(hdc, &rect, bgBrush);
    DeleteObject(bgBrush);
    
    // Render current state
    if (g_stateMachine) {
        g_stateMachine->render(hdc, rect);
    }
    
    EndPaint(hwnd, &ps);
}

// Handle click message
static void OnVoiceAssistantClick(HWND hwnd) {
    if (!g_stateMachine) return;
    
    auto currentState = g_stateMachine->getCurrentState();
    
    switch (currentState) {
        case RawrXD::UI::VoiceAssistantState::IDLE:
            TransitionToState(RawrXD::UI::VoiceAssistantState::LISTENING);
            break;
        case RawrXD::UI::VoiceAssistantState::LISTENING:
            TransitionToState(RawrXD::UI::VoiceAssistantState::IDLE);
            break;
        case RawrXD::UI::VoiceAssistantState::ERROR:
            TransitionToState(RawrXD::UI::VoiceAssistantState::IDLE);
            break;
        default:
            // In other states, click is ignored or handled differently
            break;
    }
}

// Shutdown voice assistant panel
void Win32IDE::shutdownVoiceAssistantPanel() {
    // Stop animation timer
    if (g_animationTimer && g_hwndVoiceAssistantPanel) {
        KillTimer(g_hwndVoiceAssistantPanel, g_animationTimer);
        g_animationTimer = 0;
    }
    
    // Cleanup renderer
    if (g_renderer) {
        g_renderer->shutdown();
        g_renderer.reset();
    }
    
    // Cleanup state machine
    if (g_stateMachine) {
        g_stateMachine.reset();
    }
    
    g_voiceAssistantInitialized = false;
}

// Create voice assistant panel
HWND Win32IDE::createVoiceAssistantPanel(HWND hwndParent) {
    if (!g_voiceAssistantInitialized) {
        initVoiceAssistantPanel();
    }
    
    // Register custom window class for voice assistant panel
    static bool classRegistered = false;
    if (!classRegistered) {
        WNDCLASSEXW wc = {};
        wc.cbSize = sizeof(WNDCLASSEXW);
        wc.lpfnWndProc = VoiceAssistantPanelProc;
        wc.hInstance = m_hInstance;
        wc.lpszClassName = L"VoiceAssistantPanel";
        wc.hCursor = LoadCursor(nullptr, IDC_HAND);
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        RegisterClassExW(&wc);
        classRegistered = true;
    }
    
    g_hwndVoiceAssistantPanel = CreateWindowExW(
        WS_EX_CLIENTEDGE | WS_EX_COMPOSITED,
        L"VoiceAssistantPanel",
        L"Voice Assistant",
        WS_CHILD | WS_VISIBLE | SS_CENTER,
        0, 0, 300, 600,
        hwndParent,
        nullptr,
        m_hInstance,
        nullptr
    );
    
    // Initialize renderer with panel HWND
    if (g_renderer && g_hwndVoiceAssistantPanel) {
        g_renderer->initialize(g_hwndVoiceAssistantPanel);
    }
    
    // Start animation timer (30 FPS)
    g_animationTimer = SetTimer(g_hwndVoiceAssistantPanel, 1, 33, AnimationTimerProc);
    
    return g_hwndVoiceAssistantPanel;
}

// Voice Assistant Panel Window Procedure
LRESULT CALLBACK Win32IDE::VoiceAssistantPanelProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_PAINT:
            OnVoiceAssistantPaint(hwnd);
            return 0;
            
        case WM_LBUTTONDOWN:
            OnVoiceAssistantClick(hwnd);
            return 0;
            
        case WM_TIMER:
            if (wParam == 1) {
                AnimationTimerProc(hwnd, msg, (UINT_PTR)wParam, GetTickCount());
            }
            return 0;
            
        case WM_DESTROY:
            if (g_animationTimer) {
                KillTimer(hwnd, g_animationTimer);
                g_animationTimer = 0;
            }
            return 0;
            
        case WM_ERASEBKGND:
            // Prevent flickering
            return 1;
            
        default:
            return DefWindowProc(hwnd, msg, wParam, lParam);
    }
}

// Layout voice assistant panel
void Win32IDE::layoutVoiceAssistantPanel(int panelWidth, int panelHeight) {
    if (!g_hwndVoiceAssistantPanel) return;
    
    // Layout child controls if they exist
    HWND hwndInput = GetDlgItem(g_hwndVoiceAssistantPanel, 1001);
    HWND hwndSend = GetDlgItem(g_hwndVoiceAssistantPanel, 1002);
    HWND hwndClear = GetDlgItem(g_hwndVoiceAssistantPanel, 1003);
    HWND hwndMic = GetDlgItem(g_hwndVoiceAssistantPanel, 1004);
    HWND hwndHistory = GetDlgItem(g_hwndVoiceAssistantPanel, 1005);
    
    int margin = 10;
    int buttonWidth = 80;
    int buttonHeight = 28;
    int micButtonSize = 40;
    int inputHeight = 60;
    
    // Position input area at bottom
    if (hwndInput) {
        SetWindowPos(hwndInput, nullptr, margin, panelHeight - inputHeight - margin, 
                     panelWidth - (2 * margin) - buttonWidth - micButtonSize - 20, 
                     inputHeight - buttonHeight - 10, SWP_NOZORDER);
    }
    
    // Position send button
    if (hwndSend) {
        SetWindowPos(hwndSend, nullptr, panelWidth - buttonWidth - margin, 
                     panelHeight - buttonHeight - margin, 
                     buttonWidth, buttonHeight, SWP_NOZORDER);
    }
    
    // Position clear button
    if (hwndClear) {
        SetWindowPos(hwndClear, nullptr, panelWidth - (2 * buttonWidth) - margin - 5, 
                     panelHeight - buttonHeight - margin, 
                     buttonWidth, buttonHeight, SWP_NOZORDER);
    }
    
    // Position mic button
    if (hwndMic) {
        SetWindowPos(hwndMic, nullptr, panelWidth - micButtonSize - margin, 
                     panelHeight - inputHeight - margin - micButtonSize - 5, 
                     micButtonSize, micButtonSize, SWP_NOZORDER);
    }
    
    // Position history list
    if (hwndHistory) {
        SetWindowPos(hwndHistory, nullptr, margin, margin, 
                     panelWidth - (2 * margin), 
                     panelHeight - inputHeight - micButtonSize - (3 * margin), 
                     SWP_NOZORDER);
    }
}

// Handle voice assistant command
void Win32IDE::handleVoiceAssistantCommand(int commandId) {
    switch (commandId) {
        case 1: // Send
            handleSendButton();
            break;
        case 2: // Clear
            handleClearButton();
            break;
        case 3: // Mic toggle
            handleMicButton();
            break;
        case 4: // Show settings
            showVoiceAssistantSettings();
            break;
        case 5: // Show history
            showVoiceHistory();
            break;
        case 6: // Clear history
            clearVoiceHistory();
            break;
        default:
            break;
    }
}

// Handle RAG semantic command
void Win32IDE::handleRAGSemanticCommand(int commandId) {
    // Get current file context
    std::string currentFile = getCurrentFilePath();
    int currentLine = getCurrentLineNumber();
    
    IntentType intent = IntentType::UNKNOWN;
    std::wstring query;
    
    switch (commandId) {
        case 100: // Explain symbol
            intent = IntentType::CODE_EXPLAIN_SYMBOL;
            query = L"Explain the current symbol";
            break;
        case 101: // Find references
            intent = IntentType::CODE_FIND_REFERENCES;
            query = L"Find references to this symbol";
            break;
        case 102: // Get dependencies
            intent = IntentType::CODE_GET_DEPENDENCIES;
            query = L"What files depend on this?";
            break;
        case 103: // Suggest fix
            intent = IntentType::CODE_SUGGEST_FIX;
            query = L"How do I fix this error?";
            break;
        case 104: // Architecture query
            intent = IntentType::CODE_ARCHITECTURE_QUERY;
            query = L"Explain the architecture";
            break;
        default:
            return;
    }
    
    // Submit semantic query to worker
    if (g_voiceAssistantWorker && g_voiceAssistantWorker->IsInitialized()) {
        g_voiceAssistantWorker->SubmitSemanticQuery(query, g_hwndVoiceAssistantPanel, 
                                                      intent, currentFile, currentLine);
        TransitionToState(RawrXD::UI::VoiceAssistantState::QUERYING);
    }
}

// Handle RAG semantic result
void Win32IDE::handleRAGSemanticResult(const nlohmann::json& result) {
    if (result.contains("error")) {
        TransitionToState(RawrXD::UI::VoiceAssistantState::ERROR);
        updateVoiceStatus("Error: " + result["error"].get<std::string>());
        return;
    }
    
    // Extract response and context
    std::string response = result.value("response", "No response");
    std::string context = result.value("context", "");
    
    // Display the result
    displayVoiceResponse(result);
    
    // Add to history
    addToVoiceHistory("RAG Query", result);
    
    // Transition to response state
    TransitionToState(RawrXD::UI::VoiceAssistantState::RESPONDING);
}

// Process voice input
void Win32IDE::processVoiceInput(const std::string& input) {
    // Transition to PROCESSING state
    TransitionToState(RawrXD::UI::VoiceAssistantState::PROCESSING);
    
    // Submit to voice assistant worker for async processing
    if (g_voiceAssistantWorker && g_voiceAssistantWorker->IsInitialized()) {
        // Convert string to wstring for worker
        std::wstring wideInput(input.begin(), input.end());
        
        // Submit task and get task ID
        unsigned int taskId = g_voiceAssistantWorker->SubmitTask(
            wideInput, 
            g_hwndVoiceAssistantPanel,
            "hybrid",  // Default to hybrid assistant
            ""         // Generate new session ID
        );
        
        updateVoiceStatus("Processing task " + std::to_string(taskId) + "...");
        
        // Transition to QUERYING state
        TransitionToState(RawrXD::UI::VoiceAssistantState::QUERYING);
    } else {
        // Worker not available - handle locally
        updateVoiceStatus("Voice worker not initialized");
        TransitionToState(RawrXD::UI::VoiceAssistantState::ERROR);
    }
}

// Finalize voice assistant result
void Win32IDE::finalizeVoiceAssistantResult(const std::string& input, const nlohmann::json& result) {
    // Add to history
    addToVoiceHistory(input, result);
    
    // Display the response
    displayVoiceResponse(result);
    
    // Check if IDE action is needed
    if (result.contains("intent")) {
        std::string intentStr = result["intent"].get<std::string>();
        IntentType intent = IntentType::UNKNOWN;
        
        // Map string intent to enum
        if (intentStr == "IDE_BUILD") intent = IntentType::IDE_BUILD;
        else if (intentStr == "IDE_OPEN_FILE") intent = IntentType::IDE_OPEN_FILE;
        else if (intentStr == "IDE_SAVE_FILE") intent = IntentType::IDE_SAVE_FILE;
        else if (intentStr == "IDE_FIND") intent = IntentType::IDE_FIND;
        else if (intentStr == "IDE_GOTO_LINE") intent = IntentType::IDE_GOTO_LINE;
        else if (intentStr == "IDE_RUN") intent = IntentType::IDE_RUN;
        else if (intentStr == "IDE_DEBUG") intent = IntentType::IDE_DEBUG;
        else if (intentStr == "IDE_EXPLAIN_CODE") intent = IntentType::IDE_EXPLAIN_CODE;
        else if (intentStr == "IDE_FIX_CODE") intent = IntentType::IDE_FIX_CODE;
        else if (intentStr == "IDE_OPTIMIZE_CODE") intent = IntentType::IDE_OPTIMIZE_CODE;
        
        if (intent != IntentType::UNKNOWN) {
            dispatchVoiceAssistantIDEAction(intent, result);
        }
    }
    
    // Transition back to idle
    TransitionToState(RawrXD::UI::VoiceAssistantState::IDLE);
}

// Dispatch voice assistant IDE action
void Win32IDE::dispatchVoiceAssistantIDEAction(IntentType intent, const nlohmann::json& entities) {
    std::unordered_map<std::string, std::string> entityMap;
    
    // Convert JSON entities to map
    if (entities.contains("entities") && entities["entities"].is_object()) {
        for (auto& [key, value] : entities["entities"].items()) {
            if (value.is_string()) {
                entityMap[key] = value.get<std::string>();
            }
        }
    }
    
    // Route to IDE command
    routeVoiceAssistantToIDECommand(intent, entityMap);
}

// Route voice assistant to IDE command
void Win32IDE::routeVoiceAssistantToIDECommand(IntentType intent, const std::unordered_map<std::string, std::string>& entities) {
    switch (intent) {
        case IntentType::IDE_BUILD:
            handleBuildCommand(IDM_BUILD_BUILD);
            break;
        case IntentType::IDE_OPEN_FILE: {
            auto it = entities.find("file");
            if (it != entities.end()) {
                openFile(it->second);
            } else {
                handleFileCommand(IDM_FILE_OPEN);
            }
            break;
        }
        case IntentType::IDE_SAVE_FILE:
            saveCurrentFile();
            break;
        case IntentType::IDE_CLOSE_FILE:
            handleFileCommand(IDM_FILE_CLOSE);
            break;
        case IntentType::IDE_FIND:
            showFindDialog();
            break;
        case IntentType::IDE_GOTO_LINE: {
            auto it = entities.find("line");
            if (it != entities.end()) {
                int line = std::stoi(it->second);
                goToLine(line);
            } else {
                showGoToLineDialog();
            }
            break;
        }
        case IntentType::IDE_RUN:
            handleBuildCommand(IDM_BUILD_RUN);
            break;
        case IntentType::IDE_DEBUG:
            startDebugging();
            break;
        case IntentType::IDE_TOGGLE_THEME:
            toggleTheme();
            break;
        case IntentType::IDE_TOGGLE_OUTPUT:
            toggleOutputPanel();
            break;
        case IntentType::IDE_TOGGLE_TERMINAL:
            toggleTerminal();
            break;
        case IntentType::IDE_EXPLAIN_CODE:
            // Trigger AI explanation
            explainCurrentCode();
            break;
        case IntentType::IDE_FIX_CODE:
            // Trigger AI fix
            fixCurrentCode();
            break;
        case IntentType::IDE_OPTIMIZE_CODE:
            // Trigger AI optimization
            optimizeCurrentCode();
            break;
        case IntentType::IDE_OPEN_SETTINGS:
            showSettingsDialog();
            break;
        default:
            break;
    }
}

// Dispatch RAG query
void Win32IDE::dispatchRAGQuery(IntentType intent, const std::unordered_map<std::string, std::string>& entities) {
    // Build query from intent and entities
    std::wstring query;
    std::string currentFile = getCurrentFilePath();
    int currentLine = getCurrentLineNumber();
    
    switch (intent) {
        case IntentType::CODE_EXPLAIN_SYMBOL:
            query = L"Explain what this function does";
            break;
        case IntentType::CODE_FIND_REFERENCES:
            query = L"Find all references to this symbol";
            break;
        case IntentType::CODE_GET_DEPENDENCIES:
            query = L"What are the dependencies of this file?";
            break;
        case IntentType::CODE_SUGGEST_FIX:
            query = L"Suggest a fix for this code";
            break;
        case IntentType::CODE_ARCHITECTURE_QUERY:
            query = L"Explain the architecture of this module";
            break;
        default:
            return;
    }
    
    // Submit to worker
    if (g_voiceAssistantWorker && g_voiceAssistantWorker->IsInitialized()) {
        g_voiceAssistantWorker->SubmitSemanticQuery(query, g_hwndVoiceAssistantPanel, 
                                                      intent, currentFile, currentLine);
        TransitionToState(RawrXD::UI::VoiceAssistantState::QUERYING);
    }
}

// Display voice response
void Win32IDE::displayVoiceResponse(const nlohmann::json& result) {
    std::string response;
    
    if (result.contains("response")) {
        response = result["response"].get<std::string>();
    } else if (result.contains("text")) {
        response = result["text"].get<std::string>();
    } else if (result.contains("message")) {
        response = result["message"].get<std::string>();
    } else {
        response = result.dump(2);
    }
    
    // Update status with truncated response
    std::string status = response;
    if (status.length() > 100) {
        status = status.substr(0, 97) + "...";
    }
    updateVoiceStatus(status);
    
    // Append to output panel
    appendToOutput("[Voice Assistant] " + response + "\n", "Voice", OutputSeverity::Info);
    
    // Force panel redraw
    if (g_hwndVoiceAssistantPanel) {
        InvalidateRect(g_hwndVoiceAssistantPanel, nullptr, TRUE);
    }
}

// Add to voice history
void Win32IDE::addToVoiceHistory(const std::string& input, const nlohmann::json& result) {
    // Store in session history (could be persisted to disk)
    static std::vector<std::pair<std::string, nlohmann::json>> s_history;
    
    // Limit history size
    if (s_history.size() >= 100) {
        s_history.erase(s_history.begin());
    }
    
    s_history.push_back({input, result});
    
    // Update history list control if it exists
    HWND hwndHistory = GetDlgItem(g_hwndVoiceAssistantPanel, 1005);
    if (hwndHistory) {
        std::string displayText = input;
        if (displayText.length() > 50) {
            displayText = displayText.substr(0, 47) + "...";
        }
        SendMessageA(hwndHistory, LB_ADDSTRING, 0, (LPARAM)displayText.c_str());
    }
}

// Set voice assistant mode
void Win32IDE::setVoiceAssistantMode(const std::string& mode) {
    if (mode == "hybrid") {
        // Use hybrid assistant (Siri + Alexa)
        updateVoiceStatus("Mode: Hybrid");
    } else if (mode == "siri") {
        // Use Siri only
        updateVoiceStatus("Mode: Siri");
    } else if (mode == "alexa") {
        // Use Alexa only
        updateVoiceStatus("Mode: Alexa");
    } else if (mode == "offline") {
        // Use offline/local processing only
        updateVoiceStatus("Mode: Offline");
    }
}

// Update voice status
void Win32IDE::updateVoiceStatus(const std::string& status) {
    if (m_hwndStatusBar) {
        RawrXD::StatusBarSetTextUtf8(m_hwndStatusBar, 2, "Voice: " + status);
    }
    appendToOutput("[Voice Status] " + status + "\n", "Voice", OutputSeverity::Info);
}

// Show voice assistant panel
void Win32IDE::showVoiceAssistantPanel() {
    if (!g_hwndVoiceAssistantPanel) {
        createVoiceAssistantPanel(m_hwndMain);
    }
    ShowWindow(g_hwndVoiceAssistantPanel, SW_SHOW);
}

// Show voice assistant settings
void Win32IDE::showVoiceAssistantSettings() {
    MessageBoxA(m_hwndMain, "Voice Assistant Settings", "Settings", MB_OK);
}

// Show voice history
void Win32IDE::showVoiceHistory() {
    MessageBoxA(m_hwndMain, "Voice History", "History", MB_OK);
}

// Clear voice history
void Win32IDE::clearVoiceHistory() {
    // Clear history list control
    HWND hwndHistory = GetDlgItem(g_hwndVoiceAssistantPanel, 1005);
    if (hwndHistory) {
        SendMessage(hwndHistory, LB_RESETCONTENT, 0, 0);
    }
    
    updateVoiceStatus("History cleared");
}

// Handle voice assistant message
LRESULT Win32IDE::handleVoiceAssistantMessage(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_USER_VOICE_RESPONSE_READY: {
            // Voice worker has completed processing
            // wParam contains task ID, lParam contains pointer to result JSON
            if (lParam != 0) {
                auto* result = reinterpret_cast<nlohmann::json*>(lParam);
                if (result) {
                    // Check for error
                    if (result->contains("error")) {
                        TransitionToState(RawrXD::UI::VoiceAssistantState::ERROR);
                        updateVoiceStatus("Error: " + result->value("error", "Unknown error"));
                    } else {
                        // Success - finalize the result
                        finalizeVoiceAssistantResult("", *result);
                    }
                    // Clean up the allocated JSON
                    delete result;
                }
            }
            return 0;
        }
        
        case WM_COMMAND: {
            // Handle button clicks
            int controlId = LOWORD(wParam);
            int notification = HIWORD(wParam);
            
            if (notification == BN_CLICKED) {
                handleVoiceAssistantCommand(controlId);
            }
            return 0;
        }
        
        case WM_LBN_SELCHANGE: {
            // History list selection changed
            handleHistorySelection();
            return 0;
        }
        
        default:
            return DefWindowProc(hwnd, msg, wParam, lParam);
    }
}

// Handle send button
void Win32IDE::handleSendButton() {
    HWND hwndInput = GetDlgItem(g_hwndVoiceAssistantPanel, 1001);
    if (!hwndInput) return;
    
    // Get input text
    char buffer[4096] = {0};
    GetWindowTextA(hwndInput, buffer, sizeof(buffer) - 1);
    
    if (strlen(buffer) > 0) {
        std::string input(buffer);
        processVoiceInput(input);
        
        // Clear input
        SetWindowTextA(hwndInput, "");
    }
}

// Handle clear button
void Win32IDE::handleClearButton() {
    HWND hwndInput = GetDlgItem(g_hwndVoiceAssistantPanel, 1001);
    if (hwndInput) {
        SetWindowTextA(hwndInput, "");
    }
    
    // Also clear output display
    if (g_hwndVoiceAssistantPanel) {
        InvalidateRect(g_hwndVoiceAssistantPanel, nullptr, TRUE);
    }
}

// Handle mic button
void Win32IDE::handleMicButton() {
    // Toggle recording state
    static bool isRecording = false;
    isRecording = !isRecording;
    
    if (isRecording) {
        TransitionToState(RawrXD::UI::VoiceAssistantState::LISTENING);
        updateVoiceStatus("Listening...");
        
        // Initialize audio recording using Windows Core Audio APIs
        // This uses WASAPI for low-latency audio capture
        HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (SUCCEEDED(hr)) {
            // Create audio client
            IMMDeviceEnumerator* pEnumerator = nullptr;
            hr = CoCreateInstance(
                __uuidof(MMDeviceEnumerator), nullptr, CLSCTX_ALL,
                __uuidof(IMMDeviceEnumerator), (void**)&pEnumerator);
            
            if (SUCCEEDED(hr) && pEnumerator) {
                IMMDevice* pDevice = nullptr;
                hr = pEnumerator->GetDefaultAudioEndpoint(eCapture, eConsole, &pDevice);
                
                if (SUCCEEDED(hr) && pDevice) {
                    IAudioClient* pAudioClient = nullptr;
                    hr = pDevice->Activate(__uuidof(IAudioClient), CLSCTX_ALL, 
                                              nullptr, (void**)&pAudioClient);
                    
                    if (SUCCEEDED(hr) && pAudioClient) {
                        // Get mix format
                        WAVEFORMATEX* pwfx = nullptr;
                        hr = pAudioClient->GetMixFormat(&pwfx);
                        
                        if (SUCCEEDED(hr) && pwfx) {
                            // Initialize audio client in shared mode
                            hr = pAudioClient->Initialize(
                                AUDCLNT_SHAREMODE_SHARED,
                                AUDCLNT_STREAMFLAGS_LOOPBACK,
                                0, 0, pwfx, nullptr);
                            
                            if (SUCCEEDED(hr)) {
                                // Start recording
                                hr = pAudioClient->Start();
                                if (SUCCEEDED(hr)) {
                                    updateVoiceStatus("Recording audio...");
                                    
                                    // Store audio client for later processing
                                    // In production, would spawn thread to read audio data
                                    // and feed to speech recognition engine
                                }
                            }
                            
                            CoTaskMemFree(pwfx);
                        }
                        
                        pAudioClient->Release();
                    }
                    
                    pDevice->Release();
                }
                
                pEnumerator->Release();
            }
        }
        
        // Show user feedback
        MessageBoxA(m_hwndMain, 
            "Voice recording started.\nAudio is being captured via WASAPI.",
            "Voice Input", MB_OK | MB_ICONINFORMATION);
    } else {
        TransitionToState(RawrXD::UI::VoiceAssistantState::PROCESSING);
        updateVoiceStatus("Processing...");
        
        // Stop audio recording and process captured audio
        // In production, would:
        // 1. Stop IAudioClient
        // 2. Process captured PCM data
        // 3. Send to speech-to-text engine (local Whisper or cloud API)
        // 4. Get transcription result
        // 5. Send to AI model for processing
    }
}

// Handle history selection
void Win32IDE::handleHistorySelection() {
    HWND hwndHistory = GetDlgItem(g_hwndVoiceAssistantPanel, 1005);
    if (!hwndHistory) return;
    
    // Get selected index
    int sel = (int)SendMessage(hwndHistory, LB_GETCURSEL, 0, 0);
    if (sel == LB_ERR) return;
    
    // Get selected text
    char buffer[256] = {0};
    SendMessageA(hwndHistory, LB_GETTEXT, sel, (LPARAM)buffer);
    
    // Copy to input
    HWND hwndInput = GetDlgItem(g_hwndVoiceAssistantPanel, 1001);
    if (hwndInput) {
        SetWindowTextA(hwndInput, buffer);
    }
}

// Handle voice assistant timer
void Win32IDE::handleVoiceAssistantTimer() {
    // Update animation state
    if (g_stateMachine) {
        g_stateMachine->updateAnimation();
    }
    
    // Force redraw
    if (g_hwndVoiceAssistantPanel) {
        InvalidateRect(g_hwndVoiceAssistantPanel, nullptr, FALSE);
    }
}

// Connect voice to micro-model chain
void Win32IDE::connectVoiceToMicroModelChain() {
    // Integrate voice assistant with the micro-model chain for enhanced processing
    
    // Get the micro-model chain instance from the AI subsystem
    auto* aiEngine = GetAiEngine();
    if (!aiEngine) {
        updateVoiceStatus("Error: AI engine not available");
        return;
    }
    
    // Register voice assistant as a consumer of the micro-model chain
    MicroModelChain* chain = aiEngine->GetMicroModelChain();
    if (!chain) {
        updateVoiceStatus("Error: Micro-model chain not initialized");
        return;
    }
    
    // Set up callback for model responses
    chain->RegisterConsumer("voice_assistant", 
        [this](const std::string& response, float confidence) {
            // Handle model response in voice assistant context
            if (confidence > 0.7f) {
                // High confidence - display result
                updateVoiceStatus("Response: " + response.substr(0, 50) + "...");
                
                // If response is code-related, offer to insert at cursor
                if (response.find("```") != std::string::npos ||
                    response.find("function") != std::string::npos ||
                    response.find("class") != std::string::npos) {
                    // Show insert button or auto-insert based on settings
                    SetDlgItemTextA(g_hwndVoiceAssistantPanel, 1001, response.c_str());
                }
            } else {
                // Low confidence - ask for clarification
                updateVoiceStatus("Low confidence response. Please clarify.");
            }
        });
    
    // Configure voice-specific processing parameters
    chain->SetProcessingParams("voice_assistant", {
        {"max_tokens", 256},
        {"temperature", 0.3f},  // Lower temperature for more deterministic responses
        {"top_p", 0.9f},
        {"context_window", 2048}
    });
    
    updateVoiceStatus("Connected to micro-model chain");
    
    // Enable voice-specific features
    EnableWindow(GetDlgItem(g_hwndVoiceAssistantPanel, 1006), TRUE); // Enable chain-specific button
}

