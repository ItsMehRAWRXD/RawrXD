// Win32IDE_VoiceAssistantPanel.cpp - Voice Assistant Panel with State Machine
// Sprint 02: UI/UX Enhancement - GDI+ Integration

#include "Win32IDE.h"
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
    // Stub implementation
}

// Handle voice assistant command
void Win32IDE::handleVoiceAssistantCommand(int commandId) {
    // Stub implementation
}

// Handle RAG semantic command
void Win32IDE::handleRAGSemanticCommand(int commandId) {
    // Stub implementation
}

// Handle RAG semantic result
void Win32IDE::handleRAGSemanticResult(const nlohmann::json& result) {
    // Stub implementation
}

// Process voice input
void Win32IDE::processVoiceInput(const std::string& input) {
    // Transition to PROCESSING state
    TransitionToState(RawrXD::UI::VoiceAssistantState::PROCESSING);
    
    // TODO: Integrate with VoiceAssistantManager for actual processing
    // For now, simulate processing and transition to QUERYING
    
    // In production, this would:
    // 1. Call VoiceAssistantManager::process_voice_input()
    // 2. Handle the result
    // 3. Transition to appropriate state based on result
    
    // Simulate async processing
    // TransitionToState(RawrXD::UI::VoiceAssistantState::QUERYING);
}

// Finalize voice assistant result
void Win32IDE::finalizeVoiceAssistantResult(const std::string& input, const nlohmann::json& result) {
    // Stub implementation
}

// Dispatch voice assistant IDE action
void Win32IDE::dispatchVoiceAssistantIDEAction(IntentType intent, const nlohmann::json& entities) {
    // Stub implementation
}

// Route voice assistant to IDE command
void Win32IDE::routeVoiceAssistantToIDECommand(IntentType intent, const std::unordered_map<std::string, std::string>& entities) {
    // Stub implementation
}

// Dispatch RAG query
void Win32IDE::dispatchRAGQuery(IntentType intent, const std::unordered_map<std::string, std::string>& entities) {
    // Stub implementation
}

// Display voice response
void Win32IDE::displayVoiceResponse(const nlohmann::json& result) {
    // Stub implementation
}

// Add to voice history
void Win32IDE::addToVoiceHistory(const std::string& input, const nlohmann::json& result) {
    // Stub implementation
}

// Set voice assistant mode
void Win32IDE::setVoiceAssistantMode(const std::string& mode) {
    // Stub implementation
}

// Update voice status
void Win32IDE::updateVoiceStatus(const std::string& status) {
    // Stub implementation
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
    // Stub implementation
}

// Handle voice assistant message
LRESULT Win32IDE::handleVoiceAssistantMessage(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

// Handle send button
void Win32IDE::handleSendButton() {
    // Stub implementation
}

// Handle clear button
void Win32IDE::handleClearButton() {
    // Stub implementation
}

// Handle mic button
void Win32IDE::handleMicButton() {
    // Stub implementation
}

// Handle history selection
void Win32IDE::handleHistorySelection() {
    // Stub implementation
}

// Handle voice assistant timer
void Win32IDE::handleVoiceAssistantTimer() {
    // Stub implementation
}

// Connect voice to micro-model chain
void Win32IDE::connectVoiceToMicroModelChain() {
    // Stub implementation
}

