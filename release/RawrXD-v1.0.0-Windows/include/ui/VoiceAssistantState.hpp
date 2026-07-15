// VoiceAssistantState.hpp - State Machine for Voice Assistant UI
// Sprint 02: UI/UX Enhancement - State-Driven Architecture
// ============================================================================

#pragma once

#include <Windows.h>
#include <functional>
#include <string>

// Undefine Windows ERROR macro to avoid conflict with enum class
#ifdef ERROR
#undef ERROR
#endif

namespace RawrXD {
namespace UI {

// ============================================================================
// Voice Assistant States
// ============================================================================

enum class VoiceAssistantState {
    IDLE,           // Minimal UI, standby pulse
    LISTENING,      // High-frequency amplitude visualization
    PROCESSING,     // Subtle pulse effects during processing
    QUERYING,       // "Searching Knowledge Base..." animation
    RESPONDING,     // Displaying results
    ERROR           // Subtle red notification/tooltip
};

// ============================================================================
// State Event Types
// ============================================================================

enum class StateEvent {
    USER_CLICKED_MIC,
    VOICE_INPUT_RECEIVED,
    RAG_QUERY_STARTED,
    RAG_QUERY_COMPLETED,
    RESPONSE_READY,
    ERROR_OCCURRED,
    TIMEOUT,
    USER_CANCELLED
};

// ============================================================================
// State Transition Handler
// ============================================================================

using StateTransitionCallback = std::function<void(VoiceAssistantState oldState, VoiceAssistantState newState)>;
using StateRenderCallback = std::function<void(HDC hdc, const RECT& panelRect, VoiceAssistantState state)>;

// ============================================================================
// Voice Assistant State Machine
// ============================================================================

class VoiceAssistantStateMachine {
public:
    VoiceAssistantStateMachine();
    ~VoiceAssistantStateMachine();
    
    // State Management
    void transitionTo(VoiceAssistantState newState);
    VoiceAssistantState getCurrentState() const { return m_currentState; }
    std::string getStateName() const;
    
    // Event Handling
    void handleEvent(StateEvent event);
    
    // Callbacks
    void setTransitionCallback(StateTransitionCallback callback);
    void setRenderCallback(StateRenderCallback callback);
    
    // Rendering
    void render(HDC hdc, const RECT& panelRect);
    
    // Animation
    void updateAnimation(); // Call from timer
    float getAnimationProgress() const { return m_animationProgress; }
    
    // State-specific properties
    bool isActive() const { return m_currentState != VoiceAssistantState::IDLE; }
    bool isProcessing() const { 
        return m_currentState == VoiceAssistantState::PROCESSING || 
               m_currentState == VoiceAssistantState::QUERYING; 
    }
    
private:
    VoiceAssistantState m_currentState;
    VoiceAssistantState m_previousState;
    
    StateTransitionCallback m_transitionCallback;
    StateRenderCallback m_renderCallback;
    
    // Animation
    float m_animationProgress;
    DWORD m_lastUpdateTime;
    
    // State transition validation
    bool canTransition(VoiceAssistantState from, VoiceAssistantState to);
    VoiceAssistantState getNextState(StateEvent event);
};

// ============================================================================
// State Renderer (GDI+ Implementation)
// ============================================================================

class VoiceAssistantRenderer {
public:
    VoiceAssistantRenderer();
    ~VoiceAssistantRenderer();
    
    // Initialization
    bool initialize(HWND hwnd);
    void shutdown();
    
    // Rendering
    void renderState(HDC hdc, const RECT& panelRect, VoiceAssistantState state, float animationProgress);
    
    // State-specific renders
    void renderIdle(HDC hdc, const RECT& panelRect, float animationProgress);
    void renderListening(HDC hdc, const RECT& panelRect, float animationProgress);
    void renderProcessing(HDC hdc, const RECT& panelRect, float animationProgress);
    void renderQuerying(HDC hdc, const RECT& panelRect, float animationProgress);
    void renderResponding(HDC hdc, const RECT& panelRect, float animationProgress);
    void renderError(HDC hdc, const RECT& panelRect, float animationProgress);
    
    // Visual effects
    void drawPulseEffect(HDC hdc, const RECT& rect, COLORREF color, float intensity);
    void drawAmplitudeBars(HDC hdc, const RECT& rect, float amplitude);
    void drawProgressIndicator(HDC hdc, const RECT& rect, float progress);
    void drawStatusText(HDC hdc, const RECT& rect, const std::wstring& text, COLORREF color);
    
private:
    HWND m_hwnd;
    bool m_initialized;
    
    // GDI+ resources
    void* m_graphics; // Gdiplus::Graphics*
    void* m_font;     // Gdiplus::Font*
    void* m_brush;    // Gdiplus::SolidBrush*
    ULONG_PTR m_gdiplusToken; // GDI+ initialization token
    
    // Animation resources
    COLORREF m_idleColor;
    COLORREF m_listeningColor;
    COLORREF m_processingColor;
    COLORREF m_errorColor;
};

// ============================================================================
// State Names for Debugging
// ============================================================================

inline const char* getStateName(VoiceAssistantState state) {
    switch (state) {
        case VoiceAssistantState::IDLE: return "IDLE";
        case VoiceAssistantState::LISTENING: return "LISTENING";
        case VoiceAssistantState::PROCESSING: return "PROCESSING";
        case VoiceAssistantState::QUERYING: return "QUERYING";
        case VoiceAssistantState::RESPONDING: return "RESPONDING";
        case VoiceAssistantState::ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

} // namespace UI
} // namespace RawrXD
