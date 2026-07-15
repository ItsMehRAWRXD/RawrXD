// VoiceAssistantState.cpp - State Machine Implementation
// Sprint 02: UI/UX Enhancement
// ============================================================================

#include <Windows.h>
#include <objidl.h>
#include <gdiplus.h>
#include "ui/VoiceAssistantState.hpp"

#pragma comment(lib, "gdiplus.lib")

using namespace Gdiplus;

namespace RawrXD {
namespace UI {

// ============================================================================
// VoiceAssistantStateMachine Implementation
// ============================================================================

VoiceAssistantStateMachine::VoiceAssistantStateMachine()
    : m_currentState(VoiceAssistantState::IDLE)
    , m_previousState(VoiceAssistantState::IDLE)
    , m_animationProgress(0.0f)
    , m_lastUpdateTime(GetTickCount())
{
}

VoiceAssistantStateMachine::~VoiceAssistantStateMachine() = default;

void VoiceAssistantStateMachine::transitionTo(VoiceAssistantState newState) {
    if (!canTransition(m_currentState, newState)) {
        return; // Invalid transition
    }
    
    m_previousState = m_currentState;
    m_currentState = newState;
    m_animationProgress = 0.0f;
    
    if (m_transitionCallback) {
        m_transitionCallback(m_previousState, m_currentState);
    }
}

std::string VoiceAssistantStateMachine::getStateName() const {
    return std::string(RawrXD::UI::getStateName(m_currentState));
}

void VoiceAssistantStateMachine::handleEvent(StateEvent event) {
    VoiceAssistantState nextState = getNextState(event);
    if (nextState != m_currentState) {
        transitionTo(nextState);
    }
}

void VoiceAssistantStateMachine::setTransitionCallback(StateTransitionCallback callback) {
    m_transitionCallback = callback;
}

void VoiceAssistantStateMachine::setRenderCallback(StateRenderCallback callback) {
    m_renderCallback = callback;
}

void VoiceAssistantStateMachine::render(HDC hdc, const RECT& panelRect) {
    if (m_renderCallback) {
        m_renderCallback(hdc, panelRect, m_currentState);
    }
}

void VoiceAssistantStateMachine::updateAnimation() {
    DWORD currentTime = GetTickCount();
    float deltaTime = (currentTime - m_lastUpdateTime) / 1000.0f;
    m_lastUpdateTime = currentTime;
    
    // Update animation progress (0.0 to 1.0, looping)
    m_animationProgress += deltaTime * 2.0f; // 2 second cycle
    if (m_animationProgress > 1.0f) {
        m_animationProgress -= 1.0f;
    }
}

bool VoiceAssistantStateMachine::canTransition(VoiceAssistantState from, VoiceAssistantState to) {
    // Define valid state transitions
    switch (from) {
        case VoiceAssistantState::IDLE:
            return to == VoiceAssistantState::LISTENING || 
                   to == VoiceAssistantState::PROCESSING ||
                   to == VoiceAssistantState::ERROR;
            
        case VoiceAssistantState::LISTENING:
            return to == VoiceAssistantState::PROCESSING || 
                   to == VoiceAssistantState::IDLE ||
                   to == VoiceAssistantState::ERROR;
            
        case VoiceAssistantState::PROCESSING:
            return to == VoiceAssistantState::QUERYING || 
                   to == VoiceAssistantState::RESPONDING ||
                   to == VoiceAssistantState::IDLE ||
                   to == VoiceAssistantState::ERROR;
            
        case VoiceAssistantState::QUERYING:
            return to == VoiceAssistantState::RESPONDING || 
                   to == VoiceAssistantState::IDLE ||
                   to == VoiceAssistantState::ERROR;
            
        case VoiceAssistantState::RESPONDING:
            return to == VoiceAssistantState::IDLE || 
                   to == VoiceAssistantState::LISTENING ||
                   to == VoiceAssistantState::ERROR;
            
        case VoiceAssistantState::ERROR:
            return to == VoiceAssistantState::IDLE || 
                   to == VoiceAssistantState::LISTENING;
            
        default:
            return false;
    }
}

VoiceAssistantState VoiceAssistantStateMachine::getNextState(StateEvent event) {
    switch (m_currentState) {
        case VoiceAssistantState::IDLE:
            if (event == StateEvent::USER_CLICKED_MIC) return VoiceAssistantState::LISTENING;
            if (event == StateEvent::VOICE_INPUT_RECEIVED) return VoiceAssistantState::PROCESSING;
            break;
            
        case VoiceAssistantState::LISTENING:
            if (event == StateEvent::VOICE_INPUT_RECEIVED) return VoiceAssistantState::PROCESSING;
            if (event == StateEvent::TIMEOUT || event == StateEvent::USER_CANCELLED) return VoiceAssistantState::IDLE;
            break;
            
        case VoiceAssistantState::PROCESSING:
            if (event == StateEvent::RAG_QUERY_STARTED) return VoiceAssistantState::QUERYING;
            if (event == StateEvent::RESPONSE_READY) return VoiceAssistantState::RESPONDING;
            if (event == StateEvent::ERROR_OCCURRED) return VoiceAssistantState::ERROR;
            break;
            
        case VoiceAssistantState::QUERYING:
            if (event == StateEvent::RAG_QUERY_COMPLETED) return VoiceAssistantState::RESPONDING;
            if (event == StateEvent::ERROR_OCCURRED) return VoiceAssistantState::ERROR;
            break;
            
        case VoiceAssistantState::RESPONDING:
            if (event == StateEvent::USER_CLICKED_MIC) return VoiceAssistantState::LISTENING;
            if (event == StateEvent::TIMEOUT) return VoiceAssistantState::IDLE;
            break;
            
        case VoiceAssistantState::ERROR:
            if (event == StateEvent::USER_CLICKED_MIC) return VoiceAssistantState::LISTENING;
            if (event == StateEvent::TIMEOUT) return VoiceAssistantState::IDLE;
            break;
            
        default:
            break;
    }
    
    return m_currentState; // No state change
}

// ============================================================================
// VoiceAssistantRenderer Implementation
// ============================================================================

VoiceAssistantRenderer::VoiceAssistantRenderer()
    : m_hwnd(nullptr)
    , m_initialized(false)
    , m_graphics(nullptr)
    , m_font(nullptr)
    , m_brush(nullptr)
    , m_idleColor(RGB(100, 100, 100))
    , m_listeningColor(RGB(0, 150, 255))
    , m_processingColor(RGB(255, 165, 0))
    , m_errorColor(RGB(255, 50, 50))
{
}

VoiceAssistantRenderer::~VoiceAssistantRenderer() {
    shutdown();
}

bool VoiceAssistantRenderer::initialize(HWND hwnd) {
    if (m_initialized) return true;
    
    m_hwnd = hwnd;
    
    // Initialize GDI+
    GdiplusStartupInput input;
    GdiplusStartupOutput output;
    input.GdiplusVersion = 1;
    input.DebugEventCallback = nullptr;
    input.SuppressBackgroundThread = FALSE;
    input.SuppressExternalCodecs = FALSE;
    
    GdiplusStartup(&m_gdiplusToken, &input, &output);
    
    m_initialized = true;
    return true;
}

void VoiceAssistantRenderer::shutdown() {
    if (!m_initialized) return;
    
    // Cleanup GDI+ resources
    if (m_graphics) { delete static_cast<Graphics*>(m_graphics); m_graphics = nullptr; }
    if (m_font) { delete static_cast<Font*>(m_font); m_font = nullptr; }
    if (m_brush) { delete static_cast<SolidBrush*>(m_brush); m_brush = nullptr; }
    
    GdiplusShutdown(m_gdiplusToken);
    m_initialized = false;
}

void VoiceAssistantRenderer::renderState(HDC hdc, const RECT& panelRect, 
    VoiceAssistantState state, float animationProgress) {
    
    if (!m_initialized) return;
    
    switch (state) {
        case VoiceAssistantState::IDLE:
            renderIdle(hdc, panelRect, animationProgress);
            break;
        case VoiceAssistantState::LISTENING:
            renderListening(hdc, panelRect, animationProgress);
            break;
        case VoiceAssistantState::PROCESSING:
            renderProcessing(hdc, panelRect, animationProgress);
            break;
        case VoiceAssistantState::QUERYING:
            renderQuerying(hdc, panelRect, animationProgress);
            break;
        case VoiceAssistantState::RESPONDING:
            renderResponding(hdc, panelRect, animationProgress);
            break;
        case VoiceAssistantState::ERROR:
            renderError(hdc, panelRect, animationProgress);
            break;
    }
}

void VoiceAssistantRenderer::renderIdle(HDC hdc, const RECT& panelRect, float animationProgress) {
    // Subtle pulse effect in gray
    float intensity = 0.3f + (sinf(animationProgress * 3.14159f * 2.0f) * 0.1f);
    drawPulseEffect(hdc, panelRect, m_idleColor, intensity);
    drawStatusText(hdc, panelRect, L"Voice Assistant Ready", m_idleColor);
}

void VoiceAssistantRenderer::renderListening(HDC hdc, const RECT& panelRect, float animationProgress) {
    // High-frequency amplitude visualization in blue
    float amplitude = 0.5f + (sinf(animationProgress * 3.14159f * 8.0f) * 0.4f);
    drawAmplitudeBars(hdc, panelRect, amplitude);
    drawStatusText(hdc, panelRect, L"Listening...", m_listeningColor);
}

void VoiceAssistantRenderer::renderProcessing(HDC hdc, const RECT& panelRect, float animationProgress) {
    // Orange pulse effect
    float intensity = 0.4f + (sinf(animationProgress * 3.14159f * 4.0f) * 0.2f);
    drawPulseEffect(hdc, panelRect, m_processingColor, intensity);
    drawProgressIndicator(hdc, panelRect, animationProgress);
    drawStatusText(hdc, panelRect, L"Processing...", m_processingColor);
}

void VoiceAssistantRenderer::renderQuerying(HDC hdc, const RECT& panelRect, float animationProgress) {
    // Progress indicator with "Searching Knowledge Base..."
    drawProgressIndicator(hdc, panelRect, animationProgress);
    drawStatusText(hdc, panelRect, L"Searching Knowledge Base...", m_processingColor);
}

void VoiceAssistantRenderer::renderResponding(HDC hdc, const RECT& panelRect, float animationProgress) {
    // Display response with fade-in effect
    drawStatusText(hdc, panelRect, L"Response Ready", RGB(50, 200, 50));
}

void VoiceAssistantRenderer::renderError(HDC hdc, const RECT& panelRect, float animationProgress) {
    // Red notification
    drawPulseEffect(hdc, panelRect, m_errorColor, 0.5f);
    drawStatusText(hdc, panelRect, L"Error Occurred", m_errorColor);
}

void VoiceAssistantRenderer::drawPulseEffect(HDC hdc, const RECT& rect, COLORREF color, float intensity) {
    // Create pulse effect using alpha blending
    int alpha = static_cast<int>(255 * intensity);
    
    HBRUSH brush = CreateSolidBrush(color);
    
    // Draw expanding circles or glow effect
    int centerX = (rect.left + rect.right) / 2;
    int centerY = (rect.top + rect.bottom) / 2;
    int radius = static_cast<int>(20 + (intensity * 30));
    
    // Simple pulse visualization (placeholder for GDI+ implementation)
    RECT pulseRect = {
        centerX - radius,
        centerY - radius,
        centerX + radius,
        centerY + radius
    };
    
    FillRect(hdc, &pulseRect, brush);
    DeleteObject(brush);
}

void VoiceAssistantRenderer::drawAmplitudeBars(HDC hdc, const RECT& rect, float amplitude) {
    // Draw audio amplitude visualization
    int barCount = 8;
    int barWidth = 8;
    int barSpacing = 4;
    int maxBarHeight = (rect.bottom - rect.top) / 3;
    
    int startX = ((rect.left + rect.right) / 2) - ((barCount * (barWidth + barSpacing)) / 2);
    int baseY = (rect.top + rect.bottom) / 2;
    
    HBRUSH brush = CreateSolidBrush(m_listeningColor);
    
    for (int i = 0; i < barCount; i++) {
        // Vary bar height based on position and amplitude
        float barAmplitude = amplitude * (0.5f + 0.5f * sinf((i / static_cast<float>(barCount)) * 3.14159f));
        int barHeight = static_cast<int>(maxBarHeight * barAmplitude);
        
        RECT barRect = {
            startX + i * (barWidth + barSpacing),
            baseY - barHeight / 2,
            startX + i * (barWidth + barSpacing) + barWidth,
            baseY + barHeight / 2
        };
        
        FillRect(hdc, &barRect, brush);
    }
    
    DeleteObject(brush);
}

void VoiceAssistantRenderer::drawProgressIndicator(HDC hdc, const RECT& rect, float progress) {
    // Draw circular or linear progress indicator
    int barWidth = (rect.right - rect.left) - 40;
    int barHeight = 8;
    int barX = rect.left + 20;
    int barY = rect.bottom - 40;
    
    // Background bar
    RECT bgRect = { barX, barY, barX + barWidth, barY + barHeight };
    HBRUSH bgBrush = CreateSolidBrush(RGB(60, 60, 60));
    FillRect(hdc, &bgRect, bgBrush);
    DeleteObject(bgBrush);
    
    // Progress bar
    int progressWidth = static_cast<int>(barWidth * progress);
    RECT progressRect = { barX, barY, barX + progressWidth, barY + barHeight };
    HBRUSH progressBrush = CreateSolidBrush(m_processingColor);
    FillRect(hdc, &progressRect, progressBrush);
    DeleteObject(progressBrush);
}

void VoiceAssistantRenderer::drawStatusText(HDC hdc, const RECT& rect, const std::wstring& text, COLORREF color) {
    // Draw status text centered in the panel
    SetTextColor(hdc, color);
    SetBkMode(hdc, TRANSPARENT);
    
    HFONT font = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    
    HFONT oldFont = (HFONT)SelectObject(hdc, font);
    
    RECT textRect = rect;
    textRect.top = rect.bottom - 80;
    textRect.bottom = rect.bottom - 50;
    
    DrawTextW(hdc, text.c_str(), -1, &textRect, 
        DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    
    SelectObject(hdc, oldFont);
    DeleteObject(font);
}

} // namespace UI
} // namespace RawrXD
