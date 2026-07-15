// StepController.cpp
// Phase 24C: Stepping Controls - Implementation
// ============================================================================

#include "StepController.hpp"
#include <windowsx.h>
#include <commctrl.h>

#pragma comment(lib, "comctl32.lib")

namespace RawrXD {
namespace Debug {
namespace UI {

// ============================================================================
// StepController Implementation
// ============================================================================
StepController::StepController() = default;
StepController::~StepController() = default;

void StepController::AttachToDapService(DapService* service) {
    dapService_ = service;
    
    // Wire up DAP callbacks
    dapService_>onStopped([this](const std::string& reason, uint32_t threadId, 
                                   const std::string& description) {
        HandleStopped(reason, threadId);
    });
    
    dapService_>onError([this](const std::string& error, bool fatal) {
        HandleError(error);
    });
}

void StepController::Detach() {
    dapService_ = nullptr;
}

void StepController::StepOver(uint32_t threadId) {
    if (!dapService_ || state_ == StepState::Stepping) return;
    
    state_ = StepState::Stepping;
    lastStepType_ = StepType::Over;
    currentThreadId_ = threadId;
    stepStartTime_ = std::chrono::steady_clock::now();
    
    if (onStepStarted) {
        onStepStarted(StepType::Over);
    }
    
    dapService_>stepOver(threadId);
}

void StepController::StepInto(uint32_t threadId) {
    if (!dapService_ || state_ == StepState::Stepping) return;
    
    state_ = StepState::Stepping;
    lastStepType_ = StepType::Into;
    currentThreadId_ = threadId;
    stepStartTime_ = std::chrono::steady_clock::now();
    
    if (onStepStarted) {
        onStepStarted(StepType::Into);
    }
    
    dapService_>stepInto(threadId);
}

void StepController::StepOut(uint32_t threadId) {
    if (!dapService_ || state_ == StepState::Stepping) return;
    
    state_ = StepState::Stepping;
    lastStepType_ = StepType::Out;
    currentThreadId_ = threadId;
    stepStartTime_ = std::chrono::steady_clock::now();
    
    if (onStepStarted) {
        onStepStarted(StepType::Out);
    }
    
    dapService_>stepOut(threadId);
}

void StepController::StepInstruction(uint32_t threadId) {
    if (!dapService_ || state_ == StepState::Stepping) return;
    
    state_ = StepState::Stepping;
    lastStepType_ = StepType::Instruction;
    currentThreadId_ = threadId;
    stepStartTime_ = std::chrono::steady_clock::now();
    
    if (onStepStarted) {
        onStepStarted(StepType::Instruction);
    }
    
    // Note: DAP doesn't have direct stepInstruction, use stepIn with granularity
    dapService_>stepInto(threadId);
}

void StepController::HandleStopped(const std::string& reason, uint32_t threadId) {
    if (state_ != StepState::Stepping) return;
    
    // Check if this is a step completion
    if (reason == "step" || reason == "breakpoint" || reason == "exception") {
        state_ = StepState::Complete;
        
        // Request stack trace to get new line
        dapService_>requestStackTrace(threadId, 0, 1);
        
        // Callback will be triggered when stack trace arrives
        // For now, notify with line 0 (unknown until stack trace)
        if (onStepComplete) {
            onStepComplete(lastStepType_, 0);
        }
        
        // Reset after a delay
        ResetState();
    }
}

void StepController::HandleError(const std::string& error) {
    if (state_ == StepState::Stepping) {
        if (onStepError) {
            onStepError(error);
        }
        ResetState();
    }
}

void StepController::ResetState() {
    state_ = StepState::Idle;
    currentThreadId_ = 0;
}

void StepController::FlashLine(uint32_t line, COLORREF color) {
    // Implementation: Flash the line briefly for visual feedback
    // This would integrate with your editor's highlighting
}

// ============================================================================
// StepToolbarController Implementation
// ============================================================================
StepToolbarController::StepToolbarController() = default;
StepToolbarController::~StepToolbarController() = default;

bool StepToolbarController::Create(HWND hwndParent, int x, int y) {
    // Create toolbar window
    hwndToolbar_ = CreateWindowExW(0, TOOLBARCLASSNAMEW, nullptr,
                                   WS_VISIBLE | WS_CHILD | TBSTYLE_FLAT | TBSTYLE_TOOLTIPS,
                                   x, y, 200, 28,
                                   hwndParent, nullptr, GetModuleHandle(nullptr), nullptr);
    
    if (!hwndToolbar_) return false;
    
    // Set button struct size
    SendMessage(hwndToolbar_, TB_BUTTONSTRUCTSIZE, sizeof(TBBUTTON), 0);
    
    // Create buttons
    TBBUTTON buttons[] = {
        // Step Over (F10)
        { 0, ID_STEP_OVER, TBSTATE_ENABLED, BTNS_BUTTON, {0}, 0, (INT_PTR)L"Step Over (F10)" },
        
        // Step Into (F11)
        { 1, ID_STEP_INTO, TBSTATE_ENABLED, BTNS_BUTTON, {0}, 0, (INT_PTR)L"Step Into (F11)" },
        
        // Step Out (Shift+F11)
        { 2, ID_STEP_OUT, TBSTATE_ENABLED, BTNS_BUTTON, {0}, 0, (INT_PTR)L"Step Out (Shift+F11)" },
        
        // Separator
        { 0, 0, 0, BTNS_SEP, {0}, 0, 0 },
        
        // Step Instruction (Alt+F11)
        { 3, ID_STEP_INSTRUCTION, TBSTATE_ENABLED, BTNS_BUTTON, {0}, 0, (INT_PTR)L"Step Instruction (Alt+F11)" }
    };
    
    SendMessage(hwndToolbar_, TB_ADDBUTTONS, ARRAYSIZE(buttons), (LPARAM)buttons);
    SendMessage(hwndToolbar_, TB_AUTOSIZE, 0, 0);
    
    return true;
}

void StepToolbarController::Destroy() {
    if (hwndToolbar_) {
        DestroyWindow(hwndToolbar_);
        hwndToolbar_ = nullptr;
    }
}

void StepToolbarController::AttachToStepController(StepController* controller) {
    stepController_ = controller;
}

void StepToolbarController::AttachToDapService(DapService* service) {
    dapService_ = service;
}

void StepToolbarController::UpdateButtonStates(DapState debugState, StepState stepState) {
    if (!hwndToolbar_) return;
    
    bool canStep = (debugState == DapState::Paused) && (stepState != StepState::Stepping);
    bool isPaused = (debugState == DapState::Paused);
    
    // Enable/disable step buttons
    SendMessage(hwndToolbar_, TB_ENABLEBUTTON, ID_STEP_OVER, canStep ? TRUE : FALSE);
    SendMessage(hwndToolbar_, TB_ENABLEBUTTON, ID_STEP_INTO, canStep ? TRUE : FALSE);
    SendMessage(hwndToolbar_, TB_ENABLEBUTTON, ID_STEP_OUT, canStep ? TRUE : FALSE);
    SendMessage(hwndToolbar_, TB_ENABLEBUTTON, ID_STEP_INSTRUCTION, canStep ? TRUE : FALSE);
    
    // Visual feedback: pressed state while stepping
    if (stepState == StepState::Stepping) {
        // Could set pressed state here
    }
}

void StepToolbarController::EnableAllButtons(bool enable) {
    if (!hwndToolbar_) return;
    
    SendMessage(hwndToolbar_, TB_ENABLEBUTTON, ID_STEP_OVER, enable ? TRUE : FALSE);
    SendMessage(hwndToolbar_, TB_ENABLEBUTTON, ID_STEP_INTO, enable ? TRUE : FALSE);
    SendMessage(hwndToolbar_, TB_ENABLEBUTTON, ID_STEP_OUT, enable ? TRUE : FALSE);
    SendMessage(hwndToolbar_, TB_ENABLEBUTTON, ID_STEP_INSTRUCTION, enable ? TRUE : FALSE);
}

void StepToolbarController::EnableButton(int buttonId, bool enable) {
    if (!hwndToolbar_) return;
    SendMessage(hwndToolbar_, TB_ENABLEBUTTON, buttonId, enable ? TRUE : FALSE);
}

void StepToolbarController::OnStepOver() {
    if (stepController_) {
        stepController_>StepOver();
    }
}

void StepToolbarController::OnStepInto() {
    if (stepController_) {
        stepController_>StepInto();
    }
}

void StepToolbarController::OnStepOut() {
    if (stepController_) {
        stepController_>StepOut();
    }
}

void StepToolbarController::OnStepInstruction() {
    if (stepController_) {
        stepController_>StepInstruction();
    }
}

LRESULT CALLBACK StepToolbarController::WndProc(HWND hwnd, UINT msg, 
                                                 WPARAM wParam, LPARAM lParam) {
    // Handle toolbar messages
    switch (msg) {
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case ID_STEP_OVER:
                    // Handle step over
                    return 0;
                case ID_STEP_INTO:
                    // Handle step into
                    return 0;
                case ID_STEP_OUT:
                    // Handle step out
                    return 0;
                case ID_STEP_INSTRUCTION:
                    // Handle step instruction
                    return 0;
            }
            break;
    }
    
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

// ============================================================================
// StepAnimator Implementation
// ============================================================================
StepAnimator::StepAnimator() = default;
StepAnimator::~StepAnimator() = default;

void StepAnimator::Initialize(HWND hwndEditor) {
    hwndEditor_ = hwndEditor;
}

void StepAnimator::Shutdown() {
    hwndEditor_ = nullptr;
    animating_ = false;
}

void StepAnimator::AnimateStepOver(uint32_t fromLine, uint32_t toLine) {
    currentLine_ = fromLine;
    targetLine_ = toLine;
    animating_ = true;
    animationProgress_ = 0.0f;
    animationStart_ = std::chrono::steady_clock::now();
    
    // Start animation timer
    SetTimer(hwndEditor_, 1, 16, nullptr); // ~60fps
}

void StepAnimator::AnimateStepInto(uint32_t fromLine, uint32_t toLine) {
    // Similar to StepOver but could have different visual
    AnimateStepOver(fromLine, toLine);
}

void StepAnimator::AnimateStepOut(uint32_t fromLine, uint32_t toLine) {
    // Similar but could show "returning" animation
    AnimateStepOver(fromLine, toLine);
}

void StepAnimator::SetExecutionLine(uint32_t line) {
    currentLine_ = line;
    InvalidateRect(hwndEditor_, nullptr, FALSE);
}

void StepAnimator::ClearExecutionLine() {
    currentLine_ = 0;
    InvalidateRect(hwndEditor_, nullptr, FALSE);
}

void StepAnimator::UpdateAnimation() {
    if (!animating_) return;
    
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - animationStart_).count();
    
    animationProgress_ = elapsed / 300.0f; // 300ms animation
    
    if (animationProgress_ >= 1.0f) {
        animationProgress_ = 1.0f;
        animating_ = false;
        KillTimer(hwndEditor_, 1);
        currentLine_ = targetLine_;
    }
    
    InvalidateRect(hwndEditor_, nullptr, FALSE);
}

void StepAnimator::Render(HDC hdc) {
    if (!hwndEditor_) return;
    
    // Draw current execution line
    if (currentLine_ > 0) {
        int y = (currentLine_ - 1) * 20; // Assuming 20px line height
        DrawExecutionArrow(hdc, y);
    }
    
    // Draw animation trail
    if (animating_) {
        int fromY = (currentLine_ - 1) * 20;
        int toY = (targetLine_ - 1) * 20;
        DrawStepTrail(hdc, fromY, toY, animationProgress_);
    }
}

void StepAnimator::DrawExecutionArrow(HDC hdc, int y) {
    // Draw yellow arrow indicating current execution line
    int centerX = 20; // Gutter width / 2
    int centerY = y + 10; // Line height / 2
    
    POINT points[3] = {
        {centerX - 6, centerY - 6},
        {centerX + 6, centerY},
        {centerX - 6, centerY + 6}
    };
    
    HBRUSH hBrush = CreateSolidBrush(RGB(255, 215, 0)); // Gold
    HPEN hPen = CreatePen(PS_SOLID, 1, RGB(200, 170, 0));
    
    HGDIOBJ hOldBrush = SelectObject(hdc, hBrush);
    HGDIOBJ hOldPen = SelectObject(hdc, hPen);
    
    Polygon(hdc, points, 3);
    
    SelectObject(hdc, hOldBrush);
    SelectObject(hdc, hOldPen);
    DeleteObject(hBrush);
    DeleteObject(hPen);
}

void StepAnimator::DrawStepTrail(HDC hdc, int fromY, int toY, float progress) {
    // Draw animated trail showing step direction
    int currentY = fromY + (toY - fromY) * progress;
    
    // Draw gradient trail
    for (int i = 0; i < 10; i++) {
        float alpha = (10 - i) / 10.0f * (1.0f - progress);
        int trailY = currentY - (toY > fromY ? i * 2 : -i * 2);
        
        COLORREF color = RGB(255 * alpha, 215 * alpha, 0);
        HBRUSH hBrush = CreateSolidBrush(color);
        
        RECT rc = { 10, trailY, 30, trailY + 4 };
        FillRect(hdc, &rc, hBrush);
        
        DeleteObject(hBrush);
    }
}

// ============================================================================
// Keyboard Shortcuts
// ============================================================================
bool HandleDebugKeyDown(HWND hwnd, WPARAM wParam, LPARAM lParam,
                        StepController* controller) {
    if (!controller) return false;
    
    bool shiftPressed = (GetKeyState(VK_SHIFT) & 0x8000) != 0;
    bool altPressed = (GetKeyState(VK_MENU) & 0x8000) != 0;
    
    switch (wParam) {
        case VK_F10:
            if (!shiftPressed && !altPressed) {
                controller->StepOver();
                return true;
            }
            break;
            
        case VK_F11:
            if (shiftPressed) {
                controller->StepOut();
                return true;
            } else if (!altPressed) {
                controller->StepInto();
                return true;
            } else {
                controller->StepInstruction();
                return true;
            }
            break;
    }
    
    return false;
}

} // namespace UI
} // namespace Debug
} // namespace RawrXD
