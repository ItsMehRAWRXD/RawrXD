// StepController.hpp
// Phase 24C: Stepping Controls
// ============================================================================
// Manages step operations and visual feedback during debugging
// ============================================================================

#pragma once

#include "DapService.hpp"
#include <windows.h>
#include <functional>
#include <chrono>

namespace RawrXD {
namespace Debug {
namespace UI {

// ============================================================================
// Step Operation Types
// ============================================================================
enum class StepType {
    Over,       // Step over function calls
    Into,       // Step into function calls  
    Out,        // Step out of current function
    Instruction // Single instruction step
};

enum class StepState {
    Idle,       // Not stepping
    Stepping,   // Step request sent, waiting for stopped event
    Complete    // Step complete, target paused
};

// ============================================================================
// Step Controller
// ============================================================================
class StepController {
public:
    StepController();
    ~StepController();

    // Initialization
    void AttachToDapService(DapService* service);
    void Detach();

    // Step Operations
    void StepOver(uint32_t threadId = 0);
    void StepInto(uint32_t threadId = 0);
    void StepOut(uint32_t threadId = 0);
    void StepInstruction(uint32_t threadId = 0);
    
    // State
    StepState GetState() const { return state_; }
    bool IsStepping() const { return state_ == StepState::Stepping; }
    StepType GetLastStepType() const { return lastStepType_; }
    
    // Visual Feedback
    void SetLineIndicator(HWND hwndEditor, uint32_t line);
    void ClearLineIndicator();
    void FlashLine(uint32_t line, COLORREF color);
    
    // Callbacks
    std::function<void(StepType)> onStepStarted;
    std::function<void(StepType, uint32_t newLine)> onStepComplete;
    std::function<void(const std::string& error)> onStepError;

private:
    DapService* dapService_ = nullptr;
    StepState state_ = StepState::Idle;
    StepType lastStepType_ = StepType::Over;
    uint32_t currentThreadId_ = 0;
    
    std::chrono::steady_clock::time_point stepStartTime_;
    
    void HandleStopped(const std::string& reason, uint32_t threadId);
    void HandleError(const std::string& error);
    void ResetState();
};

// ============================================================================
// Step Toolbar Button Controller
// ============================================================================
class StepToolbarController {
public:
    StepToolbarController();
    ~StepToolbarController();

    bool Create(HWND hwndParent, int x, int y);
    void Destroy();
    
    // Attach to services
    void AttachToStepController(StepController* controller);
    void AttachToDapService(DapService* service);
    
    // Update button states
    void UpdateButtonStates(DapState debugState, StepState stepState);
    void EnableAllButtons(bool enable);
    void EnableButton(int buttonId, bool enable);
    
    // Button IDs
    static constexpr int ID_STEP_OVER = 1101;
    static constexpr int ID_STEP_INTO = 1102;
    static constexpr int ID_STEP_OUT = 1103;
    static constexpr int ID_STEP_INSTRUCTION = 1104;

private:
    HWND hwndToolbar_ = nullptr;
    StepController* stepController_ = nullptr;
    DapService* dapService_ = nullptr;
    
    void OnStepOver();
    void OnStepInto();
    void OnStepOut();
    void OnStepInstruction();
    
    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
};

// ============================================================================
// Step Animation (Visual feedback during step)
// ============================================================================
class StepAnimator {
public:
    StepAnimator();
    ~StepAnimator();

    void Initialize(HWND hwndEditor);
    void Shutdown();
    
    // Animation effects
    void AnimateStepOver(uint32_t fromLine, uint32_t toLine);
    void AnimateStepInto(uint32_t fromLine, uint32_t toLine);
    void AnimateStepOut(uint32_t fromLine, uint32_t toLine);
    
    // Highlight current execution line
    void SetExecutionLine(uint32_t line);
    void ClearExecutionLine();
    
    // Draw animation frame (call from WM_PAINT)
    void Render(HDC hdc);

private:
    HWND hwndEditor_ = nullptr;
    uint32_t currentLine_ = 0;
    uint32_t targetLine_ = 0;
    
    // Animation state
    bool animating_ = false;
    float animationProgress_ = 0.0f;
    std::chrono::steady_clock::time_point animationStart_;
    
    void UpdateAnimation();
    void DrawExecutionArrow(HDC hdc, int y);
    void DrawStepTrail(HDC hdc, int fromY, int toY, float progress);
};

// ============================================================================
// Keyboard Shortcuts
// ============================================================================
bool HandleDebugKeyDown(HWND hwnd, WPARAM wParam, LPARAM lParam,
                        StepController* controller);

// Default key bindings:
// F10 = Step Over
// F11 = Step Into  
// Shift+F11 = Step Out
// Alt+F11 = Step Instruction

} // namespace UI
} // namespace Debug
} // namespace RawrXD
