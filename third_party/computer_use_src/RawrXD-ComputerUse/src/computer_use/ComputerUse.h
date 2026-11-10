#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <string>
#include <vector>
#include <atomic>
#include <cstdint>

namespace rawrxd::computer_use {
enum class ActionType { Screenshot, FindWindow, InspectControls, Click, MoveMouse, TypeText, KeyPress, Scroll, WaitForWindow, LaunchProcess };
struct ComputerAction {
    ActionType type = ActionType::Screenshot;
    HWND targetWindow = nullptr;
    POINT position{0,0}; // target client coordinates for mouse actions
    std::wstring text; // window title substring, text, or executable path
    std::wstring arguments; // launch arguments (not a shell command)
    WORD virtualKey = 0;
    int scrollDelta = 0;
    DWORD timeoutMs = 5000;
};
struct ControlInfo { std::wstring name; std::wstring className; RECT bounds{}; HWND handle = nullptr; };
struct ActionResult {
    bool success = false;
    DWORD errorCode = 0;
    std::wstring message;
    HWND window = nullptr;
    std::vector<ControlInfo> controls;
    std::wstring screenshotPath;
};
struct SafetyPolicy {
    std::vector<DWORD> allowedProcessIds;
    bool allowLaunch = false;
    bool allowTyping = false;
    bool allowMouse = false;
    bool allowKeyboard = false;
    bool allowScreenshots = true;
    bool allowInspection = true;
    bool requireForeground = true;
};
class ComputerUseEngine {
public:
    explicit ComputerUseEngine(SafetyPolicy policy);
    ActionResult Execute(const ComputerAction& action);
    bool IsTargetAllowed(HWND window) const;
    void Cancel() noexcept { cancelled_.store(true); }
    void ResetCancel() noexcept { cancelled_.store(false); }
private:
    SafetyPolicy policy_;
    std::atomic_bool cancelled_{false};
    ActionResult Capture(HWND window) const;
    ActionResult Inspect(HWND window) const;
    ActionResult Find(const std::wstring& title, DWORD timeoutMs);
    ActionResult Input(const ComputerAction& action);
    ActionResult Launch(const ComputerAction& action) const;
};
std::wstring FormatReceipt(const ComputerAction& action, const ActionResult& result);
}
