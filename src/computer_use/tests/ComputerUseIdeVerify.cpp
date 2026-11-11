// Extended Windows verification for Computer Use + IDE bridge dispatch.
#include "ComputerUse.h"
#include "AgentAdapter.h"
#include "ComputerUseBridge.h"
#include <iostream>
#include <string>

using namespace rawrxd::computer_use;

static int g_fails = 0;
static void expect(bool ok, const char* name) {
    if (!ok) { std::cerr << "FAIL " << name << "\n"; ++g_fails; }
    else std::cout << "PASS " << name << "\n";
}

int main() {
    SafetyPolicy deny; ComputerUseEngine engine(deny);
    ComputerAction click; click.type = ActionType::Click;
    expect(!engine.Execute(click).success, "policy_mouse_deny");
    ComputerAction launch; launch.type = ActionType::LaunchProcess;
    launch.text = L"C:\\Windows\\System32\\notepad.exe";
    expect(!engine.Execute(launch).success, "policy_launch_deny");

    AgentAdapter denyAd(engine, [](const ComputerAction&) { return false; });
    expect(denyAd.Dispatch(click).errorCode == ERROR_ACCESS_DENIED, "approval_deny");
    AgentAdapter allowAd(engine, [](const ComputerAction&) { return true; });
    expect(!allowAd.Dispatch(click).success, "approval_allow_still_policy");

    engine.Cancel();
    expect(engine.Execute(launch).errorCode == ERROR_CANCELLED, "cancel");
    engine.ResetCancel();

    auto& bridge = ComputerUseBridge::Instance();
    bridge.EnsureInitialized();
    bridge.AllowOwnAndConfiguredParents();
    bridge.ResetCancel();

    // Create a disposable owned top-level window for allowlist targeting.
    WNDCLASSEXW wc{}; wc.cbSize = sizeof(wc); wc.lpfnWndProc = DefWindowProcW;
    wc.hInstance = GetModuleHandleW(nullptr); wc.lpszClassName = L"RawrXDCuVerify";
    RegisterClassExW(&wc);
    HWND hwnd = CreateWindowExW(0, L"RawrXDCuVerify", L"RawrXDCuVerify",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE, 100, 100, 320, 240,
        nullptr, nullptr, wc.hInstance, nullptr);
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);
    for (int i = 0; i < 8; ++i) {
        MSG msg{};
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        Sleep(10);
    }
    SetForegroundWindow(hwnd);
    ComputerAction shot; shot.type = ActionType::Screenshot; shot.targetWindow = hwnd;
    auto shotR = bridge.DispatchApproved(shot, true);
    expect(shotR.success && !shotR.screenshotPath.empty(), "screenshot_own_window");
    if (shotR.success) DeleteFileW(shotR.screenshotPath.c_str());

    ComputerAction find; find.type = ActionType::FindWindow; find.text = L"RawrXDCuVerify";
    expect(bridge.DispatchApproved(find, true).success, "find_own_window");

    // Disposable owned window: enable mouse/type for this process only.
    bridge.SetMouseAllowed(true);
    bridge.SetTypingAllowed(true);
    {
        HWND fg = GetForegroundWindow();
        DWORD fgTid = fg ? GetWindowThreadProcessId(fg, nullptr) : 0;
        DWORD myTid = GetCurrentThreadId();
        if (fgTid && fgTid != myTid) AttachThreadInput(fgTid, myTid, TRUE);
        BringWindowToTop(hwnd);
        SetForegroundWindow(hwnd);
        if (fgTid && fgTid != myTid) AttachThreadInput(fgTid, myTid, FALSE);
        for (int i = 0; i < 4; ++i) {
            MSG msg{};
            while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }
    ComputerAction move; move.type = ActionType::MoveMouse;
    move.targetWindow = hwnd; move.position = {40, 40};
    expect(bridge.DispatchApproved(move, true).success, "mouse_own_window");
    ComputerAction type; type.type = ActionType::TypeText;
    type.targetWindow = hwnd; type.text = L"cu";
    expect(bridge.DispatchApproved(type, true).success, "type_own_window");
    bridge.SetMouseAllowed(false);
    bridge.SetTypingAllowed(false);

    rawrxd::tools::Registry reg;
    bridge.RegisterTools(reg);
    rawrxd::tools::Request req;
    req.name = "computer_use.launch";
    req.args["path"] = "C:\\Windows\\System32\\notepad.exe";
    auto denied = reg.call(req, [](const rawrxd::tools::Tool&,
                                   const rawrxd::tools::Request&) { return false; });
    expect(!denied.ok, "agent_tool_approval_deny");
    expect(reg.names().size() >= 8, "agent_tools_registered");

    // Approved launch still denied by default SafetyPolicy.allowLaunch=false.
    auto polDenied = reg.call(req, [](const rawrxd::tools::Tool&,
                                      const rawrxd::tools::Request&) { return true; });
    expect(!polDenied.ok, "agent_tool_policy_deny_launch");

    bridge.Cancel();
    ComputerAction find2; find2.type = ActionType::FindWindow; find2.text = L"x";
    expect(bridge.DispatchApproved(find2, true).errorCode == ERROR_CANCELLED,
           "bridge_cancel");
    bridge.SetMouseAllowed(false);
    bridge.AllowOwnProcess();
    expect(bridge.DispatchApproved(find2, true).errorCode == ERROR_CANCELLED,
           "policy_change_preserves_cancel");
    bridge.ResetCancel();
    expect(bridge.DispatchApproved(find, true).success, "bridge_restart_after_cancel");

    DestroyWindow(hwnd);
    std::cout << (g_fails ? "VERIFY FAIL\n" : "VERIFY PASS\n");
    return g_fails ? 1 : 0;
}
