#include "ComputerUse.h"
#include "AgentAdapter.h"
#include <chrono>
#include <cstring>
#include <future>
#include <iostream>
#include <thread>
using namespace rawrxd::computer_use;

namespace {
int failures = 0;
void Expect(bool ok, const char* name) {
    std::cout << (ok ? "PASS " : "FAIL ") << name << '\n';
    if (!ok) ++failures;
}
LRESULT CALLBACK FixtureProc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    if (message == WM_DESTROY) { PostQuitMessage(0); return 0; }
    return DefWindowProcW(window, message, wparam, lparam);
}
HWND FixtureWindow(const std::wstring& title) {
    WNDCLASSW wc{};
    wc.lpfnWndProc = FixtureProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = L"RawrXDCuDiscoveryFixture";
    RegisterClassW(&wc);
    return CreateWindowExW(WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW, wc.lpszClassName,
        title.c_str(), WS_POPUP | WS_VISIBLE, 0, 0, 1, 1,
        nullptr, nullptr, wc.hInstance, nullptr);
}
std::wstring Widen(const char* ascii) { return std::wstring(ascii, ascii + std::strlen(ascii)); }
}

int main(int argc, char** argv) {
    if (argc == 4 && std::string(argv[1]) == "--foreign-window") {
        const HWND window = FixtureWindow(Widen(argv[2]));
        if (!window) return 2;
        SetWindowPos(window, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
        const HANDLE ready = OpenEventW(EVENT_MODIFY_STATE, FALSE, Widen(argv[3]).c_str());
        if (!ready) return 3;
        SetEvent(ready); CloseHandle(ready);
        MSG message{};
        while (GetMessageW(&message, nullptr, 0, 0) > 0) {
            TranslateMessage(&message); DispatchMessageW(&message);
        }
        return 0;
    }

    SafetyPolicy policy;
    ComputerUseEngine engine(policy);
    ComputerAction action; action.type = ActionType::Click;
    const auto denied = engine.Execute(action);
    Expect(!denied.success && denied.errorCode == ERROR_ACCESS_DENIED, "mouse_policy_denied");
    action.type = ActionType::LaunchProcess;
    action.text = L"C:\\Windows\\System32\\notepad.exe";
    Expect(!engine.Execute(action).success, "launch_policy_denied");
    AgentAdapter adapter(engine, [](const ComputerAction&) { return false; });
    Expect(adapter.Dispatch(action).errorCode == ERROR_ACCESS_DENIED, "approval_denied");
    AgentAdapter approved(engine, [](const ComputerAction&) { return true; });
    Expect(!approved.Dispatch(action).success, "approval_preserves_policy");
    engine.Cancel();
    Expect(engine.Execute(action).errorCode == ERROR_CANCELLED, "cancelled_action_denied");
    engine.ResetCancel();
    action.type = ActionType::FindWindow; action.text.clear();
    Expect(engine.Execute(action).errorCode == ERROR_INVALID_PARAMETER, "empty_title_invalid");

    const std::wstring title = L"RawrXDCuDiscovery_" + std::to_wstring(GetCurrentProcessId());
    const HWND own = FixtureWindow(title);
    Expect(own != nullptr, "owned_fixture_created");
    const std::wstring eventName = L"Local\\" + title;
    const HANDLE ready = CreateEventW(nullptr, TRUE, FALSE, eventName.c_str());
    wchar_t executable[MAX_PATH]{};
    GetModuleFileNameW(nullptr, executable, MAX_PATH);
    std::wstring command = L"\"" + std::wstring(executable) + L"\" --foreign-window " + title + L" " + eventName;
    STARTUPINFOW startup{}; startup.cb = sizeof(startup);
    PROCESS_INFORMATION child{};
    const bool started = ready && CreateProcessW(executable, command.data(), nullptr, nullptr,
        FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &child);
    Expect(started, "foreign_fixture_started");
    if (started) {
        const bool childReady = WaitForSingleObject(ready, 5000) == WAIT_OBJECT_0;
        Expect(childReady, "foreign_fixture_ready");
        HWND firstMatch = FindWindowW(L"RawrXDCuDiscoveryFixture", title.c_str());
        DWORD firstPid = 0;
        GetWindowThreadProcessId(firstMatch, &firstPid);
        Expect(firstPid == child.dwProcessId, "disallowed_duplicate_precedes_allowed_window");
        policy.allowedProcessIds = {GetCurrentProcessId()};
        ComputerUseEngine discovery(policy);
        action.text = title; action.timeoutMs = 0;
        const auto found = discovery.Execute(action);
        Expect(found.success && found.window == own, "discovery_skips_disallowed_duplicate");
        policy.allowInspection = false;
        ComputerUseEngine noInspection(policy);
        Expect(noInspection.Execute(action).errorCode == ERROR_ACCESS_DENIED, "discovery_policy_denied");
        action.text = title + L"_absent"; action.timeoutMs = 10000;
        auto waiting = std::async(std::launch::async, [&] { return discovery.Execute(action); });
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
        discovery.Cancel();
        const bool completed = waiting.wait_for(std::chrono::seconds(1)) == std::future_status::ready;
        Expect(completed, "waiting_discovery_cancels_promptly");
        Expect(waiting.get().errorCode == ERROR_CANCELLED, "waiting_discovery_returns_cancelled");
        discovery.ResetCancel(); action.text = title; action.timeoutMs = 0;
        Expect(discovery.Execute(action).success, "discovery_restarts_after_cancel");
        if (firstPid == child.dwProcessId) PostMessageW(firstMatch, WM_CLOSE, 0, 0);
        if (WaitForSingleObject(child.hProcess, 3000) != WAIT_OBJECT_0) {
            TerminateProcess(child.hProcess, 4); // Only this test's disposable child.
            WaitForSingleObject(child.hProcess, 1000);
        }
        CloseHandle(child.hThread); CloseHandle(child.hProcess);
    }
    if (ready) CloseHandle(ready);
    if (own) DestroyWindow(own);
    std::cout << (failures ? "POLICY TESTS FAIL\n" : "POLICY TESTS PASS\n");
    return failures ? 1 : 0;
}
