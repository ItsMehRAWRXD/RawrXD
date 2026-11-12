// C44 marketplace / C45 computer-use / C46 collab / C47 installer CLI probes.
// Real product paths — PROMOTE=0 CERTIFIED=0 TIP_CLIMB=HOLD.
#include "cli/rawr_cli_top25_gaps.hpp"

#include "marketplace/extension_package_local.hpp"
#include "collab/crdt_buffer.h"
#include "collab/websocket_hub.h"
#include "ComputerUseBridge.h"

#include <filesystem>
#include <iostream>
#include <string>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace fs = std::filesystem;
using rawrxd::computer_use::ComputerAction;
using rawrxd::computer_use::ActionType;
using rawrxd::computer_use::ComputerUseBridge;

static void emit(const std::string& s) { std::cout << s << "\n"; }

int rawrCliMarketplaceCommand(const std::vector<std::string>& args, bool json) {
    if (args.empty() || args[0] != "probe") {
        emit("usage: rawr marketplace probe [--vsix PATH]");
        return 1;
    }
    std::string vsix =
        "F:\\rawrxd\\evidence\\FULL_FEATURE_ONESHOT_001\\fixtures\\"
        "oneshot-ext-smoke.vsix";
    for (size_t i = 1; i + 1 < args.size(); ++i) {
        if (args[i] == "--vsix") vsix = args[i + 1];
    }
    size_t catalogN = 0;
    RawrXD::Extensions::Local::IdeCatalog(catalogN);
    const auto inst = RawrXD::Extensions::Local::InstallPackage(vsix);
    if (json) {
        emit(std::string("{\"install_ok\":") + (inst.success ? "1" : "0") +
             ",\"catalog_n\":" + std::to_string(catalogN) + "}");
    } else {
        emit("install_ok=" + std::to_string(inst.success ? 1 : 0) +
             " catalog_n=" + std::to_string(catalogN) + " path=" + vsix +
             " msg=" + inst.message);
    }
    return (inst.success && catalogN > 0) ? 0 : 1;
}

int rawrCliComputerUseCommand(const std::vector<std::string>& args, bool json) {
    if (args.empty() || args[0] != "probe") {
        emit("usage: rawr computer-use probe");
        return 1;
    }
    auto& bridge = ComputerUseBridge::Instance();
    bridge.EnsureInitialized();
    bridge.AllowOwnAndConfiguredParents();
    bridge.ResetCancel();

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = DefWindowProcW;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = L"RawrXDCliCuProbe";
    RegisterClassExW(&wc);
    HWND hwnd = CreateWindowExW(
        0, L"RawrXDCliCuProbe", L"RawrXDCliCuProbe",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE, 80, 80, 280, 180, nullptr, nullptr,
        wc.hInstance, nullptr);
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);
    for (int i = 0; i < 6; ++i) {
        MSG msg{};
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        Sleep(10);
    }

    ComputerAction find;
    find.type = ActionType::FindWindow;
    find.text = L"RawrXDCliCuProbe";
    const auto findR = bridge.DispatchApproved(find, true);

    ComputerAction shot;
    shot.type = ActionType::Screenshot;
    shot.targetWindow = hwnd;
    const auto shotR = bridge.DispatchApproved(shot, true);
    if (shotR.success && !shotR.screenshotPath.empty())
        DeleteFileW(shotR.screenshotPath.c_str());

    DestroyWindow(hwnd);
    const int ok = (findR.success && shotR.success) ? 1 : 0;
    if (json) {
        emit(std::string("{\"find_ok\":") + (findR.success ? "1" : "0") +
             ",\"screenshot_ok\":" + (shotR.success ? "1" : "0") +
             ",\"SESSION_REAL\":" + std::to_string(ok) + "}");
    } else {
        emit("find_ok=" + std::to_string(findR.success ? 1 : 0) +
             " screenshot_ok=" + std::to_string(shotR.success ? 1 : 0) +
             " SESSION_REAL=" + std::to_string(ok));
    }
    return ok ? 0 : 1;
}

int rawrCliCollabCommand(const std::vector<std::string>& args, bool json) {
    if (args.empty() || args[0] != "probe") {
        emit("usage: rawr collab probe");
        return 1;
    }
    CRDTBuffer buf;
    buf.insertText(0, "collab_probe");
    const int crdtOk = (buf.getText() == "collab_probe") ? 1 : 0;
    RawrXD::WebSocketHub hub;
    // Prefer a CLI-only port so a live IDE collab hub does not collide.
    const bool started = hub.startServer(5191);
    const int hubOk = (started && hub.isRunning()) ? 1 : 0;
    if (hubOk) hub.stopServer();
    if (json) {
        emit(std::string("{\"crdt_ok\":") + std::to_string(crdtOk) +
             ",\"hub_running\":" + std::to_string(hubOk) + "}");
    } else {
        emit("crdt_ok=" + std::to_string(crdtOk) +
             " hub_running=" + std::to_string(hubOk));
    }
    return (crdtOk && hubOk) ? 0 : 1;
}

int rawrCliInstallerCommand(const std::vector<std::string>& args, bool json) {
    if (args.empty() || args[0] != "probe") {
        emit("usage: rawr installer probe");
        return 1;
    }
    const fs::path wizard = "F:\\rawrxd\\installer\\SetupWizard.exe";
    const int present = fs::exists(wizard) ? 1 : 0;
    uintmax_t sz = 0;
    if (present) {
        std::error_code ec;
        sz = fs::file_size(wizard, ec);
        if (ec) sz = 0;
    }
    int launched = 0, exited = 0;
    DWORD exitCode = 0;
    if (present && sz > 0) {
        STARTUPINFOA si{};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi{};
        std::string cmd = "\"" + wizard.string() + "\" /?";
        if (CreateProcessA(nullptr, cmd.data(), nullptr, nullptr, FALSE,
                           CREATE_NO_WINDOW, nullptr, "F:\\rawrxd\\installer",
                           &si, &pi)) {
            launched = 1;
            const DWORD wr = WaitForSingleObject(pi.hProcess, 2500);
            if (wr == WAIT_OBJECT_0) {
                exited = 1;
                GetExitCodeProcess(pi.hProcess, &exitCode);
            } else {
                TerminateProcess(pi.hProcess, 1);
            }
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
    }
    if (json) {
        emit(std::string("{\"present\":") + std::to_string(present) +
             ",\"size\":" + std::to_string(static_cast<unsigned long long>(sz)) +
             ",\"launched\":" + std::to_string(launched) + "}");
    } else {
        emit("present=" + std::to_string(present) +
             " size=" + std::to_string(static_cast<unsigned long long>(sz)) +
             " launched=" + std::to_string(launched) +
             " exited=" + std::to_string(exited) +
             " exit_code=" + std::to_string(static_cast<unsigned long>(exitCode)));
    }
    return (present && sz > 0 && launched) ? 0 : 1;
}
