#include "finish_batches.hpp"
#include <fstream>
#include <sstream>
#include <vector>
#include <filesystem>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")

static bool copyLaunch(const std::filesystem::path& dir) {
    wchar_t exe[32768] = {};
    GetModuleFileNameW(nullptr, exe, 32768);
    std::filesystem::create_directories(dir);
    std::filesystem::path dest = dir / "KartGib.exe";
    std::filesystem::copy_file(exe, dest, std::filesystem::copy_options::overwrite_existing);
    std::wstring cmd = L"\"" + dest.wstring() + L"\" --finish-smoke";
    std::vector<wchar_t> buffer(cmd.begin(), cmd.end());
    buffer.push_back(0);
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(dest.c_str(), buffer.data(), nullptr, nullptr, FALSE, 0, nullptr, dir.c_str(), &startup, &process)) return false;
    WaitForSingleObject(process.hProcess, 15000);
    DWORD code = 1;
    GetExitCodeProcess(process.hProcess, &code);
    CloseHandle(process.hProcess);
    CloseHandle(process.hThread);
    std::ifstream smoke(dir / "smoke.txt");
    std::string text;
    std::getline(smoke, text);
    return code == 0 && text == "KARTGIB_SMOKE";
}

void fillBatchShip(std::vector<BatchGate>& out, const std::string& dir) {
    bool synced = false;
    float sent = 12.5f, got = 0;
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) == 0) {
        SOCKET server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = 0;
        bind(server, reinterpret_cast<sockaddr*>(&address), sizeof(address));
        listen(server, 1);
        int length = sizeof(address);
        getsockname(server, reinterpret_cast<sockaddr*>(&address), &length);
        SOCKET client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        connect(client, reinterpret_cast<sockaddr*>(&address), sizeof(address));
        SOCKET peer = accept(server, nullptr, nullptr);
        int wrote = send(client, reinterpret_cast<char*>(&sent), sizeof(sent), 0);
        int read = recv(peer, reinterpret_cast<char*>(&got), sizeof(got), 0);
        synced = wrote == sizeof(sent) && read == sizeof(got) && got == sent;
        closesocket(peer); closesocket(client); closesocket(server);
        WSACleanup();
    }
    addGate(out, 21, "Multiplayer networking and replication", synced ? "PARTIAL" : "FAIL",
        synced ? "loopback_position=12.5 two_game_clients=NOT_RUN" : "socket_failed");
    addGate(out, 22, "Rendering and performance optimization", "NOT_RUN",
        "60fps, culling improvement, and shader-cache stability were not measured");
    wchar_t exe[32768] = {};
    GetModuleFileNameW(nullptr, exe, 32768);
    std::wstring cmd = L"\"" + std::wstring(exe) + L"\" --finish-write";
    std::vector<wchar_t> buffer(cmd.begin(), cmd.end());
    buffer.push_back(0);
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    bool intact = false;
    if (CreateProcessW(exe, buffer.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &startup, &process)) {
        std::filesystem::path save = std::filesystem::path(dir) / "kartgib_autosave.bin";
        for (int i = 0; i < 50 && !std::filesystem::exists(save); ++i) Sleep(100);
        TerminateProcess(process.hProcess, 1);
        WaitForSingleObject(process.hProcess, 5000);
        CloseHandle(process.hProcess);
        CloseHandle(process.hThread);
        std::ifstream file(save, std::ios::binary);
        uint32_t magic = 0;
        float value = 0;
        file.read(reinterpret_cast<char*>(&magic), 4);
        file.read(reinterpret_cast<char*>(&value), 4);
        intact = magic == 0x4B474931u && value == 12.5f;
    }
    addGate(out, 23, "Crash recovery, autosave and content integrity", intact ? "PARTIAL" : "FAIL",
        intact ? "killed_after_flush value=12.5 editor_project=NOT_RUN" : "autosave_missing");
    bool packed = false;
    try { packed = copyLaunch(std::filesystem::temp_directory_path() / "kartgib_pkg"); }
    catch (...) { packed = false; }
    addGate(out, 24, "Standalone game packaging and project templates", packed ? "PARTIAL" : "FAIL",
        packed ? "copied_exe_smoke=PASS clean_machine=NOT_RUN templates=NOT_RUN" : "package_smoke_failed");
    addGate(out, 25, "Release certification and end-to-end gameplay", "NOT_RUN",
        "full playthrough, long soak, and release receipts were not executed");
}
