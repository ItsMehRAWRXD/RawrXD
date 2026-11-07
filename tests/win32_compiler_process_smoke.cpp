// Windows-only smoke: run executable with --selftest after building with MSVC.
// cl /nologo /EHsc /std:c++17 tests/win32_compiler_process_smoke.cpp
// cl /nologo /EHsc /std:c++17 /Fe:win32_compiler_process_smoke.exe tests/win32_compiler_process_smoke.cpp
#include "../src/build/win32_compiler_process.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <windows.h>
namespace fs = std::filesystem;
using namespace RawrXD::Build;
int wmain(int argc, wchar_t** argv) {
    if (argc > 1 && std::wstring(argv[1]) == L"--child-output") {
        for (int i = 0; i < 1000; ++i) {
            std::cout << "stdout:" << i << "\n";
            std::cerr << "stderr:" << i << "\n";
        }
        return 7;
    }
    if (argc > 1 && std::wstring(argv[1]) == L"--child-sleep") {
        Sleep(30000); return 0;
    }
    if (argc > 1 && std::wstring(argv[1]) == L"--child-args") {
        return argc == 3 && std::wstring(argv[2]) == L"a b\\\"c" ? 0 : 9;
    }
    wchar_t path[MAX_PATH]{};
    if (!GetModuleFileNameW(nullptr, path, MAX_PATH)) return 1;
    ProcessOptions p;
    p.executable = path;
    p.arguments = {L"--child-output"};
    auto output = run_process(p);
    if (!output.launched || output.timed_out || output.exit_code != 7 ||
        output.stdout_text.find("stdout:999") == std::string::npos ||
        output.stderr_text.find("stderr:999") == std::string::npos) return 2;
    p.max_output_bytes_per_stream = 64;
    auto capped = run_process(p);
    if (!capped.stdout_truncated || !capped.stderr_truncated ||
        capped.stdout_text.size() != 64 || capped.stderr_text.size() != 64) return 3;
    p.arguments = {L"--child-args", L"a b\\\"c"};
    p.max_output_bytes_per_stream = 4096;
    if (run_process(p).exit_code != 0) return 4;
    p.arguments = {L"--child-sleep"};
    p.timeout_ms = 150;
    auto timed = run_process(p);
    if (!timed.launched || !timed.timed_out) return 5;
    // Real MSVC compile -> .obj -> link -> executable -> run. No model needed.
    // Invoke from an x64 Native Tools Command Prompt so cl.exe/link.exe are available.
    wchar_t compiler[MAX_PATH]{}, linker[MAX_PATH]{};
    if (!SearchPathW(nullptr, L"cl.exe", nullptr, MAX_PATH, compiler, nullptr) ||
        !SearchPathW(nullptr, L"link.exe", nullptr, MAX_PATH, linker, nullptr)) {
        std::cerr << "SKIP: MSVC cl.exe/link.exe not on PATH\n";
        return 77; // CTest SKIP_RETURN_CODE 77; never report PASS.
    }
    const fs::path temp = fs::temp_directory_path() /
        (L"rawrxd-compiler-smoke-" + std::to_wstring(GetCurrentProcessId()));
    fs::create_directories(temp);
    struct Cleanup { fs::path dir; ~Cleanup() { std::error_code ec; fs::remove_all(dir, ec); } } cleanup{temp};
    const fs::path source = temp / L"hello.cpp";
    const fs::path obj = temp / L"hello.obj";
    const fs::path exe = temp / L"hello.exe";
    { std::ofstream f(source); f << "int main(){return 23;}\n"; }
    ProcessOptions build;
    build.executable = compiler;
    build.working_directory = temp.wstring();
    build.arguments = {L"/nologo", L"/c", source.wstring(), L"/Fo:" + obj.wstring()};
    auto compile = run_process(build);
    if (!compile.launched || compile.timed_out || compile.exit_code != 0 || !fs::exists(obj)) {
        std::cerr << "compile failed: " << compile.stdout_text << compile.stderr_text;
        return 6;
    }
    build.executable = linker;
    build.arguments = {L"/nologo", obj.wstring(), L"/OUT:" + exe.wstring()};
    auto link = run_process(build);
    if (!link.launched || link.timed_out || link.exit_code != 0 || !fs::exists(exe)) {
        std::cerr << "link failed: " << link.stdout_text << link.stderr_text;
        return 7;
    }
    build.executable = exe.wstring();
    build.arguments.clear();
    auto run = run_process(build);
    if (!run.launched || run.timed_out || run.exit_code != 23) return 8;
    std::cout << "PASS: capture, cap, quoting, timeout, MSVC compile-object-link-run\n";
    return 0;
}
