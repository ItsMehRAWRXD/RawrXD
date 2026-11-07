// Actual Windows compile -> object -> link -> executable acceptance.
// cl.exe must be available (run in a VS developer environment).
#include "../build/windows_process_runner.hpp"
#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
namespace fs = std::filesystem;
using RawrXD::Build::Run;
int wmain() {
    const auto root = fs::temp_directory_path() / L"rawrxd build gate with spaces";
    fs::create_directories(root);
    const auto source = root / L"hello.cpp";
    const auto object = root / L"hello.obj";
    const auto binary = root / L"hello.exe";
    {
        std::ofstream file(source);
        file << "#include <cstdio>\nint main(){std::puts(\"BUILD_PIPELINE_OK\");return 0;}\n";
    }
    auto compile = Run(L"cl.exe", {L"/nologo", L"/c", L"/Fo" + object.wstring(), source.wstring()},
                       root.wstring(), 60000);
    if (!compile.launched || compile.timedOut || compile.exitCode) {
        std::cerr << "COMPILE FAILED: " << compile.error << "\n" << compile.stdoutText << compile.stderrText;
        return 1;
    }
    auto link = Run(L"link.exe", {L"/nologo", L"/OUT:" + binary.wstring(), object.wstring()},
                    root.wstring(), 60000);
    if (!link.launched || link.timedOut || link.exitCode) {
        std::cerr << "LINK FAILED: " << link.error << "\n" << link.stdoutText << link.stderrText;
        return 2;
    }
    auto execute = Run(binary.wstring(), {}, root.wstring(), 10000);
    if (!execute.launched || execute.timedOut || execute.exitCode ||
        execute.stdoutText.find("BUILD_PIPELINE_OK") == std::string::npos) {
        std::cerr << "EXEC FAILED: " << execute.error << "\n" << execute.stdoutText << execute.stderrText;
        return 3;
    }
    // Concurrent stdout/stderr pressure exceeds pipe buffers; must not deadlock.
    auto pressure = Run(cl, {L"/d", L"/c", L"for /L %i in (1,1,2000) do @echo stdout%i & @echo stderr%i 1>&2"},
                        root.wstring(), 30000);
    if (!pressure.launched || pressure.timedOut || pressure.exitCode ||
        pressure.stdoutText.find("stdout2000") == std::string::npos ||
        pressure.stderrText.find("stderr2000") == std::string::npos) {
        std::cerr << "PIPE PRESSURE FAILED: " << pressure.error;
        return 4;
    }
    auto timeout = Run(cl, {L"/d", L"/c", L"ping -n 8 127.0.0.1 >nul"}, root.wstring(), 100);
    if (!timeout.launched || !timeout.timedOut) {
        std::cerr << "TIMEOUT FAILED: " << timeout.error;
        return 5;
    }
    auto missing = Run(root.wstring() + L"\\nonexistent.exe", {}, root.wstring(), 1000);
    if (missing.launched || missing.error.empty()) return 6;
    std::cout << "WINDOWS_BUILD_GATE_PASS\n";
    fs::remove_all(root);
    return 0;
}
