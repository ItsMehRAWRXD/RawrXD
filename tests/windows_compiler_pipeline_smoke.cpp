#include "../~dev/rawrxd/src/cli/windows_process_runner.hpp"
#include <windows.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
using namespace rawrxd::build;
namespace fs = std::filesystem;

static void require(bool ok, const char* message) {
    if (!ok) throw std::runtime_error(message);
}
static std::wstring env(const wchar_t* name) {
    DWORD n = GetEnvironmentVariableW(name, nullptr, 0);
    if (!n) return L"";
    std::wstring value(n, L'\0');
    GetEnvironmentVariableW(name, value.data(), n);
    value.resize(n - 1);
    return value;
}
int wmain() {
    try {
        auto temp = fs::temp_directory_path() / L"rawrxd compiler runner smoke";
        fs::create_directories(temp);
        auto source = temp / L"hello world.cpp";
        auto object = temp / L"hello world.obj";
        auto binary = temp / L"hello world.exe";
        {
            std::ofstream out(source);
            out << "#include <cstdio>\nint main() { std::puts(\"PIPELINE_OK\"); return 0; }\n";
        }
        const auto compiler = env(L"RAWRXD_TEST_CXX");
        const auto linker = env(L"RAWRXD_TEST_LINK");
        require(!compiler.empty(), "RAWRXD_TEST_CXX is required");
        require(!linker.empty(), "RAWRXD_TEST_LINK is required");
        auto compile = run_process(compiler, {L"/nologo", L"/c", L"/EHsc",
            source.wstring(), L"/Fo" + object.wstring()}, 60000, temp.wstring());
        require(compile.started && !compile.timed_out && compile.exit_code == 0,
                "real C++ compile failed");
        require(fs::is_regular_file(object), "compiler did not produce object");
        auto link = run_process(linker, {L"/nologo", object.wstring(),
            L"/OUT:" + binary.wstring()}, 60000, temp.wstring());
        require(link.started && !link.timed_out && link.exit_code == 0,
                "real object link failed");
        require(fs::is_regular_file(binary), "linker did not produce executable");
        auto execute = run_process(binary.wstring(), {}, 10000);
        require(execute.started && !execute.timed_out && execute.exit_code == 0,
                "linked executable failed");
        require(execute.stdout_text.find("PIPELINE_OK") != std::string::npos,
                "linked executable output mismatch");
        std::cout << "PASS: C++ -> OBJ -> LINK -> EXE -> stdout\n";

        auto missing = run_process(L"Z:\\rawrxd-nonexistent-compiler.exe", {}, 1000);
        require(!missing.started && missing.exit_code != 0,
                "missing compiler was not rejected");
        std::cout << "PASS: missing executable rejected\n";

        auto stdout_stderr = run_process(L"C:\\Windows\\System32\\cmd.exe",
            {L"/d", L"/s", L"/c", L"echo STDOUT_OK & echo STDERR_OK 1>&2"}, 10000);
        require(stdout_stderr.started && !stdout_stderr.timed_out &&
                stdout_stderr.exit_code == 0 &&
                stdout_stderr.stdout_text.find("STDOUT_OK") != std::string::npos &&
                stdout_stderr.stderr_text.find("STDERR_OK") != std::string::npos,
                "concurrent stdout/stderr capture failed");
        std::cout << "PASS: concurrent stdout and stderr\n";

        auto timeout = run_process(L"C:\\Windows\\System32\\ping.exe",
            {L"-n", L"20", L"127.0.0.1"}, 200);
        require(timeout.started && timeout.timed_out, "timeout enforcement failed");
        std::cout << "PASS: enforced process timeout\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAIL: " << e.what() << "\n";
        return 1;
    }
}
