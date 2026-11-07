// Windows-only, model-free integration gate: real MSVC compile -> object -> link -> exe.
#include "../~dev/rawrxd/src/core/compiler_subprocess_win32.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
using rawrxd::build::runProcess;
static bool require(bool condition, const char* label) {
    std::cout << (condition ? "PASS " : "FAIL ") << label << "\n";
    return condition;
}
int wmain() {
    namespace fs = std::filesystem;
    const auto root = fs::temp_directory_path() / (L"rawrxd_compiler_gate_" + std::to_wstring(GetCurrentProcessId()));
    std::error_code ec;
    fs::create_directories(root, ec);
    if (ec) return 2;
    struct Cleanup { fs::path p; ~Cleanup() { std::error_code e; fs::remove_all(p,e); } } cleanup{root};
    const auto source = root / "hello.cpp";
    const auto object = root / "hello.obj";
    const auto binary = root / "hello.exe";
    {
        std::ofstream f(source);
        f << "#include <cstdio>\nint main(){std::puts(\"RAWRXD_COMPILE_LINK_OK\");return 0;}\n";
    }
    bool ok = true;
    const auto compile = runProcess(L"cl.exe", {L"/nologo",L"/c",L"/EHsc",L"/std:c++20",
                                                L"/Fo:" + object.wstring(),source.wstring()}, 60000, root.wstring());
    ok &= require(compile.launched && !compile.timed_out && compile.exit_code == 0 && fs::exists(object), "compile object");
    if (!ok) { std::cerr << compile.stderr_text << compile.stdout_text; return 1; }
    const auto link = runProcess(L"link.exe", {L"/NOLOGO",L"/OUT:" + binary.wstring(),object.wstring()},60000,root.wstring());
    ok &= require(link.launched && !link.timed_out && link.exit_code == 0 && fs::exists(binary), "link executable");
    if (!ok) { std::cerr << link.stderr_text << link.stdout_text; return 1; }
    const auto run = runProcess(binary.wstring(), {}, 10000, root.wstring());
    ok &= require(run.launched && !run.timed_out && run.exit_code == 0 &&
                  run.stdout_text.find("RAWRXD_COMPILE_LINK_OK") != std::string::npos, "run compiled executable");
    const auto dual = runProcess(L"cmd.exe", {L"/d",L"/s",L"/c",L"for /L %i in (1,1,3000) do @echo stdout-%i & @echo stderr-%i 1>&2"},30000);
    ok &= require(dual.launched && !dual.timed_out && dual.exit_code == 0 &&
                  dual.stdout_text.find("stdout-3000") != std::string::npos &&
                  dual.stderr_text.find("stderr-3000") != std::string::npos, "concurrent stdout stderr drain");
    const auto timeout = runProcess(L"cmd.exe", {L"/d",L"/c",L"ping -n 12 127.0.0.1 >nul"},200);
    ok &= require(timeout.launched && timeout.timed_out, "timeout kills job");
    const auto missing = runProcess(L"Z:\\rawrxd_nonexistent_compiler_8a92.exe",{},1000);
    ok &= require(!missing.launched && missing.win32_error != 0, "missing compiler reported");
    return ok ? 0 : 1;
}
