// Windows real toolchain acceptance: C and C++ source -> object -> executable.
// No Ollama, model, GPU or GUI is involved.
#include "../~dev/rawrxd/src/reverse_engineering/RawrCompiler.hpp"
#include <windows.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

int main() {
    using namespace RawrXD::ReverseEngineering;
    namespace fs = std::filesystem;
    RawrCompiler compiler;
    const fs::path base = fs::temp_directory_path() /
        ("rawr-compiler-e2e-" + std::to_string(GetCurrentProcessId()));
    fs::create_directories(base);
    int failures = 0;
    auto check = [&](bool value, const char* name) {
        std::cout << (value ? "PASS " : "FAIL ") << name << '\n';
        if (!value) ++failures;
    };
    const fs::path cfile = base / "fixture.c";
    const fs::path cppfile = base / "fixture.cpp";
    { std::ofstream out(cfile); out << "int main(void){return 0;}\n"; }
    { std::ofstream out(cppfile); out << "int main(){return 0;}\n"; }
    const auto c = compiler.CompileSource(cfile.string());
    check(c.success, "01 compile C source");
    check(c.success && fs::is_regular_file(c.objectFile), "02 C object exists");
    const auto cpp = compiler.CompileSource(cppfile.string());
    check(cpp.success, "03 compile C++ source");
    check(cpp.success && fs::is_regular_file(cpp.objectFile), "04 C++ object exists");
    const fs::path cexe = base / "fixture-c.exe";
    const fs::path cppexe = base / "fixture-cpp.exe";
    check(c.success && compiler.Link({c.objectFile}, cexe.string()), "05 link C executable");
    check(cpp.success && compiler.Link({cpp.objectFile}, cppexe.string()), "06 link C++ executable");
    check(fs::is_regular_file(cexe), "07 C executable exists");
    check(fs::is_regular_file(cppexe), "08 C++ executable exists");
    auto execute = [](const fs::path& exe) {
        if (!fs::is_regular_file(exe)) return false;
        STARTUPINFOA si{}; si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        std::string cmd = "\"" + exe.string() + "\"";
        std::vector<char> mutableCmd(cmd.begin(), cmd.end());
        mutableCmd.push_back('\0');
        if (!CreateProcessA(nullptr, mutableCmd.data(), nullptr, nullptr, FALSE,
                            CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) return false;
        const DWORD wait = WaitForSingleObject(pi.hProcess, 5000);
        if (wait != WAIT_OBJECT_0) {
            TerminateProcess(pi.hProcess, 1);
            WaitForSingleObject(pi.hProcess, 5000);
        }
        DWORD code = 1;
        const BOOL ok = GetExitCodeProcess(pi.hProcess, &code);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return wait == WAIT_OBJECT_0 && ok && code == 0;
    };
    check(execute(cexe), "09 run C executable");
    check(execute(cppexe), "10 run C++ executable");
    const auto invalid = compiler.CompileString("this is invalid C++ !!!", "cpp");
    check(!invalid.success, "11 invalid source rejected");
    check(!compiler.Link({(base / "missing.o").string()}, (base / "bad.exe").string()),
          "12 missing object rejected");
    const auto jit = compiler.CompileAndLoadJIT("int main(){return 0;}");
    check(jit.codePtr == nullptr && jit.codeSize == 0, "13 JIT unavailable fails closed");
    std::error_code ec;
    fs::remove_all(base, ec);
    std::cout << "RESULT " << (13 - failures) << "/13 checks; "
              << (failures ? "FAIL" : "PASS") << '\n';
    return failures ? 1 : 0;
}
