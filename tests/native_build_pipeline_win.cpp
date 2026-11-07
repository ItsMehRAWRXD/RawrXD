#ifdef _WIN32
#include "native_process_runner.hpp"
#include <windows.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using RawrXD::Build::RunProcess;
using RawrXD::Build::ProcessResult;

static bool pass(const ProcessResult& r) {
    return r.launched && !r.timed_out && r.error.empty() && r.exit_code == 0;
}

static bool write(const fs::path& p, const char* content) {
    std::ofstream f(p, std::ios::binary);
    f << content;
    return f.good();
}

int wmain() {
    wchar_t buffer[MAX_PATH]{};
    DWORD n = GetTempPathW(MAX_PATH, buffer);
    if (!n || n >= MAX_PATH) return 10;
    wchar_t unique[MAX_PATH]{};
    if (!GetTempFileNameW(buffer, L"rxb", 0, unique)) return 11;
    DeleteFileW(unique);
    const fs::path root(unique);
    std::error_code ec;
    if (!fs::create_directories(root, ec)) return 12;
    struct Cleanup {
        fs::path p;
        ~Cleanup() { std::error_code ec; fs::remove_all(p, ec); }
    } cleanup{root};

    if (!write(root / "lib.c", "int rawrxd_c(int x) { return x + 5; }\n") ||
        !write(root / "main.cpp",
               "extern \"C\" int rawrxd_c(int);\n"
               "int main() { return rawrxd_c(37) == 42 ? 0 : 17; }\n") ||
        !write(root / "bad.cpp",
               "extern int rawrxd_missing_symbol();\n"
               "int main() { return rawrxd_missing_symbol(); }\n")) return 13;

    // Every compiler and linker invocation goes through the same native
    // subprocess API that the IDE will consume.
    const auto c_obj = RunProcess({L"cl.exe", L"/nologo", L"/c",
        L"lib.c", L"/Folib.obj"}, root.wstring(), 30000);
    if (!pass(c_obj) || !fs::exists(root / "lib.obj")) {
        std::cerr << "C compile failed: " << c_obj.error << c_obj.stderr_text;
        return 20;
    }
    const auto cpp_obj = RunProcess({L"cl.exe", L"/nologo", L"/EHsc",
        L"/std:c++17", L"/c", L"main.cpp", L"/Fomain.obj"},
        root.wstring(), 30000);
    if (!pass(cpp_obj) || !fs::exists(root / "main.obj")) {
        std::cerr << "C++ compile failed: " << cpp_obj.error << cpp_obj.stderr_text;
        return 21;
    }
    const auto linked = RunProcess({L"link.exe", L"/nologo",
        L"main.obj", L"lib.obj", L"/OUT:fixture.exe"},
        root.wstring(), 30000);
    if (!pass(linked) || !fs::exists(root / "fixture.exe")) {
        std::cerr << "Link failed: " << linked.error << linked.stderr_text;
        return 22;
    }
    const auto executable = RunProcess({(root / "fixture.exe").wstring()},
                                       root.wstring(), 5000);
    if (!pass(executable)) {
        std::cerr << "Executable failed: " << executable.error;
        return 23;
    }
    const auto bad_obj = RunProcess({L"cl.exe", L"/nologo", L"/EHsc",
        L"/std:c++17", L"/c", L"bad.cpp", L"/Fobad.obj"},
        root.wstring(), 30000);
    if (!pass(bad_obj)) return 24;
    const auto bad_link = RunProcess({L"link.exe", L"/nologo",
        L"bad.obj", L"/OUT:bad.exe"}, root.wstring(), 30000);
    if (!bad_link.launched || bad_link.timed_out || bad_link.exit_code == 0 ||
        fs::exists(root / "bad.exe")) return 25;

    std::cout << "PASS: native runner C/C++ -> .obj -> link -> .exe -> run; "
                 "unresolved external rejected\n";
    return 0;
}
#endif
