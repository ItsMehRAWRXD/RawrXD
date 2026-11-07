#include "../src/compiler/native_process_runner.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
using namespace rawrxd::build;
namespace fs = std::filesystem;
static int failures = 0;
static void check(bool condition, const char* name) {
    std::cout << (condition ? "PASS " : "FAIL ") << name << '\n';
    if (!condition) ++failures;
}
static std::wstring wide(const fs::path& p) { return p.wstring(); }
static void write(const fs::path& p, const char* content) {
    std::ofstream file(p, std::ios::binary);
    file << content;
}
int wmain(int argc, wchar_t** argv) {
    if (argc >= 2 && std::wstring(argv[1]) == L"--flood") {
        for (int i = 0; i < 15000; ++i) {
            std::cout << "stdout message " << i << '\n';
            std::cerr << "stderr message " << i << '\n';
        }
        return 0;
    }
    if (argc >= 2 && std::wstring(argv[1]) == L"--sleep") {
        Sleep(10000);
        return 0;
    }
    const fs::path root = fs::temp_directory_path() / "rawrxd compiler fixture with spaces";
    fs::create_directories(root);
    const fs::path exe = fs::absolute(argv[0]);
    {
        ProcessSpec s{wide(exe), {L"--flood"}, wide(root), 15000, 1024};
        const auto r = runProcess(s);
        check(r.started && r.exitCode == 0 && !r.timedOut, "concurrent pipe drain");
        check(r.outputTruncated && r.stdoutText.size() <= 1024 &&
              r.stderrText.size() <= 1024, "bounded output capture");
    }
    {
        ProcessSpec s{wide(exe), {L"--sleep"}, wide(root), 150, 1024};
        const auto r = runProcess(s);
        check(r.started && r.timedOut, "enforced timeout");
    }
    {
        ProcessSpec s{L"Z:\\rawrxd-nonexistent-compiler.exe", {}, wide(root), 1000, 1024};
        const auto r = runProcess(s);
        check(!r.started && !r.error.empty(), "missing compiler fails closed");
    }
    // Compile actual C and C++ translation units to objects, then link and run.
    const auto c = root / "source c.c", cpp = root / "source cpp.cpp";
    const auto cObj = root / "source c.obj", cppObj = root / "source cpp.obj";
    const auto output = root / "linked executable.exe";
    write(c, "int c_answer(void) { return 40; }\n");
    write(cpp, "extern \"C\" int c_answer(void);\nint main() { return c_answer() == 40 ? 0 : 9; }\n");
    const auto run = [&](const std::vector<std::wstring>& args, DWORD timeout = 30000) {
        return runProcess(ProcessSpec{L"cl.exe", args, wide(root), timeout, 1024 * 1024});
    };
    auto a = run({L"/nologo", L"/c", L"/TC", wide(c), L"/Fo" + wide(cObj)});
    check(a.started && a.exitCode == 0 && fs::exists(cObj), "C source to object");
    auto b = run({L"/nologo", L"/c", L"/TP", wide(cpp), L"/Fo" + wide(cppObj)});
    check(b.started && b.exitCode == 0 && fs::exists(cppObj), "C++ source to object");
    if (fs::exists(cObj) && fs::exists(cppObj)) {
        auto link = runProcess(ProcessSpec{L"link.exe",
            {L"/NOLOGO", wide(cObj), wide(cppObj), L"/OUT:" + wide(output)},
            wide(root), 30000, 1024 * 1024});
        check(link.started && link.exitCode == 0 && fs::exists(output), "objects to linked executable");
        if (fs::exists(output)) {
            auto execution = runProcess(ProcessSpec{wide(output), {}, wide(root), 5000, 1024});
            check(execution.started && execution.exitCode == 0, "execute linked binary");
        }
    } else {
        check(false, "objects to linked executable");
        check(false, "execute linked binary");
    }
    std::cout << "compiler pipeline failures=" << failures << '\n';
    return failures ? 1 : 0;
}
