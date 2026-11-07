// Compile with MSVC developer environment: cl /std:c++17 /EHsc /W4 this_file.cpp
// Run from any directory. Uses a temp directory and the real MSVC cl/link tools.
#include "../src/core/windows_subprocess_runner.h"
#include <windows.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
using rawrxd::build::run;
namespace fs = std::filesystem;
static void require(bool ok, const char* why) { if (!ok) throw std::runtime_error(why); }
static void check(const rawrxd::build::ProcessResult& p, const char* stage) {
    if (p.timedOut || !p.error.empty() || p.exitCode != 0) {
        std::cerr << stage << " exit=" << p.exitCode << " timeout=" << p.timedOut
                  << " error=" << p.error << "\nstdout:\n" << p.stdoutText
                  << "\nstderr:\n" << p.stderrText << "\n";
        throw std::runtime_error(stage);
    }
}
int wmain() {
    try {
        wchar_t temp[MAX_PATH]{};
        require(GetTempPathW(MAX_PATH, temp) != 0, "GetTempPathW failed");
        fs::path dir = fs::path(temp) / (L"rawrxd-compiler-" + std::to_wstring(GetCurrentProcessId()));
        fs::create_directories(dir);
        struct Cleanup { fs::path p; ~Cleanup() { std::error_code ec; fs::remove_all(p, ec); } } cleanup{dir};
        fs::path src = dir / L"smoke.cpp", obj = dir / L"smoke.obj", exe = dir / L"smoke.exe";
        {
            std::ofstream code(src);
            code << "#include <iostream>\nint main(){std::cout<<\"RAWRXD_PIPELINE_OK\\n\";return 0;}\n";
        }
        check(run({L"cl.exe", L"/nologo", L"/EHsc", L"/c", src.wstring(), L"/Fo" + obj.wstring()}, dir.wstring(), 60000), "compile");
        require(fs::exists(obj), "compiler did not create object");
        check(run({L"link.exe", L"/nologo", obj.wstring(), L"/OUT:" + exe.wstring()}, dir.wstring(), 60000), "link");
        require(fs::exists(exe), "linker did not create executable");
        auto execution = run({exe.wstring()}, dir.wstring(), 10000);
        check(execution, "execute");
        require(execution.stdoutText.find("RAWRXD_PIPELINE_OK") != std::string::npos, "executable output mismatch");
        // A compiler error must propagate as a nonzero process exit.
        fs::path invalid = dir / L"invalid.cpp";
        {
            std::ofstream code(invalid);
            code << "int main( { this is invalid C++ }\\n";
        }
        auto compileFailure = run({L"cl.exe", L"/nologo", L"/c", invalid.wstring()}, dir.wstring(), 30000);
        require(!compileFailure.timedOut && compileFailure.error.empty() &&
                compileFailure.exitCode != 0, "invalid C++ unexpectedly compiled");
        require(!compileFailure.stdoutText.empty() || !compileFailure.stderrText.empty(),
                "compiler diagnostics were lost");
        // Concurrent stream capture must not deadlock on large independent outputs.
        fs::path streams = dir / L"streams.cpp", streamsExe = dir / L"streams.exe";
        {
            std::ofstream code(streams);
            code << "#include <cstdio>\nint main(){for(int i=0;i<20000;++i){"
                    "std::fputs(\"stdout-data\\n\",stdout);std::fputs(\"stderr-data\\n\",stderr);}"
                    "return 0;}\n";
        }
        check(run({L"cl.exe", L"/nologo", L"/EHsc", streams.wstring(), L"/Fe:" + streamsExe.wstring()}, dir.wstring(), 60000), "streams build");
        auto captured = run({streamsExe.wstring()}, dir.wstring(), 30000);
        check(captured, "concurrent streams");
        require(captured.stdoutText.size() > 100000 && captured.stderrText.size() > 100000, "stream capture truncated");
        // Timeout must kill a real process and return promptly.
        auto timeout = run({L"cmd.exe", L"/d", L"/c", L"ping -n 30 127.0.0.1 >NUL"}, dir.wstring(), 500);
        require(timeout.timedOut, "timeout was not enforced");
        std::cout << "PASS: MSVC compile/object/link/exe, dual streams, enforced timeout\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAIL: " << e.what() << "\n";
        return 1;
    }
}
