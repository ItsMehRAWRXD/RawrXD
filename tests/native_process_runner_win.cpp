#ifdef _WIN32
#include "native_process_runner.hpp"
#include <windows.h>
#include <iostream>
#include <string>
#include <vector>

int wmain(int argc, wchar_t** argv) {
    if (argc > 1 && std::wstring(argv[1]) == L"--fixture") {
        std::cout << "STDOUT_MARKER\n";
        std::cerr << "STDERR_MARKER\n";
        return 23;
    }
    if (argc > 1 && std::wstring(argv[1]) == L"--sleep") {
        Sleep(10000);
        return 0;
    }
    if (argc > 1 && std::wstring(argv[1]) == L"--flood") {
        for (int i = 0; i < 50000; ++i) {
            std::cout << "out-" << i << "\n";
            std::cerr << "err-" << i << "\n";
        }
        return 0;
    }
    if (argc > 1 && std::wstring(argv[1]) == L"--echo") {
        std::wcout << argv[2] << L"\n";
        return 0;
    }
    using RawrXD::Build::RunProcess;
    const std::wstring self = argv[0];
    const auto basic = RunProcess({self, L"--fixture"}, L"", 5000);
    if (!basic.launched || basic.timed_out || basic.exit_code != 23 ||
        basic.stdout_text.find("STDOUT_MARKER") == std::string::npos ||
        basic.stderr_text.find("STDERR_MARKER") == std::string::npos) return 1;

    const auto flood = RunProcess({self, L"--flood"}, L"", 15000);
    if (!flood.launched || flood.timed_out || flood.exit_code != 0 ||
        flood.stdout_text.find("out-49999") == std::string::npos ||
        flood.stderr_text.find("err-49999") == std::string::npos) return 2;

    const auto timeout = RunProcess({self, L"--sleep"}, L"", 200);
    if (!timeout.launched || !timeout.timed_out) return 3;

    const auto missing = RunProcess({L"rawrxd_missing_executable_9ac88.exe"}, L"", 1000);
    if (missing.launched || missing.error.empty()) return 4;

    const auto quoted = RunProcess({self, L"--echo", L"two words with \"quotes\""}, L"", 5000);
    if (!quoted.launched || quoted.exit_code != 0 ||
        quoted.stdout_text.find("two words with \"quotes\"") == std::string::npos) return 5;

    std::cout << "PASS: concurrent capture, flood, timeout, missing exe, quoting\n";
    return 0;
}
#endif
