#pragma once

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <string_view>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace RawrXD {

enum class ExitCode : std::int32_t {
    SUCCESS = 0,
    GENERAL_ERROR = 1,
    INVALID_ARGUMENT = 2,
    MODEL_NOT_FOUND = 3,
    VRAM_ALLOCATION_FAILURE = 4,
    GATE_VERIFICATION_FAILED = 5,
    STREAMING_PIPE_ERROR = 6,
    HEADLESS_REQUIRED = 2
};

class ErrorLevelHandler {
public:
    static void set_error_level(ExitCode code) {
        std::int32_t numeric_code = static_cast<std::int32_t>(code);
#ifdef _WIN32
        // Use standard C exit, not system("exit /b ...")
        std::exit(numeric_code);
#else
        std::exit(numeric_code);
#endif
    }

    static std::int32_t get_current_error_level(ExitCode code) {
        return static_cast<std::int32_t>(code);
    }

    [[noreturn]] static void report_and_exit(ExitCode code, const std::string& context_message) {
        std::cerr << "[ErrorLevelHandler] Exit code " << static_cast<std::int32_t>(code)
                  << ": " << context_message << std::endl;

#ifdef _WIN32
        // Only show MessageBox in interactive sessions
        if (interactive_session()) {
            std::wstring wmsg(context_message.begin(), context_message.end());
            MessageBoxW(nullptr, wmsg.c_str(), L"RawrXD Fatal Error", MB_OK | MB_ICONERROR | MB_SYSTEMMODAL);
        }
#endif
        std::exit(static_cast<std::int32_t>(code));
    }

private:
#ifdef _WIN32
    static bool interactive_session() noexcept {
        HWINSTA ws = GetProcessWindowStation();
        if (!ws) return false;

        WCHAR name[64] = {};
        DWORD len = 0;
        if (!GetUserObjectInformationW(ws, UOI_NAME, name, sizeof(name), &len)) {
            return false;
        }

        // WinSta0 is the interactive window station
        return std::wstring_view(name) == L"WinSta0";
    }
#endif
};

} // namespace RawrXD
