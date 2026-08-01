#include "StdReplacements.hpp"
#include "RawrXD_Agent.hpp"
#include "../src/masm/RawrXD_NativeHttpServer.h"
#include <iostream>
#include <algorithm>
#include <cctype>

namespace {
    RawrXD::NativeHttpServerPtr g_httpServer;
    volatile bool g_consoleExitRequested = false;

    BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType) {
        if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_BREAK_EVENT || ctrlType == CTRL_CLOSE_EVENT) {
            g_consoleExitRequested = true;
            return TRUE;
        }
        return FALSE;
    }

    static void TrimInput(RawrXD::String& s) {
        auto start = s.find_first_not_of(L" \t\r\n");
        if (start == RawrXD::String::npos) {
            s.clear();
            return;
        }
        auto end = s.find_last_not_of(L" \t\r\n");
        s = s.substr(start, end == RawrXD::String::npos ? RawrXD::String::npos : end - start + 1);
    }

