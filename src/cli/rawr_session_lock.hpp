#pragma once
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif
namespace rawr {
struct SessionLock {
#ifdef _WIN32
    HANDLE h = nullptr;
#endif
    bool acquire(const std::string& id) {
#ifdef _WIN32
        std::string name = "Local\\rawrxd_sess_" + id;
        h = CreateMutexA(nullptr, TRUE, name.c_str());
        return h != nullptr && GetLastError() != ERROR_ALREADY_EXISTS;
#else
        (void)id; return true;
#endif
    }
    void release() {
#ifdef _WIN32
        if (h) { ReleaseMutex(h); CloseHandle(h); h = nullptr; }
#endif
    }
    ~SessionLock() { release(); }
};
} // namespace rawr
