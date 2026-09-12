// rawr_out_gate.hpp — product stdout = model text only
#pragma once
#include <cstddef>
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#include <cstdio>
#endif
namespace rawr {
struct OutGate {
#ifdef _WIN32
    int real = -1;
    OutGate() {
        fflush(stdout);
        real = _dup(1);
        if (real >= 0) _dup2(2, 1);
    }
    ~OutGate() {
        fflush(stdout);
        if (real >= 0) {
            _dup2(real, 1);
            _close(real);
        }
    }
    void emit(const char* t, size_t n) const {
        if (real >= 0 && t && n) _write(real, t, (unsigned)n);
    }
#else
    void emit(const char* t, size_t n) const {
        if (t && n) {
            fwrite(t, 1, n, stdout);
            fflush(stdout);
        }
    }
#endif
};
} // namespace rawr
