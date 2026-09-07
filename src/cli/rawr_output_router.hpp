// rawr_output_router.hpp — stdout=text, stderr=diag, evidence=full
#pragma once
#include <cstdarg>
#include <cstdio>
#include <string>

namespace rawr {

inline void OutText(const char* s) {
    if (!s) return;
    fputs(s, stdout);
    fflush(stdout);
}
inline void OutTextLn(const std::string& s) {
    OutText(s.c_str());
    fputc('\n', stdout);
    fflush(stdout);
}
inline void Diag(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}
inline void DiagLn(const char* s) {
    if (!s) return;
    fputs(s, stderr);
    fputc('\n', stderr);
}

struct EvidenceWriter {
    FILE* f = nullptr;
    explicit EvidenceWriter(const char* path) {
        f = path ? fopen(path, "w") : nullptr;
    }
    ~EvidenceWriter() {
        if (f) fclose(f);
    }
    void line(const char* s) {
        if (f && s) {
            fputs(s, f);
            fputc('\n', f);
            fflush(f);
        }
        DiagLn(s);
    }
    void fmt(const char* format, ...) {
        char buf[1024];
        va_list ap;
        va_start(ap, format);
        vsnprintf(buf, sizeof(buf), format, ap);
        va_end(ap);
        line(buf);
    }
};

} // namespace rawr
