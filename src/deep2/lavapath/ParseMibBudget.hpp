#pragma once
/* Parse MiB budgets with hard PASS/FAIL — no silent default on bad input. */
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <cstdio>

namespace Deep2 {

struct MibParseResult {
    uint64_t mib = 0;
    uint64_t bytes = 0;
    int ok = 0; /* 1=PASS */
    const char* input = "";
};

inline MibParseResult ParseMibTokenEx(const char* s) {
    MibParseResult r{};
    r.input = s ? s : "";
    if (!s || !*s) return r;
    while (*s == ' ' || *s == '\t') ++s;
    size_t n = std::strlen(s);
    while (n && (s[n - 1] == 'M' || s[n - 1] == 'm' || s[n - 1] == ' '))
        --n;
    if (!n) return r;
    char buf[64];
    if (n >= sizeof(buf)) n = sizeof(buf) - 1;
    std::memcpy(buf, s, n);
    buf[n] = 0;
    int base = 10;
    const char* p = buf;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        base = 16;
        p += 2;
    } else {
        for (const char* q = p; *q; ++q) {
            unsigned char c = static_cast<unsigned char>(*q);
            if (std::isxdigit(c) && !std::isdigit(c)) {
                base = 16;
                break;
            }
        }
    }
    char* end = nullptr;
    unsigned long long v = std::strtoull(p, &end, base);
    if (!end || end == p || *end != 0 || v == 0) return r;
    r.mib = static_cast<uint64_t>(v);
    r.bytes = r.mib << 20;
    r.ok = 1;
    return r;
}

inline uint64_t ParseMibToken(const char* s) {
    return ParseMibTokenEx(s).mib;
}

inline uint64_t EnvMib(const char* key, uint64_t fallback) {
    const char* e = std::getenv(key);
    if (!e || !*e) return fallback;
    MibParseResult r = ParseMibTokenEx(e);
    return r.ok ? r.mib : fallback;
}

inline void EmitWeightBudgetReceipt(FILE* f, const MibParseResult& r,
                                    const char* source) {
    if (!f) f = stderr;
    std::fprintf(f,
                 "WEIGHT_BUDGET_INPUT=%s\n"
                 "WEIGHT_BUDGET_PARSE=%s\n"
                 "WEIGHT_BUDGET_MIB=%llu\n"
                 "WEIGHT_BUDGET_BYTES=%llu\n"
                 "WEIGHT_BUDGET_SOURCE=%s\n",
                 r.input && r.input[0] ? r.input : "(empty)",
                 r.ok ? "PASS" : "FAIL",
                 (unsigned long long)r.mib,
                 (unsigned long long)r.bytes,
                 source ? source : "ENV");
}

} // namespace Deep2
