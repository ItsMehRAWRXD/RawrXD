// StallCausalGraph.hpp — STALL ms → physical causes
#pragma once
#include <cstdio>
#include <string>

namespace Deep2 {
namespace TimeReversal {

struct StallCause {
    const char* name = "";
    double ms = 0.0;
};

struct StallGraph {
    double totalStallMs = 0.0;
    StallCause causes[12]{};
    int count = 0;
    double unknownMs = 0.0;

    void Add(const char* name, double ms) {
        if (count >= 12) { unknownMs += ms; return; }
        causes[count++] = {name, ms};
        totalStallMs += ms;
    }
};

inline std::string FormatStallGraph(const StallGraph& g) {
    char buf[768];
    int n = std::snprintf(buf, sizeof(buf), "STALL %.2f ms\n", g.totalStallMs);
    for (int i = 0; i < g.count && n < (int)sizeof(buf) - 48; ++i) {
        n += std::snprintf(buf + n, sizeof(buf) - n, "  ├─ %-24s %6.2f ms\n",
                           g.causes[i].name, g.causes[i].ms);
    }
    if (g.unknownMs > 0.0)
        n += std::snprintf(buf + n, sizeof(buf) - n, "  └─ UNKNOWN %6.2f ms\n",
                           g.unknownMs);
    return std::string(buf);
}

} // namespace TimeReversal
} // namespace Deep2
