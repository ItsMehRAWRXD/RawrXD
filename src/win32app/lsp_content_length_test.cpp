// lsp_content_length_test.cpp — acceptance tests for the strict LSP
// Content-Length parser (Package 3). Exercises the real parser via the shared
// header. Exit 0 = all pass, non-zero = failure count.
#include "lsp_content_length.h"
#include <cstdio>
#include <string>

namespace {
int g_fail = 0;

void expect(const char* name, const std::string& header, std::size_t valStart,
            bool wantOk, int wantVal) {
    int out = -1;
    const bool ok = rawrxd::ParseLspContentLength(header, valStart, out);
    const bool pass = (ok == wantOk) && (!wantOk || out == wantVal);
    std::printf("[%s] %-24s ok=%d out=%d (want ok=%d val=%d)\n",
                pass ? "PASS" : "FAIL", name, static_cast<int>(ok), out,
                static_cast<int>(wantOk), wantVal);
    if (!pass) ++g_fail;
}
} // namespace

int main() {
    // valStart = index just past "Content-Length:" (and any leading spaces).
    expect("valid",              "Content-Length: 42",                  16, true, 42);
    expect("empty",              "Content-Length:",                     15, false, 0);
    expect("alpha",              "Content-Length: abc",                 16, false, 0);
    expect("overflow",           "Content-Length: 99999999999999999999",16, false, 0);
    expect("negative",          "Content-Length: -5",                  16, false, 0);
    expect("zero",              "Content-Length: 0",                   16, false, 0);
    expect("trailing-garbage",  "Content-Length: 123abc",              16, false, 0);
    expect("oversized",         "Content-Length: 268435457",           16, false, 0);
    expect("valid-then-header", "Content-Length: 7\r\nContent-Type: x",16, true, 7);
    expect("max-ok",            "Content-Length: 268435456",           16, true, 268435456);

    std::printf(g_fail ? "RESULT: FAIL (%d)\n" : "RESULT: PASS\n", g_fail);
    return g_fail ? 1 : 0;
}