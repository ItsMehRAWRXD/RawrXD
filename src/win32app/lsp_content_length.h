// lsp_content_length.h — strict LSP Content-Length parser.
// Shared by the LSP reader (Win32IDE_LSPClient.cpp) and the acceptance test
// (lsp_content_length_test.cpp) so the test exercises the REAL code path.
#pragma once
#include <string>
#include <cstddef>

namespace rawrxd {

// Parses the value that follows "Content-Length:" starting at valStart.
// Accepts only pure decimal digits, bounded by kMaxLspMessage, with no trailing
// garbage. Returns true and sets out on success; returns false and sets out = 0
// on any empty / non-numeric / negative / zero / overflow / oversized / trailing
// garbage input (the caller then drops the frame).
inline bool ParseLspContentLength(const std::string& header, std::size_t valStart, int& out) {
    constexpr long long kMaxLspMessage = 256LL * 1024 * 1024;  // 256 MB
    long long value = 0;
    std::size_t digits = 0;
    bool overflow = false;
    std::size_t i = valStart;
    while (i < header.size() && header[i] >= '0' && header[i] <= '9') {
        const int d = header[i] - '0';
        if (value > (kMaxLspMessage - d) / 10) { overflow = true; break; }
        value = value * 10 + d;
        ++digits;
        ++i;
    }
    const bool trailingGarbage = (i < header.size() && header[i] != '\r');
    if (digits == 0 || overflow || trailingGarbage ||
        value <= 0 || value > kMaxLspMessage) {
        out = 0;
        return false;
    }
    out = static_cast<int>(value);
    return true;
}

} // namespace rawrxd