#include "deep2/Layer0Guard.hpp"
#include <cstdio>
#include <string>

static std::string Wide(const std::wstring& w) {
    std::string s; for (wchar_t c : w) s.push_back((char)(c < 128 ? c : '?')); return s;
}
int main(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        std::wstring w;
        for (const char* p = argv[i]; *p; ++p) w.push_back((wchar_t)(unsigned char)*p);
        const std::wstring got = Deep2::Layer0::HashFileSha256(w.c_str());
        std::printf("GUARD %s %s\n", argv[i], Wide(got).c_str());
    }
    return 0;
}