// RAWRXD_LAYER0_SELFTEST_001 -- known-answer test for the guard's SHA-256.
// The empty string and "abc" have published digests. If the guard's
// self-contained implementation disagrees with either, the identity gate is
// comparing against a wrong value and will refuse every correct identity.
#include "deep2/Layer0Guard.hpp"
#include <cstdio>
#include <cstring>
#include <string>

int main() {
    struct { const char* in; const char* want; } kat[] = {
        { "",    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
        { "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
    };
    int bad = 0;
    for (auto& t : kat) {
        const std::string s(t.in);
        const std::wstring got =
            Deep2::Layer0::Sha256HexOfBytes(s.data(), s.size());
        std::string g;
        for (wchar_t c : got) g.push_back((char)(c < 128 ? c : '?'));
        std::string w(t.want);
        for (auto& c : w) if (c >= 'a' && c <= 'f') c = (char)(c - 32);
        const bool ok = (g == w);
        if (!ok) ++bad;
        std::printf("KAT input=\"%s\"\n  want=%s\n  got =%s\n  MATCH=%d\n",
                    t.in, w.c_str(), g.c_str(), ok ? 1 : 0);
    }
    std::printf("KAT_FAILED=%d\n", bad);
    return bad ? 1 : 0;
}
