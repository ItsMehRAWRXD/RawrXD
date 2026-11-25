// Standalone acceptance test for Deep2::matchAdapter (exact LUID identity).
// Compile: g++ -std=c++17 -O2 -Wall -Wextra adapter_identity_test.cpp -o t && t
#include "../../../src/deep2/AdapterIdentity.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstdint>

using namespace Deep2;

#define CHECK(x) do { if (!(x)) { std::fprintf(stderr, "FAIL: %s\n", #x); std::exit(1); } } while (0)

int main() {
    // Two distinct physical adapters with valid, different LUIDs.
    std::vector<AdapterRef> vk = {
        {0x1122334455667788ull, true, 0x1002, 0x7301, true,  true,  32624ull << 20}, // R9700
        {0xAABBCCDDEEFF0011ull, true, 0x1002, 0x7800, true,  true,  16368ull << 20}, // RX 7800 XT
    };

    // 1) VALID: exact LUID match -> authoritative, strict-capable.
    AdapterMatch a = matchAdapter(0x1122334455667788ull, 0x1002, 0x7301, vk);
    CHECK(a.exact);
    CHECK(!a.ambiguous);
    CHECK(a.compute);
    CHECK(a.deviceLocalBytes == (32624ull << 20));

    // 2) VALID second adapter.
    AdapterMatch b = matchAdapter(0xAABBCCDDEEFF0011ull, 0x1002, 0x7800, vk);
    CHECK(b.exact && b.deviceLocalBytes == (16368ull << 20));

    // 3) INVALID: LUID present but not found -> ambiguous, non-strict.
    AdapterMatch c = matchAdapter(0x9999999999999999ull, 0x1002, 0x7301, vk);
    CHECK(!c.exact);
    CHECK(c.ambiguous);
    CHECK(c.compute);              // best-effort via vendor/device
    CHECK(c.deviceLocalBytes == 0); // NOT overridden without exact identity

    // 4) MISSING: dxgi LUID is 0 (unknown) -> ambiguous even if vendor/device match.
    AdapterMatch d = matchAdapter(0, 0x1002, 0x7301, vk);
    CHECK(!d.exact && d.ambiguous);

    // 5) MISSING on Vulkan side: Vulkan adapter has no valid LUID.
    std::vector<AdapterRef> vkNoLuid = {
        {0, false, 0x1002, 0x7301, true, true, 32624ull << 20},
    };
    AdapterMatch e = matchAdapter(0x1122334455667788ull, 0x1002, 0x7301, vkNoLuid);
    CHECK(!e.exact && e.ambiguous);   // cannot authoritatively match

    // 6) DUPLICATE vendor/device (two identical cards): exact LUID disambiguates.
    std::vector<AdapterRef> dup = {
        {0xAAAA000000000001ull, true, 0x1002, 0x7301, true, true, 32624ull << 20},
        {0xAAAA000000000002ull, true, 0x1002, 0x7301, true, true, 32624ull << 20},
    };
    AdapterMatch f = matchAdapter(0xAAAA000000000002ull, 0x1002, 0x7301, dup);
    CHECK(f.exact);                   // exact LUID picks the right one of two identical
    AdapterMatch g = matchAdapter(0, 0x1002, 0x7301, dup);
    CHECK(!g.exact && g.ambiguous);   // no LUID -> ambiguous, non-strict

    std::printf("valid=%d invalid=%d missing=%d duplicate=%d\n",
                (a.exact && b.exact) ? 1 : 0,
                (!c.exact && c.ambiguous) ? 1 : 0,
                (!d.exact && !e.exact) ? 1 : 0,
                (f.exact && !g.exact) ? 1 : 0);
    std::printf("ADAPTER_IDENTITY_ACCEPTANCE PASS\n");
    return 0;
}