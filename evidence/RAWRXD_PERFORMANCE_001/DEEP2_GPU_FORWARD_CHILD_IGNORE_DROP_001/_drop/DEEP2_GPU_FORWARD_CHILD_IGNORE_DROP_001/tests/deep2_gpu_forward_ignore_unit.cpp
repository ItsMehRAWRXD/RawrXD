#include "../src/deep2/GPUForwardChildIgnore.hpp"
#include <cstdio>

using namespace RawrXD::Deep2::GpuForwardIgnore;

int main() {
    // Mechanics-only test. This is NOT model-runtime authority.
    BeginRun();
    MarkGpuForwardLayer();
    {
        Scope qkv(Child::QKV);
        if (!qkv.skipped()) {
            volatile std::uint64_t x = 0;
            for (std::uint64_t i = 0; i < 10000; ++i) x += i;
            (void)x;
        }
    }
    {
        Scope attn(Child::DeviceAttention);
        if (!attn.skipped()) {
            volatile std::uint64_t x = 1;
            for (std::uint64_t i = 1; i < 10000; ++i) x ^= i;
            (void)x;
        }
    }
    std::puts("UNIT_ONLY=1");
    std::puts("RUNTIME_AUTHORITY=0");
    EmitReceipt(stdout);
    return State::Get().config().valid ? 0 : 2;
}
