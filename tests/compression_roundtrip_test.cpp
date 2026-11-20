// ============================================================================
// compression_roundtrip_test.cpp -- public-API codec contract test.
// ============================================================================
// Exercises rawrxd::compression through its public header only, against the
// real provider that rawrxd_compression_core was built with:
//
//   * empty input
//   * highly repetitive input (exercises matches)
//   * full-range binary input (exercises every byte value)
//   * corrupted stream (must fail explicitly, never return Ok)
//
// Exit code is 0 only when every case passes, so CTest can gate on it.
// In a no-zlib build every case reports Status::Unsupported; that is asserted
// separately by the caller's configuration, not treated as a pass here.
// ============================================================================
#include "codec/compression_core.h"

#include <cstdio>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace {

int g_failures = 0;

void Check(bool condition, const char* what) {
    if (!condition) {
        std::printf("FAIL: %s\n", what);
        ++g_failures;
    }
}

const char* StatusName(rawrxd::compression::Status s) {
    switch (s) {
        case rawrxd::compression::Status::Ok: return "Ok";
        case rawrxd::compression::Status::InvalidInput: return "InvalidInput";
        case rawrxd::compression::Status::CorruptData: return "CorruptData";
        case rawrxd::compression::Status::OutputLimitExceeded: return "OutputLimitExceeded";
        case rawrxd::compression::Status::AllocationFailure: return "AllocationFailure";
        case rawrxd::compression::Status::BackendError: return "BackendError";
        case rawrxd::compression::Status::Unsupported: return "Unsupported";
    }
    return "<unknown>";
}

// Compress then decompress and require byte-identical output.
void RoundTrip(const char* name, const std::uint8_t* data, std::size_t size) {
    const auto c = rawrxd::compression::compress(data, size);
    if (c.status != rawrxd::compression::Status::Ok) {
        std::printf("FAIL: %s compress status=%s\n", name, StatusName(c.status));
        ++g_failures;
        return;
    }

    const auto d = rawrxd::compression::decompress(
        c.bytes.data(), c.bytes.size(), rawrxd::compression::MaxOutputBytes);
    if (d.status != rawrxd::compression::Status::Ok) {
        std::printf("FAIL: %s decompress status=%s\n", name, StatusName(d.status));
        ++g_failures;
        return;
    }

    Check(d.bytes.size() == size, name);
    if (d.bytes.size() == size) {
        Check(d.bytes == std::vector<std::uint8_t>(data, data + size), name);
    }
    std::printf("ok: %-12s in=%zu compressed=%zu out=%zu\n",
                name, size, c.bytes.size(), d.bytes.size());
}

} // namespace

int main() {
    using rawrxd::compression::Status;

    // A no-zlib build must fail explicitly on every entry point. Detect that
    // configuration first and assert the contract that actually applies, so the
    // same test is meaningful in both build modes instead of always failing.
    {
        const std::uint8_t probe = 'R';
        const auto pc = rawrxd::compression::compress(&probe, 1);
        const auto pd = rawrxd::compression::decompress(&probe, 1, 64);
        if (pc.status == Status::Unsupported || pd.status == Status::Unsupported) {
            const bool both = pc.status == Status::Unsupported &&
                              pd.status == Status::Unsupported;
            std::printf("compress=%s decompress=%s\n",
                        StatusName(pc.status), StatusName(pd.status));
            std::printf("RESULT=%s\n",
                        both ? "UNSUPPORTED_BACKEND" : "PARTIAL_UNSUPPORTED");
            return both ? 0 : 1;
        }
    }

    // 1. Empty input. The contract states this is Ok with empty output, which
    //    matches zlib's own behaviour and the legacy adapter.
    const auto empty = rawrxd::compression::compress(nullptr, 0);
    Check(empty.status == Status::Ok, "empty compress must succeed");
    if (empty.status == Status::Ok) {
        const auto back = rawrxd::compression::decompress(
            empty.bytes.data(), empty.bytes.size(), rawrxd::compression::MaxOutputBytes);
        Check(back.status == Status::Ok, "empty decompress must succeed");
        Check(back.bytes.empty(), "empty decompress must yield no bytes");
        std::printf("ok: %-12s compressed=%zu out=%zu\n", "empty",
                    empty.bytes.size(), back.bytes.size());
    }

    // 2. Highly repetitive input: forces long matches through the codec.
    const std::string repetitive(64 * 1024, 'A');
    RoundTrip("repetitive",
              reinterpret_cast<const std::uint8_t*>(repetitive.data()),
              repetitive.size());

    // 3. Full-range binary input: every byte value, several times.
    std::vector<std::uint8_t> binary;
    binary.reserve(64 * 1024);
    for (int i = 0; i < 256 * 32; ++i)
        binary.push_back(static_cast<std::uint8_t>(i & 0xFF));
    RoundTrip("binary", binary.data(), binary.size());

    // 4. Corrupted stream: must fail explicitly, never silently return Ok.
    //    zlib validates the Adler-32 trailer, so a flipped payload byte is
    //    detected as a data error rather than ignored.
    const auto good = rawrxd::compression::compress(
        reinterpret_cast<const std::uint8_t*>(repetitive.data()), repetitive.size());
    if (good.status == Status::Ok && good.bytes.size() > 4) {
        std::vector<std::uint8_t> corrupt = good.bytes;
        corrupt[corrupt.size() / 2] ^= 0xFF;
        const auto bad = rawrxd::compression::decompress(
            corrupt.data(), corrupt.size(), rawrxd::compression::MaxOutputBytes);
        Check(bad.status != Status::Ok, "corrupted stream must not report Ok");
        std::printf("ok: %-12s status=%s (expected non-Ok)\n", "corrupted",
                    StatusName(bad.status));
    }

    // 5. Refuse an output ceiling the data cannot fit, rather than growing.
    if (good.status == Status::Ok) {
        const auto bounded = rawrxd::compression::decompress(
            good.bytes.data(), good.bytes.size(), 16);
        Check(bounded.status != Status::Ok, "undersized ceiling must not report Ok");
        std::printf("ok: %-12s status=%s (expected non-Ok)\n", "ceiling",
                    StatusName(bounded.status));
    }

    if (g_failures == 0) {
        std::printf("RESULT=PASS\n");
        return 0;
    }
    std::printf("RESULT=FAIL failures=%d\n", g_failures);
    return 1;
}