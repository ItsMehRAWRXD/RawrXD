#include "AttnCertProbe.hpp"

#include <cmath>
#include <cstring>
#include <mutex>

namespace Deep2 {
namespace AttnCert {
namespace {

std::mutex& mutex() {
    static std::mutex m;
    return m;
}
bool& enabledFlag() {
    static bool e = false;
    return e;
}
std::vector<Frame>& frames() {
    static std::vector<Frame> f;
    return f;
}

void digest(const float* data, std::size_t n, Frame& f) {
    f.count = static_cast<std::uint32_t>(n);
    f.nonfinite = 0;
    f.min = 0.0;
    f.max = 0.0;
    f.l2 = 0.0;
    f.sum = 0.0;
    f.sumAbs = 0.0;
    f.fnv = 14695981039346656037ull;
    if (!data || n == 0) return;

    bool any = false;
    double minV = 0.0, maxV = 0.0, sum = 0.0, sumAbs = 0.0, ss = 0.0;
    std::uint32_t nf = 0;
    std::uint64_t h = f.fnv;

    for (std::size_t i = 0; i < n; ++i) {
        const float v = data[i];
        std::uint32_t bits = 0;
        if (!std::isfinite(v)) {
            ++nf;
            bits = 0xFFFFFFFFu;
        } else {
            std::memcpy(&bits, &v, 4);
            const double d = static_cast<double>(v);
            if (!any) {
                minV = maxV = d;
                any = true;
            } else {
                if (d < minV) minV = d;
                if (d > maxV) maxV = d;
            }
            sum += d;
            sumAbs += (d < 0.0) ? -d : d;
            ss += d * d;
        }
        for (int b = 0; b < 4; ++b) {
            h ^= (bits >> (8 * b)) & 0xFFu;
            h *= 1099511628211ull;
        }
    }

    f.nonfinite = nf;
    f.fnv = h;
    if (nf == n) {
        f.l2 = -1.0;
        return;
    }
    f.min = minV;
    f.max = maxV;
    f.sum = sum;
    f.sumAbs = sumAbs;
    f.l2 = std::sqrt(ss);
}

} // namespace

void enable(bool on) {
    std::lock_guard<std::mutex> lock(mutex());
    enabledFlag() = on;
    // Intentionally do NOT clear frames on disable — harness snapshots after generate.
}

bool enabled() {
    std::lock_guard<std::mutex> lock(mutex());
    return enabledFlag();
}

void clear() {
    std::lock_guard<std::mutex> lock(mutex());
    frames().clear();
}

std::vector<Frame> snapshot() {
    std::lock_guard<std::mutex> lock(mutex());
    return frames();
}

void record(Stage stage, std::uint32_t layer, std::uint32_t position,
            const float* data, std::size_t n, double aux) {
    // Fast path without holding lock across digest work: check, digest, then push.
    bool on = false;
    {
        std::lock_guard<std::mutex> lock(mutex());
        on = enabledFlag();
    }
    if (!on) return;

    Frame f;
    f.stage = stage;
    f.layer = layer;
    f.position = position;
    f.aux = aux;
    if (data && n > 0) {
        digest(data, n, f);
    } else {
        f.count = static_cast<std::uint32_t>(n);
    }

    std::lock_guard<std::mutex> lock(mutex());
    if (!enabledFlag()) return;
    if (frames().size() < 8192) frames().push_back(f);
}

const char* stageName(Stage s) {
    switch (s) {
    case Stage::AttnNorm: return "ATTN_NORM";
    case Stage::QProj: return "Q";
    case Stage::KProj: return "K";
    case Stage::VProj: return "V";
    case Stage::RopeQ: return "ROPE_Q";
    case Stage::RopeK: return "ROPE_K";
    case Stage::KvWrite: return "KV_WRITE";
    case Stage::PreSoftmax: return "SCORE";
    case Stage::Softmax: return "SOFTMAX";
    case Stage::AttnOut: return "ATTN_OUT";
    case Stage::OProj: return "O_PROJ";
    case Stage::ResidualHint: return "POST_ATTN_RESIDUAL";
    case Stage::KvLength: return "KV_LENGTH";
    }
    return "UNKNOWN";
}

} // namespace AttnCert
} // namespace Deep2
