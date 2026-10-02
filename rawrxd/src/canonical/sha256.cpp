// ============================================================================
// sha256.cpp — FIPS 180-4 SHA-256
//
// See sha256.h for why this exists. Verified against the FIPS 180-4 sample
// vectors in tools/sha256_selftest.cpp, which is a ctest target.
// ============================================================================
#include "sha256.h"

#include <cstdio>
#include <cstring>
#include <vector>

namespace rawrxd {
namespace sha256 {

namespace {

constexpr uint32_t kK[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu,
    0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u,
    0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u,
    0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u,
    0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u,
    0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u, 0x1e376c08u,
    0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu,
    0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

inline uint32_t Ror(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

}  // namespace

void Sha256::Reset() {
    state_[0] = 0x6a09e667u; state_[1] = 0xbb67ae85u;
    state_[2] = 0x3c6ef372u; state_[3] = 0xa54ff53au;
    state_[4] = 0x510e527fu; state_[5] = 0x9b05688cu;
    state_[6] = 0x1f83d9abu; state_[7] = 0x5be0cd19u;
    bitLen_ = 0;
    totalBytes_ = 0;
    bufLen_ = 0;
}

void Sha256::Compress(const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = (uint32_t(block[i * 4 + 0]) << 24) |
               (uint32_t(block[i * 4 + 1]) << 16) |
               (uint32_t(block[i * 4 + 2]) << 8) |
               (uint32_t(block[i * 4 + 3]));
    }
    for (int i = 16; i < 64; ++i) {
        const uint32_t s0 = Ror(w[i - 15], 7) ^ Ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const uint32_t s1 = Ror(w[i - 2], 17) ^ Ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
    uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];

    for (int i = 0; i < 64; ++i) {
        const uint32_t S1 = Ror(e, 6) ^ Ror(e, 11) ^ Ror(e, 25);
        const uint32_t ch = (e & f) ^ (~e & g);
        const uint32_t t1 = h + S1 + ch + kK[i] + w[i];
        const uint32_t S0 = Ror(a, 2) ^ Ror(a, 13) ^ Ror(a, 22);
        const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const uint32_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
    state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
}

void Sha256::Update(const void* data, size_t len) {
    const auto* p = static_cast<const uint8_t*>(data);
    totalBytes_ += len;
    bitLen_ += uint64_t(len) * 8u;

    if (bufLen_ > 0) {
        const size_t take = (64 - bufLen_ < len) ? (64 - bufLen_) : len;
        std::memcpy(buf_ + bufLen_, p, take);
        bufLen_ += take;
        p += take;
        len -= take;
        if (bufLen_ == 64) { Compress(buf_); bufLen_ = 0; }
    }
    while (len >= 64) { Compress(p); p += 64; len -= 64; }
    if (len > 0) { std::memcpy(buf_, p, len); bufLen_ = len; }
}

void Sha256::Final(uint8_t out[32]) {
    const uint64_t bits = bitLen_;
    uint8_t pad = 0x80;
    Update(&pad, 1);
    // Update() advanced bitLen_; the padding is not part of the message length.
    pad = 0x00;
    while (bufLen_ != 56) { Update(&pad, 1); }
    uint8_t lenBytes[8];
    for (int i = 0; i < 8; ++i) {
        lenBytes[7 - i] = uint8_t((bits >> (i * 8)) & 0xFFu);
    }
    // Append the length directly rather than through Update, so bitLen_ is not
    // perturbed by the length field itself.
    std::memcpy(buf_ + bufLen_, lenBytes, 8);
    Compress(buf_);
    bufLen_ = 0;

    for (int i = 0; i < 8; ++i) {
        out[i * 4 + 0] = uint8_t((state_[i] >> 24) & 0xFFu);
        out[i * 4 + 1] = uint8_t((state_[i] >> 16) & 0xFFu);
        out[i * 4 + 2] = uint8_t((state_[i] >> 8) & 0xFFu);
        out[i * 4 + 3] = uint8_t((state_[i]) & 0xFFu);
    }
}

std::string HexDigest(const uint8_t digest[32]) {
    static const char* kHex = "0123456789abcdef";
    std::string s;
    s.resize(64);
    for (int i = 0; i < 32; ++i) {
        s[i * 2 + 0] = kHex[(digest[i] >> 4) & 0x0F];
        s[i * 2 + 1] = kHex[digest[i] & 0x0F];
    }
    return s;
}

std::string HexOfBuffer(const void* data, size_t len) {
    Sha256 h;
    h.Update(data, len);
    uint8_t d[32];
    h.Final(d);
    return HexDigest(d);
}

std::string HexOfFile(const std::string& path) {
    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return std::string();
    Sha256 h;
    std::vector<unsigned char> buf(1 << 20);
    for (;;) {
        const size_t n = std::fread(buf.data(), 1, buf.size(), f);
        if (n == 0) break;
        h.Update(buf.data(), n);
    }
    const bool bad = std::ferror(f) != 0;
    std::fclose(f);
    if (bad) return std::string();
    uint8_t d[32];
    h.Final(d);
    return HexDigest(d);
}

bool EqualDigest(const std::string& a, const std::string& b) {
    auto norm = [](const std::string& s) {
        std::string t;
        t.reserve(64);
        for (char c : s) {
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
            t.push_back(char((c >= 'A' && c <= 'F') ? (c - 'A' + 'a') : c));
        }
        return t;
    };
    const std::string x = norm(a);
    const std::string y = norm(b);
    if (x.size() != 64 || y.size() != 64) return false;
    return x == y;
}

}  // namespace sha256
}  // namespace rawrxd