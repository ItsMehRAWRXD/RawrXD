// SHA-256 implementation (FIPS 180-4).

#include "rawrstd/sha256.h"

#include "rawrstd/sys.h"
#include "rawrstd/vector.h"

namespace rawrstd {

namespace {

const uint32 kK[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

inline uint32 rotr(uint32 x, uint32 n) { return (x >> n) | (x << (32 - n)); }

void sha256_block(uint32* h, const uint8* p) {
    uint32 w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = (static_cast<uint32>(p[i * 4]) << 24) |
               (static_cast<uint32>(p[i * 4 + 1]) << 16) |
               (static_cast<uint32>(p[i * 4 + 2]) << 8) |
               static_cast<uint32>(p[i * 4 + 3]);
    }
    for (int i = 16; i < 64; ++i) {
        uint32 s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32 s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32 a = h[0], b = h[1], c = h[2], d = h[3];
    uint32 e = h[4], f = h[5], g = h[6], hh = h[7];

    for (int i = 0; i < 64; ++i) {
        uint32 S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32 ch = (e & f) ^ ((~e) & g);
        uint32 t1 = hh + S1 + ch + kK[i] + w[i];
        uint32 S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32 maj = (a & b) ^ (a & c) ^ (b & c);
        uint32 t2 = S0 + maj;

        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

} // namespace

void sha256_hex(const void* data, size_type size, char* out) {
    uint32 h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    const uint8* p = static_cast<const uint8*>(data);
    size_type remaining = size;

    while (remaining >= 64) {
        sha256_block(h, p);
        p += 64;
        remaining -= 64;
    }

    // The tail: message bytes, a 0x80 byte, zero padding, and the length
    // in bits as a 64-bit big-endian value.
    uint8 tail[128];
    size_type tail_len = 0;
    for (size_type i = 0; i < remaining; ++i) tail[tail_len++] = p[i];
    tail[tail_len++] = 0x80;

    size_type pad_to = (tail_len <= 56) ? 56 : 120;
    while (tail_len < pad_to) tail[tail_len++] = 0;

    uint64 bits = static_cast<uint64>(size) * 8;
    for (int i = 7; i >= 0; --i) {
        tail[tail_len++] = static_cast<uint8>((bits >> (i * 8)) & 0xFF);
    }

    for (size_type i = 0; i < tail_len; i += 64) {
        sha256_block(h, tail + i);
    }

    static const char kHex[] = "0123456789abcdef";
    for (int i = 0; i < 8; ++i) {
        for (int j = 0; j < 4; ++j) {
            uint8 byte = static_cast<uint8>((h[i] >> ((3 - j) * 8)) & 0xFF);
            out[i * 8 + j * 2] = kHex[byte >> 4];
            out[i * 8 + j * 2 + 1] = kHex[byte & 0x0F];
        }
    }
}

String sha256_file(const char* path) {
    File f;
    if (!f.open(path, FileMode::Read)) return String();

    // Read the whole file so the digest covers it exactly.
    Vector<uint8> data;
    char buffer[65536];
    for (;;) {
        int64 got = f.read(buffer, sizeof(buffer));
        if (got <= 0) break;
        for (int64 i = 0; i < got; ++i) {
            data.push_back(static_cast<uint8>(buffer[i]));
        }
    }
    f.close();

    char hex[64];
    sha256_hex(data.empty() ? (const void*)"" : (const void*)data.data(),
               data.size(), hex);
    return String(hex, 64);
}

} // namespace rawrstd
