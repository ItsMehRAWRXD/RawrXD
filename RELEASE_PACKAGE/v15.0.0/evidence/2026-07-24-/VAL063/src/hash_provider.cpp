#include "hash_provider.hpp"
#include <fstream>
#include <vector>

// Simple SHA-256 implementation for Gate A
// Based on public domain implementation

namespace val063 {

namespace {

// SHA-256 constants
constexpr uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Rotate right
inline uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

// SHA-256 functions
inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

inline uint32_t ep0(uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

inline uint32_t ep1(uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

inline uint32_t sig0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

inline uint32_t sig1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

} // anonymous namespace

class HashProvider::Impl {
public:
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t data[64];
    uint32_t datalen;

    Impl() {
        reset();
    }

    void reset() {
        state[0] = 0x6a09e667;
        state[1] = 0xbb67ae85;
        state[2] = 0x3c6ef372;
        state[3] = 0xa54ff53a;
        state[4] = 0x510e527f;
        state[5] = 0x9b05688c;
        state[6] = 0x1f83d9ab;
        state[7] = 0x5be0cd19;
        bitlen = 0;
        datalen = 0;
    }

    void transform(const uint8_t* data) {
        uint32_t m[64];
        uint32_t i, j;

        // Convert to big-endian 32-bit words
        for (i = 0, j = 0; i < 16; ++i, j += 4) {
            m[i] = (static_cast<uint32_t>(data[j]) << 24) |
                   (static_cast<uint32_t>(data[j + 1]) << 16) |
                   (static_cast<uint32_t>(data[j + 2]) << 8) |
                   (static_cast<uint32_t>(data[j + 3]));
        }

        // Extend
        for (; i < 64; ++i) {
            m[i] = sig1(m[i - 2]) + m[i - 7] + sig0(m[i - 15]) + m[i - 16];
        }

        uint32_t a = state[0];
        uint32_t b = state[1];
        uint32_t c = state[2];
        uint32_t d = state[3];
        uint32_t e = state[4];
        uint32_t f = state[5];
        uint32_t g = state[6];
        uint32_t h = state[7];

        // Main loop
        for (i = 0; i < 64; ++i) {
            uint32_t t1 = h + ep1(e) + ch(e, f, g) + K[i] + m[i];
            uint32_t t2 = ep0(a) + maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }

    void update(const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            this->data[this->datalen] = data[i];
            this->datalen++;
            if (this->datalen == 64) {
                transform(this->data);
                this->bitlen += 512;
                this->datalen = 0;
            }
        }
    }

    Hash256 finalize() {
        uint32_t i = datalen;

        // Pad with 0x80
        if (datalen < 56) {
            data[i++] = 0x80;
            while (i < 56) {
                data[i++] = 0x00;
            }
        } else {
            data[i++] = 0x80;
            while (i < 64) {
                data[i++] = 0x00;
            }
            transform(data);
            memset(data, 0, 56);
        }

        // Append bit length (big-endian 64-bit)
        bitlen += datalen * 8;
        data[63] = static_cast<uint8_t>(bitlen);
        data[62] = static_cast<uint8_t>(bitlen >> 8);
        data[61] = static_cast<uint8_t>(bitlen >> 16);
        data[60] = static_cast<uint8_t>(bitlen >> 24);
        data[59] = static_cast<uint8_t>(bitlen >> 32);
        data[58] = static_cast<uint8_t>(bitlen >> 40);
        data[57] = static_cast<uint8_t>(bitlen >> 48);
        data[56] = static_cast<uint8_t>(bitlen >> 56);
        transform(data);

        // Convert to bytes (big-endian)
        Hash256 result;
        for (i = 0; i < 4; ++i) {
            result.bytes[i] = static_cast<uint8_t>((state[0] >> (24 - i * 8)) & 0xFF);
            result.bytes[i + 4] = static_cast<uint8_t>((state[1] >> (24 - i * 8)) & 0xFF);
            result.bytes[i + 8] = static_cast<uint8_t>((state[2] >> (24 - i * 8)) & 0xFF);
            result.bytes[i + 12] = static_cast<uint8_t>((state[3] >> (24 - i * 8)) & 0xFF);
            result.bytes[i + 16] = static_cast<uint8_t>((state[4] >> (24 - i * 8)) & 0xFF);
            result.bytes[i + 20] = static_cast<uint8_t>((state[5] >> (24 - i * 8)) & 0xFF);
            result.bytes[i + 24] = static_cast<uint8_t>((state[6] >> (24 - i * 8)) & 0xFF);
            result.bytes[i + 28] = static_cast<uint8_t>((state[7] >> (24 - i * 8)) & 0xFF);
        }

        return result;
    }
};

HashProvider::HashProvider() : impl_(std::make_unique<Impl>()) {}
HashProvider::~HashProvider() = default;

void HashProvider::reset() {
    impl_->reset();
}

void HashProvider::update(const uint8_t* data, size_t len) {
    impl_->update(data, len);
}

Hash256 HashProvider::finalize() {
    return impl_->finalize();
}

Hash256 HashProvider::hash_bytes(const uint8_t* data, size_t len) {
    HashProvider provider;
    provider.update(data, len);
    return provider.finalize();
}

Hash256 HashProvider::hash_bytes(std::span<const uint8_t> data) {
    return hash_bytes(data.data(), data.size());
}

Hash256 HashProvider::hash_string(std::string_view str) {
    return hash_bytes(
        reinterpret_cast<const uint8_t*>(str.data()), 
        str.size()
    );
}

std::optional<Hash256> HashProvider::hash_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return std::nullopt;
    }

    HashProvider provider;
    std::vector<uint8_t> buffer(8192);

    while (file.good()) {
        file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        provider.update(buffer.data(), file.gcount());
    }

    return provider.finalize();
}

Hash256 HashProvider::combine_identity(const ExecutionIdentity& identity) {
    auto combined = identity.to_canonical_bytes();
    return hash_bytes(combined.data(), combined.size());
}

bool HashProvider::verify(const Hash256& computed, const Hash256& expected) {
    // Constant-time comparison
    volatile uint8_t result = 0;
    for (size_t i = 0; i < Hash256::SIZE; ++i) {
        result |= computed.bytes[i] ^ expected.bytes[i];
    }
    return result == 0;
}

// ============================================================================
// Convenience namespace
// ============================================================================

namespace hash {

Hash256 of_bytes(const uint8_t* data, size_t len) {
    return HashProvider().hash_bytes(data, len);
}

Hash256 of_bytes(std::span<const uint8_t> data) {
    return of_bytes(data.data(), data.size());
}

Hash256 of_string(std::string_view str) {
    return HashProvider().hash_string(str);
}

std::optional<Hash256> of_file(const std::string& path) {
    return HashProvider().hash_file(path);
}

Hash256 combine(std::span<const Hash256> hashes) {
    HashProvider provider;
    for (const auto& h : hashes) {
        provider.update(h.bytes.data(), h.bytes.size());
    }
    return provider.finalize();
}

Hash256 identity(const ExecutionIdentity& ident) {
    return HashProvider::combine_identity(ident);
}

} // namespace hash

} // namespace val063
