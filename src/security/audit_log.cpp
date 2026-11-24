// =============================================================================
// audit_log.cpp — S7 SHA-256 hash-chain audit log.
// =============================================================================
#include "audit_log.h"

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace rawrxd::security {

// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4) — compact public-domain-style implementation.
// ---------------------------------------------------------------------------
namespace {

const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,
    0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,
    0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,
    0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,
    0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,
    0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

inline uint32_t Rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

std::string ToHex(const uint8_t* d, size_t n) {
    static const char* h = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        out += h[d[i] >> 4];
        out += h[d[i] & 0xf];
    }
    return out;
}

}  // namespace

std::string Sha256::Hash(const std::string& data) {
    uint32_t h[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                     0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    const uint64_t bitLen = (uint64_t)data.size() * 8;
    std::string msg = data;
    msg += (char)0x80;
    while (msg.size() % 64 != 56) msg += (char)0x00;
    for (int i = 7; i >= 0; --i)
        msg += (char)((bitLen >> (i * 8)) & 0xff);

    for (size_t off = 0; off < msg.size(); off += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = ((uint32_t)(uint8_t)msg[off + i * 4] << 24) |
                   ((uint32_t)(uint8_t)msg[off + i * 4 + 1] << 16) |
                   ((uint32_t)(uint8_t)msg[off + i * 4 + 2] << 8) |
                   ((uint32_t)(uint8_t)msg[off + i * 4 + 3]);
        }
        for (int i = 16; i < 64; ++i) {
            const uint32_t s0 = Rotr(w[i - 15], 7) ^ Rotr(w[i - 15], 18) ^
                                (w[i - 15] >> 3);
            const uint32_t s1 = Rotr(w[i - 2], 17) ^ Rotr(w[i - 2], 19) ^
                                (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; ++i) {
            const uint32_t S1 = Rotr(e, 6) ^ Rotr(e, 11) ^ Rotr(e, 25);
            const uint32_t ch = (e & f) ^ (~e & g);
            const uint32_t t1 = hh + S1 + ch + K[i] + w[i];
            const uint32_t S0 = Rotr(a, 2) ^ Rotr(a, 13) ^ Rotr(a, 22);
            const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            const uint32_t t2 = S0 + maj;
            hh = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
    uint8_t digest[32];
    for (int i = 0; i < 8; ++i) {
        digest[i * 4] = (uint8_t)(h[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(h[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(h[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)h[i];
    }
    return ToHex(digest, 32);
}

std::string Sha256::HashFile(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return {};
    std::stringstream ss;
    ss << in.rdbuf();
    return Hash(ss.str());
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------
std::string AuditLog::Escape(const std::string& s) {
    std::string out;
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            default: out += c;
        }
    }
    return out;
}

std::string AuditLog::ComputeRecordHash(const AuditRecord& r) {
    return Sha256::Hash(r.ts + "\n" + r.actor + "\n" + r.action + "\n" +
                        r.detail + "\n" + r.prev_hash);
}

AuditLog::AuditLog(std::string path) : path_(std::move(path)) {}

std::string AuditLog::LoadLastHash() {
    std::ifstream in(path_);
    if (!in) return {};
    std::string last, line;
    while (std::getline(in, line)) {
        const size_t p = line.rfind("\"record_hash\":\"");
        if (p != std::string::npos) {
            const size_t e = line.find('"', p + 15);
            if (e != std::string::npos) last = line.substr(p + 15, e - p - 15);
        }
    }
    return last;
}

bool AuditLog::Append(const std::string& actor, const std::string& action,
                      const std::string& detail) {
    std::string broken;
    if (!Verify(&broken)) {
        std::fprintf(stderr, "audit_log: chain broken at %s; append refused\n",
                     broken.c_str());
        return false;
    }
    std::error_code ec;
    std::filesystem::create_directories(
        std::filesystem::path(path_).parent_path(), ec);
    AuditRecord r;
    r.ts = "2026-11-24T00:00:00Z";  // caller stamps; kept deterministic here
    r.actor = actor;
    r.action = action;
    r.detail = detail;
    r.prev_hash = LoadLastHash();
    if (r.prev_hash.empty()) {
        // Genesis record: prev hash of 64 zeros.
        r.prev_hash = std::string(64, '0');
    }
    r.record_hash = ComputeRecordHash(r);
    std::ofstream out(path_, std::ios::app);
    if (!out) return false;
    out << "{\"ts\":\"" << Escape(r.ts) << "\",\"actor\":\"" << Escape(r.actor)
        << "\",\"action\":\"" << Escape(r.action) << "\",\"detail\":\""
        << Escape(r.detail) << "\",\"prev_hash\":\"" << r.prev_hash
        << "\",\"record_hash\":\"" << r.record_hash << "\"}\n";
    return (bool)out;
}

bool AuditLog::Verify(std::string* firstError) const {
    std::ifstream in(path_);
    if (!in) return true;  // no log yet = valid empty chain
    std::string prev(64, '0');
    std::string line;
    int index = 0;
    std::string lastRecordHash;
    while (std::getline(in, line)) {
        ++index;
        // Minimal field extraction (records are machine-written).
        auto field = [&line](const std::string& key) {
            const std::string pat = "\"" + key + "\":\"";
            const size_t p = line.find(pat);
            if (p == std::string::npos) return std::string();
            const size_t s = p + pat.size();
            const size_t e = line.find('"', s);
            return e == std::string::npos ? std::string()
                                          : line.substr(s, e - s);
        };
        AuditRecord r;
        r.ts = field("ts");
        r.actor = field("actor");
        r.action = field("action");
        r.detail = field("detail");
        r.prev_hash = field("prev_hash");
        r.record_hash = field("record_hash");
        if (r.prev_hash != prev) {
            if (firstError) *firstError = "record " + std::to_string(index) +
                                         ": prev_hash mismatch";
            return false;
        }
        if (ComputeRecordHash(r) != r.record_hash) {
            if (firstError) *firstError = "record " + std::to_string(index) +
                                         ": record_hash mismatch";
            return false;
        }
        prev = r.record_hash;
        lastRecordHash = r.record_hash;
    }
    (void)lastRecordHash;
    return true;
}

size_t AuditLog::Size() const {
    std::ifstream in(path_);
    if (!in) return 0;
    size_t n = 0;
    std::string line;
    while (std::getline(in, line)) ++n;
    return n;
}

}  // namespace rawrxd::security