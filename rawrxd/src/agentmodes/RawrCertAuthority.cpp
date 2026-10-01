// RawrCertAuthority.cpp — RAWRXD_RAWRCERT_AUTHORITY_001
#include "agentmodes/RawrCertAuthority.h"
#include "agentmodes/RawrReceiptValidator.h"
#include "deep2/ReceiptAuthority.h"

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>

namespace rawrxd { namespace cert {

// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4), self-contained so certification has no external deps.
// ---------------------------------------------------------------------------
namespace {

struct Sha256 {
    uint32_t h[8] = { 0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
                      0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u };
    uint64_t total = 0;
    uint8_t  buf[64] = {};
    size_t   bufLen = 0;

    static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

    void block(const uint8_t* p) {
        static const uint32_t k[64] = {
            0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
            0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
            0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
            0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
            0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
            0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
            0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
            0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u };
        uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (uint32_t(p[i*4]) << 24) | (uint32_t(p[i*4+1]) << 16) |
                   (uint32_t(p[i*4+2]) << 8) | uint32_t(p[i*4+3]);
        }
        for (int i = 16; i < 64; ++i) {
            const uint32_t s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >> 3);
            const uint32_t s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19)  ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i = 0; i < 64; ++i) {
            const uint32_t S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
            const uint32_t ch = (e & f) ^ (~e & g);
            const uint32_t t1 = hh + S1 + ch + k[i] + w[i];
            const uint32_t S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
            const uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
            const uint32_t t2 = S0 + mj;
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }

    void update(const uint8_t* p, size_t n) {
        total += n;
        while (n) {
            const size_t take = (64 - bufLen < n) ? (64 - bufLen) : n;
            std::memcpy(buf + bufLen, p, take);
            bufLen += take; p += take; n -= take;
            if (bufLen == 64) { block(buf); bufLen = 0; }
        }
    }

    std::string hex() {
        // Capture the message length before padding mutates `total`.
        const uint64_t bits = total * 8;
        uint8_t pad = 0x80;
        update(&pad, 1);
        pad = 0x00;
        while (bufLen != 56) update(&pad, 1);
        uint8_t len[8];
        for (int i = 0; i < 8; ++i) len[i] = uint8_t(bits >> (56 - 8*i));
        update(len, 8);
        char out[65];
        for (int i = 0; i < 8; ++i) std::snprintf(out + i*8, 9, "%08x", h[i]);
        return std::string(out, 64);
    }
};

} // namespace

std::string sha256Bytes(const void* data, size_t len) {
    Sha256 s;
    if (data && len) s.update(static_cast<const uint8_t*>(data), len);
    return s.hex();
}

std::string sha256File(const std::string& path) {
    std::FILE* f = nullptr;
    if (fopen_s(&f, path.c_str(), "rb") != 0 || !f) return std::string();
    Sha256 s;
    std::vector<uint8_t> buf(1 << 16);
    size_t n;
    while ((n = std::fread(buf.data(), 1, buf.size(), f)) > 0) s.update(buf.data(), n);
    std::fclose(f);
    return s.hex();
}

bool sha256SelfTest(std::string* detail) {
    Sha256 s;
    const char* msg = "abc";
    s.update(reinterpret_cast<const uint8_t*>(msg), 3);
    const std::string got = s.hex();
    const char* want = "ba7816bf8f01cfea414140de5dae2223"
                       "b00361a396177a9cb410ff61f20015ad";
    if (detail) *detail = got;
    return got == want;
}

CertResult certify(const std::string& exePath, const std::vector<GateInput>& gates) {
    CertResult r;
    r.exePath = exePath;
    r.exeSha256 = sha256File(exePath);
    r.gatesRequired = (int)gates.size();

    for (const auto& g : gates) {
        const receiptcheck::Receipt rec = receiptcheck::load(g.receiptPath);
        if (!rec.exists) {
            ++r.gatesFail;
            r.failedGates.push_back(g.gateName + " (receipt missing)");
            continue;
        }
        const auto v = rec.fields.find("VERDICT");
        const std::string verdict = (v != rec.fields.end()) ? v->second : std::string("(none)");
        if (verdict == "PASS") {
            ++r.gatesPass;
        } else {
            if (verdict == "RETRACTED_FALSE_PASS" || verdict == "STUB_PASS_CONTAMINATION") {
                ++r.falsePassRetracted;
            }
            ++r.gatesFail;
            r.failedGates.push_back(g.gateName + " (" + verdict + ")");
        }
    }

    if (r.exeSha256.empty()) {
        r.verdict = "FAIL";
        r.rationale = "cannot hash the certifying executable at " + exePath;
    } else if (r.gatesRequired == 0) {
        r.verdict = "FAIL";
        r.rationale = "no gates were supplied; an empty chain cannot certify";
    } else if (r.gatesFail > 0) {
        r.verdict = "FAIL";
        r.rationale = std::to_string(r.gatesFail) + " of " +
                      std::to_string(r.gatesRequired) + " gates did not pass";
    } else {
        r.verdict = "PASS";
        r.rationale = "all " + std::to_string(r.gatesRequired) +
                      " gates passed against executable sha256 " + r.exeSha256;
    }
    return r;
}

void writeCertReceipt(const std::string& path, const CertResult& r) {
    receipt::beginGate(path, "RAWRXD_RAWRCERT_AUTHORITY_001");
    receipt::writeKeyValue(path, "STRICT_EXE", r.exePath);
    receipt::writeKeyValue(path, "STRICT_EXE_SHA256", r.exeSha256.empty() ? "(unreadable)" : r.exeSha256);
    receipt::writeKeyValueInt(path, "GATES_REQUIRED", r.gatesRequired);
    receipt::writeKeyValueInt(path, "GATES_PASS", r.gatesPass);
    receipt::writeKeyValueInt(path, "GATES_FAIL", r.gatesFail);
    receipt::writeKeyValueInt(path, "FALSE_PASS_RETRACTED", r.falsePassRetracted);
    for (size_t i = 0; i < r.failedGates.size(); ++i) {
        receipt::writeKeyValue(path, "FAILED_GATE_" + std::to_string(i + 1), r.failedGates[i]);
    }
    receipt::writeKeyValue(path, "RATIONALE", r.rationale);
    receipt::endGate(path, r.verdict.c_str());
}

}} // namespace rawrxd::cert
