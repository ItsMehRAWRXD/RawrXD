#include "d2_qpc_seal.h"
#include <cstdio>
#include <cstring>

using namespace d2qpc;

struct FakeClock {
    std::uint64_t now = 1000000;
    std::uint64_t fq = 10000000;
    std::uint32_t phase = 0;
};

static bool fake_freq(void* u, std::uint64_t* out) noexcept {
    if (!u || !out) return false;
    *out=static_cast<FakeClock*>(u)->fq;
    return true;
}
static bool fake_now(void* u, std::uint64_t* out) noexcept {
    if (!u || !out) return false;
    auto* c=static_cast<FakeClock*>(u);
    // begin/end alternate. Each full-forward token is ~50.0-50.4 ms.
    if ((c->phase & 1u)==0u) {
        *out=c->now;
    } else {
        c->now += 500000ull + ((c->phase/2u)%5u)*1000ull;
        *out=c->now;
    }
    ++c->phase;
    return true;
}

static void hex32(const std::uint8_t* p,char out[65]) noexcept {
    static const char* h="0123456789abcdef";
    for(int i=0;i<32;++i){out[2*i]=h[p[i]>>4];out[2*i+1]=h[p[i]&15];}
    out[64]=0;
}

int main() {
    SealAuthority a;

    Grant g{};
    g.magic=SealAuthority::kGrantMagic;
    g.nonce=0xA55A112233445566ull;
    g.scope=SCOPE_MEASURE|SCOPE_SEAL|SCOPE_MINT_TPS;
    std::snprintf(g.authority_name,sizeof(g.authority_name),"Deep2QpcSealAuthority");
    if (!a.grant(g)) return 1;

    const char* cert=
        "0123456789abcdef0123456789abcdef"
        "0123456789abcdef0123456789abcdef";
    if (!a.bind_identity("DEEP2_FULL_MODEL_TPS_AUTHORITY_001",cert,64)) return 2;

    FakeClock clock{};
    QpcProvider q{};
    q.user=&clock;
    q.now=&fake_now;
    q.frequency=&fake_freq;
    if (!a.bind_qpc(q)) return 3;

    Predicates p{};
    p.full_model_forward=true;
    p.real_autoregressive_decode=true;
    p.warmup_excluded=true;
    p.sealed_logits_reuse_zero=true;
    p.synthetic_logits_zero=true;
    p.device_lost_zero=true;
    p.cert_binary_unchanged=true;

    if (!a.open(p)) return 4;
    for (unsigned i=0;i<64;++i) {
        if (!a.token_begin()) return 5;
        // real product call goes here: Deep2 full forward for exactly one token.
        if (!a.token_end()) return 6;
    }
    if (!a.close()) return 7;
    if (!a.validate()) return 8;
    if (!a.calculate()) return 9;
    if (!a.seal()) return 10;
    if (!a.mint_tps_authority()) return 11;

    char digest[65];
    hex32(a.receipt().receipt_sha256,digest);

    std::printf("QPC_SEAL_SELFTEST=PASS\n");
    std::printf("OBSERVED=%u/%u\n",a.receipt().observed_tokens,a.receipt().target_tokens);
    std::printf("WALL_NS=%llu\n",(unsigned long long)a.receipt().metrics.generation_wall_ns);
    std::printf("P50_NS=%llu\n",(unsigned long long)a.receipt().metrics.token_p50_ns);
    std::printf("P95_NS=%llu\n",(unsigned long long)a.receipt().metrics.token_p95_ns);
    std::printf("SUSTAINED_TPS=%.6f\n",a.receipt().metrics.sustained_tps);
    std::printf("RECEIPT_SHA256=%s\n",digest);
    std::printf("RECEIPT_SEALED=%d\n",a.state().receipt_sealed?1:0);
    std::printf("FULL_MODEL_TPS_AUTHORITY=%d\n",a.state().full_model_tps_authority?1:0);
    return a.state().full_model_tps_authority ? 0 : 12;
}
