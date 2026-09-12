#include "d2_authority_mint15.h"
#include <cstdio>
#include <cstring>

using namespace d2auth;

static void hex32(const std::uint8_t* p,char out[65]){
    static const char* h="0123456789abcdef";
    for(int i=0;i<32;++i){out[2*i]=h[p[i]>>4];out[2*i+1]=h[p[i]&15];}
    out[64]=0;
}

int main(){
    AuthorityMint15 a;
    AuthorityGrant g{};
    g.magic=AuthorityMint15::kGrantMagic;
    g.nonce=0x1122334455667788ull;
    g.scope=SCOPE_OBSERVE|SCOPE_SEAL|SCOPE_MINT_TPS|
            SCOPE_AUTHORIZE_PROMOTE|SCOPE_COMMIT_PROMOTE;
    std::snprintf(g.authority_name,sizeof(g.authority_name),"Deep2ProductAuthority");

    if(!a.grant_authority(g)) return 1;
    if(!a.bind_gate("DEEP2_FULL_MODEL_TPS_AUTHORITY_001",64)) return 2;
    if(!a.bind_cert_sha256("576818d100000000000000000000000000000000000000000000000000946680")) return 3;

    PredicateSet p{};
    p.full_model_forward=true;
    p.real_autoregressive_decode=true;
    p.warmup_excluded=true;
    p.sealed_logits_reuse_zero=true;
    p.synthetic_logits_zero=true;
    p.device_lost_zero=true;
    p.cert_binary_unchanged=true;

    const std::uint64_t fq=10000000ull;
    if(!a.begin_observation(fq,p)) return 4;

    std::uint64_t q=1000000;
    for(unsigned i=0;i<64;++i){
        std::uint64_t dt=500000ull + (i%5)*1000ull; // ~50ms
        if(!a.observe_token(q,q+dt)) return 5;
        q += dt;
    }
    if(!a.close_observation()) return 6;
    if(!a.validate_cardinality()) return 7;
    if(!a.validate_integrity()) return 8;
    if(!a.validate_qpc()) return 9;
    if(!a.calculate_metrics()) return 10;
    if(!a.validate_predicates()) return 11;
    if(!a.seal_receipt()) return 12;
    if(!a.mint_tps_authority()) return 13;

    // Promotion remains a separately authorized operation.
    if(!a.authorize_promote()) return 14;
    if(!a.commit_promote()) return 15;

    char digest[65];hex32(a.receipt().receipt_sha256,digest);
    const State& s=a.state();
    std::printf("MINT15_SELFTEST=PASS\n");
    std::printf("OPS_MASK=0x%04x\n",s.op_mask_low);
    std::printf("OBSERVED=%u/%u\n",a.receipt().observed_tokens,a.receipt().target_tokens);
    std::printf("SUSTAINED_TPS=%.6f\n",a.receipt().metrics.sustained_tps);
    std::printf("RECEIPT_SHA256=%s\n",digest);
    std::printf("FULL_MODEL_TPS_AUTHORITY=%d\n",s.full_model_tps_authority?1:0);
    std::printf("PROMOTE_AUTHORIZED=%d\n",s.promote_authorized?1:0);
    std::printf("PROMOTE=%d\n",s.promote?1:0);
    return (s.op_mask_low==0x7fff && s.full_model_tps_authority && s.promote)?0:16;
}
