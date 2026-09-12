#include "d2_authority_mint15.h"
#include <cstring>
#include <algorithm>

namespace d2auth {

// Minimal SHA-256, dependency-free.
namespace {
struct Sha256 {
    std::uint32_t h[8];
    std::uint8_t buf[64];
    std::uint64_t bits;
    std::size_t used;
};

static constexpr std::uint32_t K[64] = {
  0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
  0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
  0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
  0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
  0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
  0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
  0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
  0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};
static inline std::uint32_t rotr(std::uint32_t x, unsigned n){ return (x>>n)|(x<<(32-n)); }
static void init(Sha256& s){
    s.h[0]=0x6a09e667u;s.h[1]=0xbb67ae85u;s.h[2]=0x3c6ef372u;s.h[3]=0xa54ff53au;
    s.h[4]=0x510e527fu;s.h[5]=0x9b05688cu;s.h[6]=0x1f83d9abu;s.h[7]=0x5be0cd19u;
    s.bits=0;s.used=0;
}
static void block(Sha256& s,const std::uint8_t* p){
    std::uint32_t w[64];
    for(int i=0;i<16;++i) w[i]=(std::uint32_t(p[4*i])<<24)|(std::uint32_t(p[4*i+1])<<16)|
                              (std::uint32_t(p[4*i+2])<<8)|std::uint32_t(p[4*i+3]);
    for(int i=16;i<64;++i){
        std::uint32_t a=w[i-15],b=w[i-2];
        std::uint32_t s0=rotr(a,7)^rotr(a,18)^(a>>3);
        std::uint32_t s1=rotr(b,17)^rotr(b,19)^(b>>10);
        w[i]=w[i-16]+s0+w[i-7]+s1;
    }
    std::uint32_t a=s.h[0],b=s.h[1],c=s.h[2],d=s.h[3],e=s.h[4],f=s.h[5],g=s.h[6],h=s.h[7];
    for(int i=0;i<64;++i){
        std::uint32_t S1=rotr(e,6)^rotr(e,11)^rotr(e,25);
        std::uint32_t ch=(e&f)^((~e)&g);
        std::uint32_t t1=h+S1+ch+K[i]+w[i];
        std::uint32_t S0=rotr(a,2)^rotr(a,13)^rotr(a,22);
        std::uint32_t maj=(a&b)^(a&c)^(b&c);
        std::uint32_t t2=S0+maj;
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    s.h[0]+=a;s.h[1]+=b;s.h[2]+=c;s.h[3]+=d;s.h[4]+=e;s.h[5]+=f;s.h[6]+=g;s.h[7]+=h;
}
static void update(Sha256& s,const void* data,std::size_t n){
    auto* p=static_cast<const std::uint8_t*>(data);
    s.bits += std::uint64_t(n)*8ull;
    while(n){
        std::size_t take=64-s.used; if(take>n) take=n;
        std::memcpy(s.buf+s.used,p,take);s.used+=take;p+=take;n-=take;
        if(s.used==64){block(s,s.buf);s.used=0;}
    }
}
static void finish(Sha256& s,std::uint8_t out[32]){
    std::uint64_t bits=s.bits;
    s.buf[s.used++]=0x80;
    if(s.used>56){while(s.used<64)s.buf[s.used++]=0;block(s,s.buf);s.used=0;}
    while(s.used<56)s.buf[s.used++]=0;
    for(int i=7;i>=0;--i)s.buf[s.used++]=std::uint8_t(bits>>(i*8));
    block(s,s.buf);
    for(int i=0;i<8;++i){
        out[4*i]=std::uint8_t(s.h[i]>>24);out[4*i+1]=std::uint8_t(s.h[i]>>16);
        out[4*i+2]=std::uint8_t(s.h[i]>>8);out[4*i+3]=std::uint8_t(s.h[i]);
    }
}
}

AuthorityMint15::AuthorityMint15() noexcept {
    std::memset(&grant_,0,sizeof(grant_));
    std::memset(&state_,0,sizeof(state_));
    std::memset(&receipt_,0,sizeof(receipt_));
    std::memset(timings_,0,sizeof(timings_));
}

bool AuthorityMint15::copy_ascii(char* dst,std::size_t cap,const char* src) noexcept {
    if(!dst||!cap||!src) return false;
    std::size_t n=0; while(src[n] && n+1<cap){ dst[n]=src[n]; ++n; }
    if(src[n]!=0) return false;
    dst[n]=0; return true;
}
bool AuthorityMint15::valid_sha256_hex(const char* s) noexcept {
    if(!s) return false;
    for(int i=0;i<64;++i){
        char c=s[i];
        bool ok=(c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F');
        if(!ok) return false;
    }
    return s[64]==0;
}
bool AuthorityMint15::has_scope(std::uint32_t bit) const noexcept {
    return state_.grant_bound && (grant_.scope & bit)!=0;
}
void AuthorityMint15::mark(Op op) noexcept {
    auto v=static_cast<unsigned>(op);
    if(v>=1 && v<=15) state_.op_mask_low |= std::uint16_t(1u<<(v-1));
}
bool AuthorityMint15::prior(Op op) const noexcept {
    auto v=static_cast<unsigned>(op);
    return v>=1 && v<=15 && (state_.op_mask_low & std::uint16_t(1u<<(v-1)))!=0;
}

// 1
bool AuthorityMint15::grant_authority(const AuthorityGrant& g) noexcept {
    if(state_.grant_bound || g.magic!=kGrantMagic || g.nonce==0 || g.scope==0) return false;
    grant_=g; state_.grant_bound=true; state_.grant_nonce=g.nonce; mark(Op::GRANT_AUTHORITY); return true;
}
// 2
bool AuthorityMint15::bind_gate(const char* gate_id,std::uint32_t target_tokens) noexcept {
    if(!prior(Op::GRANT_AUTHORITY)||state_.gate_bound||target_tokens==0||target_tokens>D2_AUTH_MAX_TOKENS) return false;
    if(!copy_ascii(receipt_.gate_id,sizeof(receipt_.gate_id),gate_id)) return false;
    receipt_.target_tokens=target_tokens;state_.gate_bound=true;mark(Op::BIND_GATE);return true;
}
// 3
bool AuthorityMint15::bind_cert_sha256(const char* sha) noexcept {
    if(!prior(Op::BIND_GATE)||state_.cert_bound||!valid_sha256_hex(sha)) return false;
    if(!copy_ascii(receipt_.cert_sha256_hex,sizeof(receipt_.cert_sha256_hex),sha)) return false;
    state_.cert_bound=true;mark(Op::BIND_CERT);return true;
}
// 4
bool AuthorityMint15::begin_observation(std::uint64_t fq,const PredicateSet& p) noexcept {
    if(!has_scope(SCOPE_OBSERVE)||!prior(Op::BIND_CERT)||state_.observation_open||fq==0) return false;
    receipt_.qpc_frequency=fq;receipt_.predicates=p;timing_count_=0;
    state_.observation_open=true;mark(Op::BEGIN_OBSERVATION);return true;
}
// 5
bool AuthorityMint15::observe_token(std::uint64_t b,std::uint64_t e) noexcept {
    if(!state_.observation_open||timing_count_>=receipt_.target_tokens||e<=b) return false;
    timings_[timing_count_++]={b,e};receipt_.observed_tokens=timing_count_;mark(Op::OBSERVE_TOKEN);return true;
}
// 6
bool AuthorityMint15::close_observation() noexcept {
    if(!prior(Op::OBSERVE_TOKEN)||!state_.observation_open) return false;
    state_.observation_open=false;state_.observation_closed=true;mark(Op::CLOSE_OBSERVATION);return true;
}
// 7
bool AuthorityMint15::validate_cardinality() noexcept {
    if(!prior(Op::CLOSE_OBSERVATION)) return false;
    state_.cardinality_valid=(timing_count_==receipt_.target_tokens && timing_count_>0);
    if(state_.cardinality_valid) mark(Op::VALIDATE_CARDINALITY);
    return state_.cardinality_valid;
}
// 8
bool AuthorityMint15::validate_integrity() noexcept {
    if(!prior(Op::VALIDATE_CARDINALITY)) return false;
    bool ok=state_.grant_nonce!=0 && receipt_.gate_id[0] && valid_sha256_hex(receipt_.cert_sha256_hex);
    state_.integrity_valid=ok;if(ok)mark(Op::VALIDATE_INTEGRITY);return ok;
}
// 9
bool AuthorityMint15::validate_qpc() noexcept {
    if(!prior(Op::VALIDATE_INTEGRITY)) return false;
    bool ok=receipt_.qpc_frequency>0;
    for(std::uint32_t i=0;i<timing_count_&&ok;++i){
        ok=timings_[i].qpc_end>timings_[i].qpc_begin;
        if(i>0) ok=ok && timings_[i].qpc_begin>=timings_[i-1].qpc_end;
    }
    state_.qpc_valid=ok;if(ok)mark(Op::VALIDATE_QPC);return ok;
}
// 10
bool AuthorityMint15::calculate_metrics() noexcept {
    if(!prior(Op::VALIDATE_QPC)) return false;
    std::uint64_t d[D2_AUTH_MAX_TOKENS]{};
    std::uint64_t sum=0,minv=~0ull,maxv=0;
    for(std::uint32_t i=0;i<timing_count_;++i){
        d[i]=timings_[i].qpc_end-timings_[i].qpc_begin;
        sum+=d[i];if(d[i]<minv)minv=d[i];if(d[i]>maxv)maxv=d[i];
    }
    std::sort(d,d+timing_count_);
    auto pct=[&](unsigned num,unsigned den)->std::uint64_t{
        std::uint64_t idx=(std::uint64_t(timing_count_-1)*num + den-1)/den;
        if(idx>=timing_count_) idx=timing_count_-1;
        return d[idx];
    };
    Metrics& m=receipt_.metrics;
    m.generated_tokens=timing_count_;
    m.wall_qpc_ticks=timings_[timing_count_-1].qpc_end-timings_[0].qpc_begin;
    m.min_qpc_ticks=minv;m.max_qpc_ticks=maxv;m.mean_qpc_ticks=sum/timing_count_;
    m.p50_qpc_ticks=pct(50,100);m.p95_qpc_ticks=pct(95,100);
    m.sustained_tps=m.wall_qpc_ticks?double(timing_count_)*double(receipt_.qpc_frequency)/double(m.wall_qpc_ticks):0.0;
    state_.metrics_ready=m.sustained_tps>0.0;if(state_.metrics_ready)mark(Op::CALCULATE_METRICS);
    return state_.metrics_ready;
}
// 11
bool AuthorityMint15::validate_predicates() noexcept {
    if(!prior(Op::CALCULATE_METRICS)) return false;
    const PredicateSet& p=receipt_.predicates;
    bool ok=p.full_model_forward && p.real_autoregressive_decode && p.warmup_excluded &&
            p.sealed_logits_reuse_zero && p.synthetic_logits_zero &&
            p.device_lost_zero && p.cert_binary_unchanged;
    state_.predicates_valid=ok;if(ok)mark(Op::VALIDATE_PREDICATES);return ok;
}

void AuthorityMint15::hash_receipt(std::uint8_t out[32]) const noexcept {
    Sha256 s;init(s);
    update(s,receipt_.gate_id,sizeof(receipt_.gate_id));
    update(s,receipt_.cert_sha256_hex,sizeof(receipt_.cert_sha256_hex));
    update(s,&receipt_.qpc_frequency,sizeof(receipt_.qpc_frequency));
    update(s,&receipt_.target_tokens,sizeof(receipt_.target_tokens));
    update(s,&receipt_.observed_tokens,sizeof(receipt_.observed_tokens));
    update(s,&receipt_.predicates,sizeof(receipt_.predicates));
    update(s,&receipt_.metrics,sizeof(receipt_.metrics));
    update(s,&grant_.nonce,sizeof(grant_.nonce));
    finish(s,out);
}
// 12
bool AuthorityMint15::seal_receipt() noexcept {
    if(!has_scope(SCOPE_SEAL)||!prior(Op::VALIDATE_PREDICATES)||state_.receipt_sealed) return false;
    hash_receipt(receipt_.receipt_sha256);
    state_.receipt_sealed=true;mark(Op::SEAL_RECEIPT);return true;
}
// 13
bool AuthorityMint15::mint_tps_authority() noexcept {
    if(!has_scope(SCOPE_MINT_TPS)||!prior(Op::SEAL_RECEIPT)||!state_.receipt_sealed) return false;
    if(!state_.cardinality_valid||!state_.integrity_valid||!state_.qpc_valid||
       !state_.metrics_ready||!state_.predicates_valid) return false;
    state_.full_model_tps_authority=true;mark(Op::MINT_TPS_AUTHORITY);return true;
}
// 14
bool AuthorityMint15::authorize_promote() noexcept {
    if(!has_scope(SCOPE_AUTHORIZE_PROMOTE)||!prior(Op::MINT_TPS_AUTHORITY)||
       !state_.full_model_tps_authority) return false;
    state_.promote_authorized=true;mark(Op::AUTHORIZE_PROMOTE);return true;
}
// 15
bool AuthorityMint15::commit_promote() noexcept {
    if(!has_scope(SCOPE_COMMIT_PROMOTE)||!prior(Op::AUTHORIZE_PROMOTE)||
       !state_.promote_authorized||!state_.full_model_tps_authority) return false;
    state_.promote=true;mark(Op::COMMIT_PROMOTE);return true;
}

} // namespace d2auth
