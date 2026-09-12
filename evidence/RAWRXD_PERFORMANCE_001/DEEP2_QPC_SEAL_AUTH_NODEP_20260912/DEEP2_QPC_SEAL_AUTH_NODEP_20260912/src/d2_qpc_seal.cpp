#include "d2_qpc_seal.h"
#include <cstring>
#include <algorithm>

namespace d2qpc {

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

static inline std::uint32_t rotr(std::uint32_t x, unsigned n) noexcept {
    return (x >> n) | (x << (32u - n));
}
static void sha_init(Sha256& s) noexcept {
    s.h[0]=0x6a09e667u; s.h[1]=0xbb67ae85u; s.h[2]=0x3c6ef372u; s.h[3]=0xa54ff53au;
    s.h[4]=0x510e527fu; s.h[5]=0x9b05688cu; s.h[6]=0x1f83d9abu; s.h[7]=0x5be0cd19u;
    s.bits=0; s.used=0;
}
static void sha_block(Sha256& s, const std::uint8_t* p) noexcept {
    std::uint32_t w[64];
    for (int i=0;i<16;++i) {
        w[i]=(std::uint32_t(p[4*i])<<24)|(std::uint32_t(p[4*i+1])<<16)|
             (std::uint32_t(p[4*i+2])<<8)|std::uint32_t(p[4*i+3]);
    }
    for (int i=16;i<64;++i) {
        std::uint32_t a=w[i-15], b=w[i-2];
        std::uint32_t s0=rotr(a,7)^rotr(a,18)^(a>>3);
        std::uint32_t s1=rotr(b,17)^rotr(b,19)^(b>>10);
        w[i]=w[i-16]+s0+w[i-7]+s1;
    }
    std::uint32_t a=s.h[0],b=s.h[1],c=s.h[2],d=s.h[3];
    std::uint32_t e=s.h[4],f=s.h[5],g=s.h[6],h=s.h[7];
    for (int i=0;i<64;++i) {
        std::uint32_t S1=rotr(e,6)^rotr(e,11)^rotr(e,25);
        std::uint32_t ch=(e&f)^((~e)&g);
        std::uint32_t t1=h+S1+ch+K[i]+w[i];
        std::uint32_t S0=rotr(a,2)^rotr(a,13)^rotr(a,22);
        std::uint32_t maj=(a&b)^(a&c)^(b&c);
        std::uint32_t t2=S0+maj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    s.h[0]+=a; s.h[1]+=b; s.h[2]+=c; s.h[3]+=d;
    s.h[4]+=e; s.h[5]+=f; s.h[6]+=g; s.h[7]+=h;
}
static void sha_update(Sha256& s, const void* data, std::size_t n) noexcept {
    const auto* p=static_cast<const std::uint8_t*>(data);
    s.bits += std::uint64_t(n)*8ull;
    while (n) {
        std::size_t take=64-s.used;
        if (take>n) take=n;
        std::memcpy(s.buf+s.used,p,take);
        s.used+=take; p+=take; n-=take;
        if (s.used==64) { sha_block(s,s.buf); s.used=0; }
    }
}
static void sha_finish(Sha256& s, std::uint8_t out[32]) noexcept {
    const std::uint64_t bits=s.bits;
    s.buf[s.used++]=0x80;
    if (s.used>56) {
        while (s.used<64) s.buf[s.used++]=0;
        sha_block(s,s.buf); s.used=0;
    }
    while (s.used<56) s.buf[s.used++]=0;
    for (int i=7;i>=0;--i) s.buf[s.used++]=std::uint8_t(bits>>(i*8));
    sha_block(s,s.buf);
    for (int i=0;i<8;++i) {
        out[4*i]=std::uint8_t(s.h[i]>>24);
        out[4*i+1]=std::uint8_t(s.h[i]>>16);
        out[4*i+2]=std::uint8_t(s.h[i]>>8);
        out[4*i+3]=std::uint8_t(s.h[i]);
    }
}

static void hash_bool(Sha256& s, bool v) noexcept {
    const std::uint8_t b=v?1u:0u;
    sha_update(s,&b,1);
}
}

SealAuthority::SealAuthority() noexcept {
    std::memset(&grant_,0,sizeof(grant_));
    std::memset(&qpc_,0,sizeof(qpc_));
    std::memset(&state_,0,sizeof(state_));
    std::memset(&receipt_,0,sizeof(receipt_));
    std::memset(samples_,0,sizeof(samples_));
}

bool SealAuthority::copy_ascii(char* dst,std::size_t cap,const char* src) noexcept {
    if (!dst || !src || cap==0) return false;
    std::size_t n=0;
    while (src[n] && n+1<cap) { dst[n]=src[n]; ++n; }
    if (src[n]!=0) return false;
    dst[n]=0;
    return true;
}
bool SealAuthority::valid_sha256_hex(const char* s) noexcept {
    if (!s) return false;
    for (int i=0;i<64;++i) {
        const char c=s[i];
        const bool ok=(c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F');
        if (!ok) return false;
    }
    return s[64]==0;
}
bool SealAuthority::has_scope(std::uint32_t bit) const noexcept {
    return state_.grant_bound && (grant_.scope & bit)!=0;
}
std::uint64_t SealAuthority::qpc_to_ns(std::uint64_t ticks,std::uint64_t fq) noexcept {
    if (!fq) return 0;
    const std::uint64_t whole=ticks/fq;
    const std::uint64_t rem=ticks%fq;
    return whole*1000000000ull + (rem*1000000000ull)/fq;
}

bool SealAuthority::grant(const Grant& g) noexcept {
    if (state_.grant_bound || g.magic!=kGrantMagic || g.nonce==0) return false;
    if ((g.scope & (SCOPE_MEASURE|SCOPE_SEAL|SCOPE_MINT_TPS))==0) return false;
    grant_=g;
    if (!copy_ascii(receipt_.authority_name,sizeof(receipt_.authority_name),g.authority_name))
        return false;
    receipt_.grant_nonce=g.nonce;
    state_.grant_bound=true;
    return true;
}

bool SealAuthority::bind_identity(const char* gate_id,const char* cert,std::uint32_t target) noexcept {
    if (!state_.grant_bound || state_.identity_bound || !gate_id || !valid_sha256_hex(cert))
        return false;
    if (target==0 || target>D2_QPC_MAX_TOKENS) return false;
    if (!copy_ascii(receipt_.gate_id,sizeof(receipt_.gate_id),gate_id)) return false;
    if (!copy_ascii(receipt_.cert_sha256_hex,sizeof(receipt_.cert_sha256_hex),cert)) return false;
    receipt_.target_tokens=target;
    state_.identity_bound=true;
    return true;
}

bool SealAuthority::bind_qpc(const QpcProvider& q) noexcept {
    if (!state_.identity_bound || state_.qpc_bound || !q.now || !q.frequency) return false;
    std::uint64_t fq=0;
    if (!q.frequency(q.user,&fq) || fq==0) return false;
    qpc_=q;
    receipt_.qpc_frequency=fq;
    state_.qpc_bound=true;
    return true;
}

bool SealAuthority::open(const Predicates& p) noexcept {
    if (!has_scope(SCOPE_MEASURE) || !state_.qpc_bound || state_.observation_open ||
        state_.observation_closed) return false;
    receipt_.predicates=p;
    sample_count_=0;
    pending_begin_=0;
    state_.observation_open=true;
    return true;
}

bool SealAuthority::token_begin() noexcept {
    if (!state_.observation_open || state_.token_open ||
        sample_count_>=receipt_.target_tokens) return false;
    std::uint64_t q=0;
    if (!qpc_.now(qpc_.user,&q) || q==0) return false;
    pending_begin_=q;
    state_.token_open=true;
    return true;
}

bool SealAuthority::token_end() noexcept {
    if (!state_.observation_open || !state_.token_open) return false;
    std::uint64_t q=0;
    if (!qpc_.now(qpc_.user,&q) || q<=pending_begin_) return false;
    samples_[sample_count_++]={pending_begin_,q};
    receipt_.observed_tokens=sample_count_;
    pending_begin_=0;
    state_.token_open=false;
    return true;
}

bool SealAuthority::close() noexcept {
    if (!state_.observation_open || state_.token_open) return false;
    state_.observation_open=false;
    state_.observation_closed=true;
    return true;
}

bool SealAuthority::validate() noexcept {
    if (!state_.observation_closed) return false;

    state_.cardinality_valid =
        sample_count_==receipt_.target_tokens && sample_count_>0;

    bool qpc_ok=state_.cardinality_valid && receipt_.qpc_frequency>0;
    for (std::uint32_t i=0;i<sample_count_ && qpc_ok;++i) {
        qpc_ok=samples_[i].end_qpc>samples_[i].begin_qpc;
        if (i>0) qpc_ok=qpc_ok && samples_[i].begin_qpc>=samples_[i-1].end_qpc;
    }
    state_.qpc_valid=qpc_ok;

    const Predicates& p=receipt_.predicates;
    state_.predicates_valid =
        p.full_model_forward &&
        p.real_autoregressive_decode &&
        p.warmup_excluded &&
        p.sealed_logits_reuse_zero &&
        p.synthetic_logits_zero &&
        p.device_lost_zero &&
        p.cert_binary_unchanged;

    return state_.cardinality_valid && state_.qpc_valid && state_.predicates_valid;
}

bool SealAuthority::calculate() noexcept {
    if (!state_.cardinality_valid || !state_.qpc_valid || !state_.predicates_valid)
        return false;

    std::uint64_t d[D2_QPC_MAX_TOKENS]{};
    std::uint64_t sum=0;
    std::uint64_t minv=~0ull;
    std::uint64_t maxv=0;

    for (std::uint32_t i=0;i<sample_count_;++i) {
        d[i]=samples_[i].end_qpc-samples_[i].begin_qpc;
        sum+=d[i];
        if (d[i]<minv) minv=d[i];
        if (d[i]>maxv) maxv=d[i];
    }
    std::sort(d,d+sample_count_);

    auto pct=[&](std::uint32_t pct_value)->std::uint64_t {
        const std::uint64_t num=std::uint64_t(sample_count_-1)*pct_value + 99ull;
        std::uint64_t idx=num/100ull;
        if (idx>=sample_count_) idx=sample_count_-1;
        return d[idx];
    };

    Metrics& m=receipt_.metrics;
    m.generated_tokens=sample_count_;
    m.generation_wall_qpc=samples_[sample_count_-1].end_qpc-samples_[0].begin_qpc;
    m.token_min_qpc=minv;
    m.token_max_qpc=maxv;
    m.token_mean_qpc=sum/sample_count_;
    m.token_p50_qpc=pct(50);
    m.token_p95_qpc=pct(95);

    m.generation_wall_ns=qpc_to_ns(m.generation_wall_qpc,receipt_.qpc_frequency);
    m.token_min_ns=qpc_to_ns(m.token_min_qpc,receipt_.qpc_frequency);
    m.token_max_ns=qpc_to_ns(m.token_max_qpc,receipt_.qpc_frequency);
    m.token_mean_ns=qpc_to_ns(m.token_mean_qpc,receipt_.qpc_frequency);
    m.token_p50_ns=qpc_to_ns(m.token_p50_qpc,receipt_.qpc_frequency);
    m.token_p95_ns=qpc_to_ns(m.token_p95_qpc,receipt_.qpc_frequency);

    m.sustained_tps =
        m.generation_wall_qpc
        ? (double(sample_count_)*double(receipt_.qpc_frequency))/double(m.generation_wall_qpc)
        : 0.0;

    return m.generated_tokens==receipt_.target_tokens && m.sustained_tps>0.0;
}

void SealAuthority::hash_receipt(std::uint8_t out[32]) const noexcept {
    Sha256 s; sha_init(s);
    sha_update(s,receipt_.gate_id,std::strlen(receipt_.gate_id));
    sha_update(s,receipt_.cert_sha256_hex,64);
    sha_update(s,receipt_.authority_name,std::strlen(receipt_.authority_name));
    sha_update(s,&receipt_.grant_nonce,sizeof(receipt_.grant_nonce));
    sha_update(s,&receipt_.qpc_frequency,sizeof(receipt_.qpc_frequency));
    sha_update(s,&receipt_.target_tokens,sizeof(receipt_.target_tokens));
    sha_update(s,&receipt_.observed_tokens,sizeof(receipt_.observed_tokens));

    hash_bool(s,receipt_.predicates.full_model_forward);
    hash_bool(s,receipt_.predicates.real_autoregressive_decode);
    hash_bool(s,receipt_.predicates.warmup_excluded);
    hash_bool(s,receipt_.predicates.sealed_logits_reuse_zero);
    hash_bool(s,receipt_.predicates.synthetic_logits_zero);
    hash_bool(s,receipt_.predicates.device_lost_zero);
    hash_bool(s,receipt_.predicates.cert_binary_unchanged);

    const Metrics& m=receipt_.metrics;
    sha_update(s,&m.generated_tokens,sizeof(m.generated_tokens));
    sha_update(s,&m.generation_wall_qpc,sizeof(m.generation_wall_qpc));
    sha_update(s,&m.token_min_qpc,sizeof(m.token_min_qpc));
    sha_update(s,&m.token_max_qpc,sizeof(m.token_max_qpc));
    sha_update(s,&m.token_mean_qpc,sizeof(m.token_mean_qpc));
    sha_update(s,&m.token_p50_qpc,sizeof(m.token_p50_qpc));
    sha_update(s,&m.token_p95_qpc,sizeof(m.token_p95_qpc));
    sha_update(s,&m.generation_wall_ns,sizeof(m.generation_wall_ns));
    sha_update(s,&m.token_min_ns,sizeof(m.token_min_ns));
    sha_update(s,&m.token_max_ns,sizeof(m.token_max_ns));
    sha_update(s,&m.token_mean_ns,sizeof(m.token_mean_ns));
    sha_update(s,&m.token_p50_ns,sizeof(m.token_p50_ns));
    sha_update(s,&m.token_p95_ns,sizeof(m.token_p95_ns));
    sha_update(s,&m.sustained_tps,sizeof(m.sustained_tps));

    for (std::uint32_t i=0;i<sample_count_;++i) {
        sha_update(s,&samples_[i].begin_qpc,sizeof(samples_[i].begin_qpc));
        sha_update(s,&samples_[i].end_qpc,sizeof(samples_[i].end_qpc));
    }
    sha_finish(s,out);
}

bool SealAuthority::seal() noexcept {
    if (!has_scope(SCOPE_SEAL) || state_.receipt_sealed) return false;
    if (!state_.cardinality_valid || !state_.qpc_valid || !state_.predicates_valid)
        return false;
    if (receipt_.metrics.generated_tokens!=receipt_.target_tokens ||
        receipt_.metrics.sustained_tps<=0.0) return false;

    hash_receipt(receipt_.receipt_sha256);
    state_.receipt_sealed=true;
    return true;
}

bool SealAuthority::mint_tps_authority() noexcept {
    if (!has_scope(SCOPE_MINT_TPS) || !state_.receipt_sealed) return false;
    if (!state_.cardinality_valid || !state_.qpc_valid || !state_.predicates_valid)
        return false;
    state_.full_model_tps_authority=true;
    return true;
}

} // namespace d2qpc
