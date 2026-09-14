#include "Deep2B70Receipt.hpp"
#include <array>
#include <sstream>
#include <iomanip>
#include <cstring>

namespace Deep2 {

// Compact dependency-free SHA-256 for receipt integrity.
// This is a digest, not a digital signature.
class Sha256 {
    uint32_t h[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    uint8_t buf[64]{};
    uint64_t total=0;
    size_t used=0;

    static uint32_t rr(uint32_t x,uint32_t n){return (x>>n)|(x<<(32-n));}
    void block(const uint8_t* p) {
        static const uint32_t k[64]={
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
        uint32_t w[64];
        for(int i=0;i<16;++i)
            w[i]=(uint32_t(p[i*4])<<24)|(uint32_t(p[i*4+1])<<16)|
                 (uint32_t(p[i*4+2])<<8)|uint32_t(p[i*4+3]);
        for(int i=16;i<64;++i) {
            uint32_t s0=rr(w[i-15],7)^rr(w[i-15],18)^(w[i-15]>>3);
            uint32_t s1=rr(w[i-2],17)^rr(w[i-2],19)^(w[i-2]>>10);
            w[i]=w[i-16]+s0+w[i-7]+s1;
        }
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for(int i=0;i<64;++i) {
            uint32_t S1=rr(e,6)^rr(e,11)^rr(e,25);
            uint32_t ch=(e&f)^((~e)&g);
            uint32_t t1=hh+S1+ch+k[i]+w[i];
            uint32_t S0=rr(a,2)^rr(a,13)^rr(a,22);
            uint32_t maj=(a&b)^(a&c)^(b&c);
            uint32_t t2=S0+maj;
            hh=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
        }
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
    }
public:
    void add(const uint8_t* p,size_t n) {
        total+=n;
        while(n) {
            size_t take=64-used;
            if(take>n) take=n;
            std::memcpy(buf+used,p,take);
            used+=take;p+=take;n-=take;
            if(used==64){block(buf);used=0;}
        }
    }
    std::string finish() {
        uint64_t bits=total*8;
        buf[used++]=0x80;
        if(used>56){while(used<64)buf[used++]=0;block(buf);used=0;}
        while(used<56)buf[used++]=0;
        for(int i=7;i>=0;--i)buf[used++]=uint8_t(bits>>(i*8));
        block(buf);
        std::ostringstream o;
        o<<std::hex<<std::setfill('0');
        for(auto v:h)o<<std::setw(8)<<v;
        return o.str();
    }
};

static std::string hashText(const std::string& s) {
    Sha256 h;
    h.add(reinterpret_cast<const uint8_t*>(s.data()),s.size());
    return h.finish();
}

B70Receipt B70ReceiptWriter::make(const B66RuntimeMeta& m,
                                  const B68Calibration& cal,
                                  const B69Contract& c,
                                  const B69Result& r) {
    std::ostringstream o;
    o<<std::fixed<<std::setprecision(6);
    o<<"DEEP2_LIVE_CONTRACT_RECEIPT=1\n";
    o<<"MODEL_ARCH="<<m.architecture<<"\n";
    o<<"LAYERS="<<m.layers<<"\n";
    o<<"HIDDEN="<<m.hidden<<"\n";
    o<<"EXPERTS="<<m.experts<<"\n";
    o<<"EXPERTS_PER_TOKEN="<<m.expertsPerToken<<"\n";
    o<<"CONTEXT="<<m.context<<"\n";
    o<<"CONTRACT="<<c.name<<"\n";
    o<<"SAMPLES="<<r.stats.samples<<"\n";
    o<<"P10_TPS="<<r.stats.p10Tps<<"\n";
    o<<"MEDIAN_TPS="<<r.stats.medianTps<<"\n";
    o<<"PHYSICAL_ROOFLINE_TPS="<<cal.physicalRooflineTps<<"\n";
    o<<"P10_ROOFLINE_FRACTION="<<r.stats.p10RooflineFraction<<"\n";
    o<<"OVERLAP="<<r.stats.medianOverlap<<"\n";
    o<<"P90_SKEW="<<r.stats.p90Skew<<"\n";
    o<<"P90_HOST_SYNC="<<r.stats.p90HostSync<<"\n";
    o<<"P90_QUEUE_IDLE="<<r.stats.p90QueueIdle<<"\n";
    o<<"GPU0_FORWARDS="<<r.stats.gpu0Forwards<<"\n";
    o<<"GPU1_FORWARDS="<<r.stats.gpu1Forwards<<"\n";
    o<<"RELOAD_BYTES="<<r.stats.reloadBytes<<"\n";
    o<<"HOST_MATERIALIZATIONS="<<r.stats.hostMaterializations<<"\n";
    o<<"HOST_TOKEN_COPIES="<<r.stats.hostTokenCopies<<"\n";
    o<<"PEER_COPY_BYTES="<<r.stats.peerCopyBytes<<"\n";
    o<<"PARITY_ALL="<<(r.stats.parityAll?1:0)<<"\n";
    o<<"OUTPUT_STABLE_ALL="<<(r.stats.stableAll?1:0)<<"\n";
    o<<"CERT="<<(r.pass?"PASS":"HOLD")<<"\n";
    o<<"FAILURE="<<r.failure<<"\n";

    B70Receipt out;
    out.canonicalText=o.str();
    out.sha256Hex=hashText(out.canonicalText);
    return out;
}

bool B70ReceiptWriter::verify(const B70Receipt& r) {
    return hashText(r.canonicalText)==r.sha256Hex;
}

} // namespace Deep2
