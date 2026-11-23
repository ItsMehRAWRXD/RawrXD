#pragma once
// Native SHA-256 for content-addressed model blobs. No external crypto library.
#include <algorithm>
#include <array>
#include <cstring>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>

namespace RawrXD { namespace REAP {
class SHA256 {
    uint32_t h_[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                    0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint8_t block_[64]={};
    uint64_t total_=0;
    size_t used_=0;
    static uint32_t Rotate(uint32_t x,unsigned n){return (x>>n)|(x<<(32-n));}
    void Transform(const uint8_t* p) {
        static constexpr uint32_t k[64]={
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,
            0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,
            0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,
            0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
            0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,
            0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,
            0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,
            0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,
            0xc67178f2};
        uint32_t w[64];
        for(int i=0;i<16;++i)w[i]=(uint32_t(p[i*4])<<24)|(uint32_t(p[i*4+1])<<16)|
                                   (uint32_t(p[i*4+2])<<8)|p[i*4+3];
        for(int i=16;i<64;++i){
            const auto x=w[i-15],y=w[i-2];
            w[i]=w[i-16]+(Rotate(x,7)^Rotate(x,18)^(x>>3))+
                 w[i-7]+(Rotate(y,17)^Rotate(y,19)^(y>>10));
        }
        uint32_t a=h_[0],b=h_[1],c=h_[2],d=h_[3],e=h_[4],f=h_[5],g=h_[6],h=h_[7];
        for(int i=0;i<64;++i){
            const uint32_t s1=Rotate(e,6)^Rotate(e,11)^Rotate(e,25);
            const uint32_t ch=(e&f)^(~e&g);
            const uint32_t t1=h+s1+ch+k[i]+w[i];
            const uint32_t s0=Rotate(a,2)^Rotate(a,13)^Rotate(a,22);
            const uint32_t maj=(a&b)^(a&c)^(b&c);
            const uint32_t t2=s0+maj;
            h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
        }
        const uint32_t v[8]={a,b,c,d,e,f,g,h};
        for(int i=0;i<8;++i)h_[i]+=v[i];
    }
public:
    bool Update(const uint8_t* p,size_t n){
        if(n==0)return true;
        if(!p)return false;
        if(n>((UINT64_MAX/8)-total_))return false;
        total_+=n;
        size_t offset=0;
        if(used_) {
            const size_t take=std::min(n,size_t(64-used_));
            std::memcpy(block_+used_,p,take);
            used_+=take;offset+=take;
            if(used_==64){Transform(block_);used_=0;}
        }
        while(n-offset>=64){
            Transform(p+offset);
            offset+=64;
        }
        if(offset<n){
            used_=n-offset;
            std::memcpy(block_,p+offset,used_);
        }
        return true;
    }
    std::string Finish(){
        const uint64_t bits=total_*8;
        block_[used_++]=0x80;
        if(used_>56){
            while(used_<64)block_[used_++]=0;
            Transform(block_);used_=0;
        }
        while(used_<56)block_[used_++]=0;
        for(int i=7;i>=0;--i)block_[used_++]=static_cast<uint8_t>(bits>>(i*8));
        Transform(block_);
        std::ostringstream out;
        out<<std::hex<<std::setfill('0');
        for(uint32_t word:h_)out<<std::setw(8)<<word;
        return out.str();
    }
};
inline bool HashFileSHA256(const std::string& path,std::string& hex){
    std::ifstream in(path,std::ios::binary);
    if(!in)return false;
    SHA256 hash;
    std::array<uint8_t,65536> chunk{};
    while(in){
        in.read(reinterpret_cast<char*>(chunk.data()),chunk.size());
        const auto n=in.gcount();
        if(n>0&&!hash.Update(chunk.data(),static_cast<size_t>(n)))return false;
    }
    if(!in.eof())return false;
    hex=hash.Finish();
    return true;
}
}} // namespace RawrXD::REAP
