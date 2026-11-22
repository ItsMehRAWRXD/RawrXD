#include "deep2/ReapVirtualPayload.hpp"
#include <cstdio>
#include <cstring>
#include <vector>
using namespace Deep2::ReapQuant;

struct MemoryReader {
    std::vector<uint8_t> data;
    unsigned reads=0;
    bool Read(ShardRange r,uint64_t limit,std::vector<uint8_t>& out) {
        ++reads;
        if(r.shard!=3||r.bytes>limit||r.offset>data.size()||
           r.bytes>data.size()-r.offset)return false;
        out.assign(data.begin()+static_cast<size_t>(r.offset),
                   data.begin()+static_cast<size_t>(r.offset+r.bytes));
        return true;
    }
};
int main(){
    unsigned passed=0,failed=0;
    auto check=[&](bool ok,const char* name){
        std::printf("%s %s\n",ok?"PASS":"FAIL",name);
        if(ok)++passed;else ++failed;
    };
    MemoryReader reader;
    constexpr unsigned blocks=3;
    reader.data.resize(blocks*Q4Bytes);
    for(unsigned n=0;n<blocks;++n){
        Q4Block source{};
        StoreHalf(source.data(),static_cast<uint16_t>(0x3000+n*13));
        StoreHalf(source.data()+2,static_cast<uint16_t>(0x2800+n*17));
        for(unsigned i=4;i<Q4Bytes;++i)
            source[i]=static_cast<uint8_t>(n*37+i*11);
        std::memcpy(reader.data.data()+n*Q4Bytes,source.data(),Q4Bytes);
    }
    BoundedExpertCache cache(blocks*Q4Bytes*3);
    const ShardRange range{3,0,blocks*Q4Bytes};
    BoundedExpertCache::Lease q2;
    check(AcquireVirtualPayload(reader,cache,range,Precision::Q2,
                                Q4Bytes,q2)&&q2&&q2->size()==blocks*Q2Bytes &&
          reader.reads==blocks,"Q2 payload with one-block read windows");
    if(q2){
        bool equal=true;
        for(unsigned n=0;n<blocks;++n){
            Q4Block source{};Q2Block reference{};Error err{};
            std::memcpy(source.data(),reader.data.data()+n*Q4Bytes,Q4Bytes);
            equal=equal&&Convert(source,reference,err)&&
                  std::memcmp(q2->data()+n*Q2Bytes,reference.data(),Q2Bytes)==0;
        }
        check(equal,"virtual Q2 payload matches scalar oracle byte for byte");
    }
    BoundedExpertCache::Lease reused;
    const unsigned before=reader.reads;
    check(AcquireVirtualPayload(reader,cache,range,Precision::Q2,
                                Q4Bytes,reused)&&reused==q2&&
          reader.reads==before,"same-key cache hit does not reread shard");
    BoundedExpertCache::Lease q3,q4;
    check(AcquireVirtualPayload(reader,cache,range,Precision::Q3,
                                2*Q4Bytes,q3)&&q3&&q3->size()==blocks*Q3Bytes,
          "Q3 payload with two-block read windows");
    check(AcquireVirtualPayload(reader,cache,range,Precision::Q4,
                                2*Q4Bytes,q4)&&q4&&q4->size()==reader.data.size()&&
          std::memcmp(q4->data(),reader.data.data(),reader.data.size())==0,
          "Q4 payload retains original block bytes");
    BoundedExpertCache::Lease rejected;
    check(!AcquireVirtualPayload(reader,cache,{3,0,Q4Bytes-1},Precision::Q2,
                                 Q4Bytes,rejected)&&!rejected,
          "unaligned source length rejected");
    check(!AcquireVirtualPayload(reader,cache,range,Precision::Q2,
                                 Q4Bytes-1,rejected)&&!rejected,
          "source window below one block rejected");
    MemoryReader missing;
    BoundedExpertCache separate(blocks*Q2Bytes);
    check(!AcquireVirtualPayload(missing,separate,range,Precision::Q2,
                                 Q4Bytes,rejected)&&!rejected&&
          separate.Reserved()==0,
          "failed reader releases cache reservation");
    std::printf("PASS_COUNT=%u FAIL_COUNT=%u\n",passed,failed);
    return failed?1:0;
}
