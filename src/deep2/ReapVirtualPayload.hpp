#pragma once
#include "ReapMixedPrecision.hpp"
#include "ReapBoundedExpertCache.hpp"
#include "ReapShardIndex.hpp"
#include <cstring>
namespace Deep2 { namespace ReapQuant {
// Reader contract: Read(ShardRange,uint64_t,vector<uint8_t>&).
// Each cache must be scoped to one immutable checkpoint identity.
template<class Reader>
bool AcquireVirtualPayload(Reader& reader,BoundedExpertCache& cache,
 const ShardRange& source,Precision precision,uint64_t maxSourceBytes,
 BoundedExpertCache::Lease& out){
    if(!source.bytes||source.bytes%Q4Bytes||maxSourceBytes<Q4Bytes||
       source.offset>UINT64_MAX-source.bytes)return false;
    const uint64_t stride=precision==Precision::Q2?Q2Bytes:
        precision==Precision::Q3?Q3Bytes:precision==Precision::Q4?Q4Bytes:0;
    if(!stride)return false;
    const uint64_t blocks=source.bytes/Q4Bytes;
    const uint64_t targetBytes=blocks*stride;
    const std::string key=std::to_string(source.shard)+":"+
        std::to_string(source.offset)+":"+std::to_string(source.bytes)+":"+
        std::to_string(unsigned(precision));
    return cache.Acquire(key,targetBytes,[&](uint8_t* dst,size_t size){
        if(size!=targetBytes)return false;
        const uint64_t chunkBlocks=(std::min)(maxSourceBytes/Q4Bytes,uint64_t(256));
        std::vector<uint8_t> chunk;
        for(uint64_t i=0;i<blocks;){
            const uint64_t count=(std::min)(blocks-i,chunkBlocks);
            const uint64_t bytes=count*Q4Bytes;
            if(!reader.Read({source.shard,source.offset+i*Q4Bytes,bytes},
               maxSourceBytes,chunk)||chunk.size()!=bytes)return false;
            for(uint64_t j=0;j<count;++j){
                Q4Block q4{};std::memcpy(q4.data(),chunk.data()+j*Q4Bytes,Q4Bytes);
                auto target=dst+(i+j)*stride;
                Error error{};
                if(precision==Precision::Q2){
                    Q2Block q{};if(!ConvertAdaptive(q4,q,error))return false;
                    std::memcpy(target,q.data(),Q2Bytes);
                }else if(precision==Precision::Q3){
                    Q3Block q{};if(!ConvertQ4ToQ3(q4,q,error))return false;
                    std::memcpy(target,q.data(),Q3Bytes);
                }else{
                    Values values{};if(!DecodeQ4(q4,values))return false;
                    std::memcpy(target,q4.data(),Q4Bytes);
                }
            }
            i+=count;
        }
        return true;
    },out);
}
} }
