#pragma once
#include "ReapQ4KToQ2K.hpp"
#include <istream>
#include <ostream>

namespace Deep2 { namespace ReapQuant {
struct RangeStats {
    uint64_t blocks=0;
    double squared=0,signal=0,maxAbs=0;
    double RelativeRmse() const noexcept {
        return signal>0?std::sqrt(squared/signal):squared==0?0:std::numeric_limits<double>::infinity();
    }
};
// Streams whole Q4_K blocks into Q2_K. Caller owns the staging output and
// must discard it on failure, including failure of the quality gate.
inline bool ConvertRange(std::istream& in,std::ostream& out,uint64_t sourceBytes,RangeStats& stats) {
    if(!sourceBytes||sourceBytes%Q4Bytes||!in.good()||!out.good()||
       !std::isfinite(stats.squared)||!std::isfinite(stats.signal)||
       !std::isfinite(stats.maxAbs)||stats.squared<0||stats.signal<0||
       stats.maxAbs<0)return false;
    constexpr size_t batch=256;
    std::array<Q4Block,batch> source{};
    std::array<Q2Block,batch> target{};
    RangeStats next=stats;
    uint64_t remaining=sourceBytes/Q4Bytes;
    if(remaining>UINT64_MAX-next.blocks)return false;
    while(remaining){
        const size_t count=static_cast<size_t>(std::min<uint64_t>(remaining,batch));
        if(!in.read(reinterpret_cast<char*>(source.data()),static_cast<std::streamsize>(count*Q4Bytes)))return false;
        for(size_t i=0;i<count;++i){
            Error error;
            if(!ConvertAdaptive(source[i],target[i],error))return false;
            next.squared+=error.squared;next.signal+=error.signal;next.maxAbs=std::max(next.maxAbs,error.maxAbs);
        }
        if(!std::isfinite(next.squared)||!std::isfinite(next.signal)||
           !std::isfinite(next.maxAbs)||!out.write(reinterpret_cast<const char*>(target.data()),static_cast<std::streamsize>(count*Q2Bytes)))return false;
        next.blocks+=count;remaining-=count;
    }
    stats=next;return true;
}
} } // namespace Deep2::ReapQuant
