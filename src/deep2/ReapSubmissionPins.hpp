#pragma once
#include "ReapBoundedExpertCache.hpp"
#include <map>
#include <exception>
namespace Deep2 { namespace ReapQuant {
// Owner must register before submission, and report completion only after
// successful fence wait or externally confirmed terminal device teardown.
// Payload pins do not own Vulkan buffers; those retain their existing owners.
class SubmissionPins {
    struct Entry { uint64_t generation; std::vector<BoundedExpertCache::Lease> pins; };
    std::mutex mutex_;
    std::map<uint64_t,Entry> live_;
    uint64_t next_=1;
    const size_t limit_;
public:
    explicit SubmissionPins(size_t limit):limit_(limit){}
    // Destruction with outstanding submissions is a lifecycle violation.
    ~SubmissionPins(){if(!live_.empty())std::terminate();}
    uint64_t Retain(uint64_t generation,const std::vector<BoundedExpertCache::Lease>& pins){
        if(!generation||pins.empty())return 0;
        for(const auto& p:pins)if(!p)return 0;
        std::lock_guard<std::mutex> lock(mutex_);
        if(live_.size()>=limit_||next_==UINT64_MAX)return 0;
        try {live_.emplace(next_,Entry{generation,pins});}catch(...){return 0;}
        return next_++;
    }
    enum class Outcome { NotSubmitted, FenceComplete, WaitFailed, DeviceLost };
    bool Resolve(uint64_t generation,uint64_t ticket,Outcome outcome){
        if(outcome!=Outcome::NotSubmitted&&outcome!=Outcome::FenceComplete)return false;
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it=live_.find(ticket);
        if(it==live_.end()||it->second.generation!=generation)return false;
        live_.erase(it);return true;
    }
    // Caller captures watermark BEFORE waiting for device idle / teardown.
    uint64_t Watermark(){
        std::lock_guard<std::mutex> lock(mutex_);return next_-1;
    }
    // Caller must close submission admission across capture and idle wait.
    size_t ReclaimConfirmedIdle(uint64_t generation,uint64_t watermark){
        std::lock_guard<std::mutex> lock(mutex_);
        if(watermark>=next_)return 0;
        size_t count=0;
        for(auto it=live_.begin();it!=live_.end()&&it->first<=watermark;){
            if(it->second.generation==generation){it=live_.erase(it);++count;}
            else ++it;
        }
        return count;
    }
    size_t Outstanding(){
        std::lock_guard<std::mutex> lock(mutex_);return live_.size();
    }
};
} }
