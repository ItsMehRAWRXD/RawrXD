#pragma once
#include <cstdint>
#include <cstddef>
#include <map>
#include <deque>
#include <mutex>
#include <vector>
#include <utility>
namespace Deep2 { namespace ReapQuant {
// Nonblocking admission; one consumer dispatches returned jobs.
// Cancellation removes queued work only, never in-flight GPU work.
class FairDispatch {
public:
    struct Job { uint64_t agent=0, ticket=0; };
private:
    std::mutex mutex_;
    std::map<uint64_t,std::deque<uint64_t>> queues_;
    size_t size_=0;
    const size_t limit_,perAgent_;
    uint64_t last_=0,next_=1;
    bool closed_=false;
public:
    FairDispatch(size_t limit,size_t perAgent):limit_(limit),perAgent_(perAgent){}
    uint64_t Submit(uint64_t agent){
        std::lock_guard<std::mutex> lock(mutex_);
        if(!agent||closed_||size_>=limit_||!perAgent_||next_==UINT64_MAX)return 0;
        auto it=queues_.find(agent);
        if(it!=queues_.end()&&it->second.size()>=perAgent_)return 0;
        try {queues_[agent].push_back(next_);}
        catch(...){auto q=queues_.find(agent);if(q!=queues_.end()&&q->second.empty())queues_.erase(q);return 0;}
        ++size_;return next_++;
    }
    bool Pop(Job& out){
        std::lock_guard<std::mutex> lock(mutex_);
        if(!size_)return false;
        auto it=queues_.upper_bound(last_);
        if(it==queues_.end())it=queues_.begin();
        out={it->first,it->second.front()};
        last_=it->first;it->second.pop_front();--size_;
        if(it->second.empty())queues_.erase(it);
        return true;
    }
    size_t CancelQueued(uint64_t agent){
        std::lock_guard<std::mutex> lock(mutex_);
        auto it=queues_.find(agent);if(it==queues_.end())return 0;
        const auto n=it->second.size();size_-=n;queues_.erase(it);return n;
    }
    void Close(){std::lock_guard<std::mutex> lock(mutex_);closed_=true;}
    size_t Pending(){std::lock_guard<std::mutex> lock(mutex_);return size_;}
};
} }
