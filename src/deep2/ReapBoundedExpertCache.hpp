#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <condition_variable>
#include <utility>

namespace Deep2 { namespace ReapQuant {
class BoundedExpertCache {
public:
    using Payload=std::vector<uint8_t>;
    using Lease=std::shared_ptr<const Payload>;
private:
    struct Entry {
        Lease data;
        uint64_t bytes=0, age=0;
        bool loading=true;
    };
    const uint64_t budget_;
    uint64_t reserved_=0, clock_=0;
    mutable std::mutex mutex_;
    std::condition_variable changed_;
    std::unordered_map<std::string,Entry> entries_;
public:
    explicit BoundedExpertCache(uint64_t budget):budget_(budget){}
    uint64_t Reserved() const {
        std::lock_guard<std::mutex> lock(mutex_);return reserved_;
    }
    // Key must include model identity, tensor, expert and precision.
    // Loader must not recursively acquire from this cache.
    // Budget covers payload capacity, not allocator or index overhead.
    template<class Loader>
    bool Acquire(const std::string& key,uint64_t bytes,Loader&& loader,Lease& out){
        if(key.empty()||!bytes||bytes>budget_||bytes>SIZE_MAX)return false;
        std::unique_lock<std::mutex> lock(mutex_);
        for(;;){
            auto it=entries_.find(key);
            if(it==entries_.end())break;
            if(it->second.bytes!=bytes)return false;
            if(it->second.loading){changed_.wait(lock);continue;}
            it->second.age=++clock_;
            Lease value=it->second.data;
            lock.unlock();out=std::move(value);return true;
        }
        while(bytes>budget_-reserved_){
            auto victim=entries_.end();
            for(auto it=entries_.begin();it!=entries_.end();++it)
                if(!it->second.loading&&it->second.data.use_count()==1&&
                   (victim==entries_.end()||it->second.age<victim->second.age))victim=it;
            if(victim==entries_.end())return false;
            reserved_-=victim->second.bytes;entries_.erase(victim);
        }
        entries_.emplace(key,Entry{nullptr,bytes,++clock_,true});
        reserved_+=bytes;
        lock.unlock();
        std::shared_ptr<Payload> pending;
        bool ok=false;
        try {
            pending=std::make_shared<Payload>(size_t(bytes));
            ok=loader(pending->data(),pending->size())&&pending->capacity()==bytes;
        } catch(...) {ok=false;}
        lock.lock();
        auto it=entries_.find(key);
        if(!ok){
            pending.reset();
            reserved_-=bytes;entries_.erase(it);
            lock.unlock();changed_.notify_all();return false;
        }
        it->second.data=std::move(pending);it->second.loading=false;
        it->second.age=++clock_;
        Lease value=it->second.data;
        lock.unlock();changed_.notify_all();out=std::move(value);return true;
    }
};
} }
