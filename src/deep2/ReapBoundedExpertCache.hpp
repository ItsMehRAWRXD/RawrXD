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
    class Lease {
        friend class BoundedExpertCache;
        std::shared_ptr<const Payload> data_;
        explicit Lease(std::shared_ptr<const Payload> p):data_(std::move(p)){}
    public:
        Lease()=default;
        Lease(std::nullptr_t){}
        explicit operator bool() const noexcept {return bool(data_);}
        const Payload* operator->() const noexcept {return data_.get();}
        const Payload& operator*() const noexcept {return *data_;}
        const Payload* get() const noexcept {return data_.get();}
        void reset() noexcept {data_.reset();}
        friend bool operator==(const Lease& a,const Lease& b) noexcept {return a.data_==b.data_;}
        friend bool operator!=(const Lease& a,const Lease& b) noexcept {return !(a==b);}
    };
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
        // Never leave an earlier successful payload in the output after a
        // rejected acquisition. Reset before validation and admission.
        out.reset();
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
                if(!it->second.loading&&it->second.data.data_.use_count()==1&&
                   (victim==entries_.end()||it->second.age<victim->second.age))victim=it;
            if(victim==entries_.end())return false;
            reserved_-=victim->second.bytes;entries_.erase(victim);
        }
        try { entries_.emplace(key,Entry{nullptr,bytes,++clock_,true}); }
        catch (...) { return false; }
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
            // Publish failure and release the reservation before notifying
            // waiters. Keep destruction outside the cache mutex.
            reserved_-=bytes;
            entries_.erase(it);
            lock.unlock();
            pending.reset();
            changed_.notify_all();
            return false;
        }
        it->second.data=Lease(std::move(pending));it->second.loading=false;
        it->second.age=++clock_;
        Lease value=it->second.data;
        lock.unlock();changed_.notify_all();out=std::move(value);return true;
    }
};
} }
