#pragma once
#include "ReapBoundedExpertCache.hpp"
#include <functional>
#include <thread>
#include <algorithm>
#include <unordered_set>
namespace Deep2 { namespace ReapQuant {
class ExpertPrefetch {
public:
    using Loader=std::function<bool(uint8_t*,size_t)>;
private:
    struct Job { std::string key; uint64_t bytes; int priority; Loader load; };
    BoundedExpertCache& cache_;
    const size_t limit_;
    std::mutex mutex_;
    std::condition_variable wake_;
    std::vector<Job> queue_;
    std::unordered_set<std::string> active_;
    bool stopping_=false;
    std::thread worker_;
    void Run(){
        for(;;){
            std::unique_lock<std::mutex> lock(mutex_);
            wake_.wait(lock,[&]{return stopping_||!queue_.empty();});
            if(stopping_)return;
            auto it=std::max_element(queue_.begin(),queue_.end(),
                [](const Job& a,const Job& b){return a.priority<b.priority;});
            Job job=std::move(*it);queue_.erase(it);
            lock.unlock();
            try { BoundedExpertCache::Lease lease;
                cache_.Acquire(job.key,job.bytes,job.load,lease);
            } catch(...) {}
            lock.lock();active_.erase(job.key);wake_.notify_all();
        }
    }
public:
    // Cache and loader-owned resources must outlive this worker.
    ExpertPrefetch(BoundedExpertCache& cache,size_t limit):
        cache_(cache),limit_(limit),worker_([this]{Run();}){}
    ~ExpertPrefetch(){Stop();}
    bool Submit(std::string key,uint64_t bytes,int priority,Loader load){
        if(key.empty()||!bytes||!load)return false;
        std::lock_guard<std::mutex> lock(mutex_);
        if(stopping_||active_.size()>=limit_||active_.count(key))return false;
        auto inserted=active_.insert(key);
        try {queue_.push_back({std::move(key),bytes,priority,std::move(load)});}
        catch(...){active_.erase(inserted.first);return false;}
        wake_.notify_one();return true;
    }
    bool CancelQueued(const std::string& key){
        std::lock_guard<std::mutex> lock(mutex_);
        auto it=std::find_if(queue_.begin(),queue_.end(),[&](const Job& j){return j.key==key;});
        if(it==queue_.end())return false;
        active_.erase(key);queue_.erase(it);wake_.notify_all();return true;
    }
    void WaitIdle(){
        std::unique_lock<std::mutex> lock(mutex_);
        wake_.wait(lock,[&]{return active_.empty();});
    }
    // Owner-thread shutdown; running I/O is drained, never force-killed.
    void Stop(){
        {std::lock_guard<std::mutex> lock(mutex_);
         stopping_=true;for(const auto& j:queue_)active_.erase(j.key);
         queue_.clear();wake_.notify_all();}
        if(worker_.joinable())worker_.join();
    }
};
} }
