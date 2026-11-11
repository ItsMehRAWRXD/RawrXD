#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>

namespace rawrxd::debug {
inline uint64_t clock_ms() noexcept { return GetTickCount64(); }
inline unsigned long tid() noexcept { return GetCurrentThreadId(); }

// Per-process flight recorder. All file writes are serialized and flushed.
// Do not place model prompts, source contents or tensor values in labels.
class Recorder {
public:
    struct Active { uint64_t id, since, lastProgress; unsigned long thread; std::string name; uint64_t units; };
private:
    std::mutex mu_;
    std::unordered_map<uint64_t,Active> active_;
    std::atomic<uint64_t> sequence_{0};
    std::atomic<bool> running_{false};
    std::thread monitor_;
    FILE* file_=nullptr;
    uint32_t monitorPeriodMs_=1000, slowThresholdMs_=5000;
    uint64_t lastProgress_=clock_ms();
    uint64_t lastReport_=0;
    void write_locked(const char* type, uint64_t id, const std::string& label,
                      uint64_t elapsed, uint64_t units, unsigned long thread) {
        if(!file_)return;
        // JSONL with labels escaped; labels should be bounded and non-sensitive.
        std::string escaped;escaped.reserve(label.size());
        for(unsigned char c:label){
            if(c=='"'||c=='\\'){escaped+='\\';escaped+=char(c);}
            else if(c<32)escaped+='?';
            else escaped+=char(c);
        }
        std::fprintf(file_,"{\"time_ms\":%llu,\"type\":\"%s\",\"id\":%llu,\"thread\":%lu,\"name\":\"%s\",\"elapsed_ms\":%llu,\"units\":%llu}\n",
          static_cast<unsigned long long>(clock_ms()),type,
          static_cast<unsigned long long>(id),thread,escaped.c_str(),
          static_cast<unsigned long long>(elapsed),static_cast<unsigned long long>(units));
        std::fflush(file_);
    }
    void monitor_loop(){
        while(running_.load(std::memory_order_acquire)){
            {
                std::lock_guard<std::mutex> lk(mu_);
                uint64_t now=clock_ms();
                for(const auto& kv:active_){
                    const auto& a=kv.second;
                    if(now-a.lastProgress>=slowThresholdMs_ && now-lastReport_>=monitorPeriodMs_){
                        write_locked("no_operation_progress",a.id,a.name,now-a.lastProgress,a.units,a.thread);
                    }
                }
                if(now-lastProgress_>=slowThresholdMs_ && now-lastReport_>=monitorPeriodMs_)
                    write_locked("global_no_progress",0,"inference",now-lastProgress_,0,0);
                lastReport_=now;
            }
            for(uint32_t waited=0;running_.load()&&waited<monitorPeriodMs_;waited+=100)
                Sleep((monitorPeriodMs_-waited<100)?monitorPeriodMs_-waited:100);
        }
    }
public:
    Recorder()=default;
    Recorder(const Recorder&)=delete;Recorder& operator=(const Recorder&)=delete;
    ~Recorder(){stop();}
    bool start(const wchar_t* path, uint32_t slowMs=5000,uint32_t pollMs=1000){
        std::lock_guard<std::mutex> lk(mu_);
        if(running_.load()||file_)return false;
        if(_wfopen_s(&file_,path,L"ab")!=0 || !file_)return false;
        slowThresholdMs_=slowMs?slowMs:5000;
        monitorPeriodMs_=pollMs?pollMs:1000;
        lastProgress_=clock_ms();lastReport_=0;
        running_.store(true);
        try{monitor_=std::thread([this]{monitor_loop();});}
        catch(...){running_.store(false);std::fclose(file_);file_=nullptr;return false;}
        return true;
    }
    void stop(){
        running_.store(false);
        if(monitor_.joinable())monitor_.join();
        std::lock_guard<std::mutex> lk(mu_);
        if(file_){std::fflush(file_);std::fclose(file_);file_=nullptr;}
        active_.clear();
    }
    uint64_t begin(std::string name){
        if(name.size()>160)name.resize(160);
        const uint64_t id=++sequence_;
        std::lock_guard<std::mutex> lk(mu_);
        const uint64_t now=clock_ms();
        active_.emplace(id,Active{id,now,now,tid(),std::move(name),0});
        write_locked("begin",id,active_.at(id).name,0,0,tid());
        return id;
    }
    void progress(uint64_t id,uint64_t units=1){
        std::lock_guard<std::mutex> lk(mu_);
        auto it=active_.find(id);if(it==active_.end())return;
        it->second.units+=units;
        it->second.lastProgress=lastProgress_=clock_ms();
        write_locked("progress",id,it->second.name,it->second.lastProgress-it->second.since,it->second.units,tid());
    }
    void end(uint64_t id,bool ok=true){
        std::lock_guard<std::mutex> lk(mu_);
        auto it=active_.find(id);if(it==active_.end())return;
        const uint64_t now=clock_ms();
        write_locked(ok?"end":"error",id,it->second.name,now-it->second.since,it->second.units,tid());
        lastProgress_=now;
        active_.erase(it);
    }
    void counter(const char* name,uint64_t value){
        std::lock_guard<std::mutex> lk(mu_);
        write_locked("counter",0,name?name:"",0,value,tid());
    }
};
class Scope {
    Recorder* r_;uint64_t id_;bool ok_=true;
public:
    Scope(Recorder& r,std::string name):r_(&r),id_(r.begin(std::move(name))){}
    ~Scope(){if(r_)r_->end(id_,ok_);}
    Scope(const Scope&)=delete;Scope& operator=(const Scope&)=delete;
    void progress(uint64_t n=1){r_->progress(id_,n);}
    void fail(){ok_=false;}
};
} // namespace rawrxd::debug
#define DEEP2_TRACE_SCOPE(rec, label) ::rawrxd::debug::Scope deep2_trace_scope_##__LINE__((rec),(label))
