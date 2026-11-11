#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>
#include <utility>

namespace rawrxd::snap {
struct Handle {
    HANDLE h=nullptr;
    explicit Handle(HANDLE v=nullptr):h(v){}
    ~Handle(){if(h && h!=INVALID_HANDLE_VALUE) CloseHandle(h);}
    Handle(const Handle&)=delete;
    Handle& operator=(const Handle&)=delete;
    HANDLE get()const{return h;}
    explicit operator bool()const{return h && h!=INVALID_HANDLE_VALUE;}
};
inline uint64_t stamp(FILETIME t) {
    ULARGE_INTEGER u{};u.LowPart=t.dwLowDateTime;u.HighPart=t.dwHighDateTime;
    return u.QuadPart;
}
inline uint64_t started(HANDLE p){
    FILETIME c{},e{},k{},u{};
    return GetProcessTimes(p,&c,&e,&k,&u)?stamp(c):0;
}
inline std::wstring image(HANDLE p){
    std::wstring s(32768,L'\0');DWORD n=static_cast<DWORD>(s.size());
    if(!QueryFullProcessImageNameW(p,0,s.data(),&n))return {};
    s.resize(n);return s;
}
struct Process {
    DWORD pid=0,parent=0;
    uint64_t created=0,workingSet=0,privateBytes=0;
    std::wstring path;
    bool inOurJob=false;
};
struct Snapshot {
    uint64_t tick=0,availablePhysical=0,totalPhysical=0;
    SIZE_T selfWorkingSet=0;
    std::vector<Process> processes;
    uint64_t scanFailures=0;
};
inline Snapshot capture(HANDLE job=nullptr) {
    Snapshot out;out.tick=GetTickCount64();
    MEMORYSTATUSEX m{};m.dwLength=sizeof(m);
    if(GlobalMemoryStatusEx(&m)){out.availablePhysical=m.ullAvailPhys;out.totalPhysical=m.ullTotalPhys;}
    PROCESS_MEMORY_COUNTERS_EX pm{};pm.cb=sizeof(pm);
    if(GetProcessMemoryInfo(GetCurrentProcess(),reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pm),sizeof(pm)))
        out.selfWorkingSet=pm.WorkingSetSize;
    Handle ss(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0));
    if(!ss){++out.scanFailures;return out;}
    PROCESSENTRY32W e{};e.dwSize=sizeof(e);
    if(!Process32FirstW(ss.get(),&e)){++out.scanFailures;return out;}
    do {
        if(_wcsicmp(e.szExeFile,L"deep2_agentic_loop.exe")!=0)continue;
        Process x;x.pid=e.th32ProcessID;x.parent=e.th32ParentProcessID;
        Handle p(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,x.pid));
        if(!p){++out.scanFailures;continue;}
        x.created=started(p.get());x.path=image(p.get());
        if(job){BOOL yes=FALSE;if(IsProcessInJob(p.get(),job,&yes))x.inOurJob=(yes!=FALSE);}
        Handle full(OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,x.pid));
        if(full){
            PROCESS_MEMORY_COUNTERS_EX pc{};pc.cb=sizeof(pc);
            if(GetProcessMemoryInfo(full.get(),reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pc),sizeof(pc))){
                x.workingSet=pc.WorkingSetSize;x.privateBytes=pc.PrivateUsage;
            }
        }
        out.processes.push_back(std::move(x));
    }while(Process32NextW(ss.get(),&e));
    return out;
}
enum class EventKind { Scan, NewProcess, ExitedProcess, MemoryPressure, ProcessPressure, ScanIncomplete };
struct Event {EventKind kind;DWORD pid=0;uint64_t value=0;};
class Detector {
    std::atomic<bool> running_{false};
    std::thread worker_;
    std::mutex mu_;
    std::unordered_map<DWORD,uint64_t> seen_;
    HANDLE job_=nullptr; // caller must keep Job Object alive until Stop()
    std::function<void(const Event&)> sink_;
    uint32_t periodMs_=2000;
    uint64_t lowRamBytes_=2ull*1024*1024*1024;
    size_t maxLoops_=1;
    void emit(EventKind k,DWORD pid,uint64_t v) {
        try {if(sink_)sink_(Event{k,pid,v});}catch(...){} // telemetry must not kill supervisor
    }
    void loop(){
        while(running_.load()){
            Snapshot s=capture(job_);
            emit(EventKind::Scan,0,s.processes.size());
            if(s.scanFailures)emit(EventKind::ScanIncomplete,0,s.scanFailures);
            if(s.availablePhysical && s.availablePhysical<lowRamBytes_)
                emit(EventKind::MemoryPressure,0,s.availablePhysical);
            if(s.processes.size()>maxLoops_)
                emit(EventKind::ProcessPressure,0,s.processes.size());
            std::unordered_map<DWORD,uint64_t> now;
            for(const auto& p:s.processes){
                if(!p.created)continue;
                now[p.pid]=p.created;
            }
            // Incomplete scans cannot prove a process exited.
            if(!s.scanFailures){
                for(auto [pid,creation]:now){
                    auto it=seen_.find(pid);
                    if(it==seen_.end() || it->second!=creation)
                        emit(EventKind::NewProcess,pid,creation);
                }
                for(auto [pid,creation]:seen_){
                    auto it=now.find(pid);
                    if(it==now.end() || it->second!=creation)
                        emit(EventKind::ExitedProcess,pid,creation);
                }
                seen_.swap(now);
            }
            for(uint32_t waited=0;running_.load() && waited<periodMs_;waited+=100)
                Sleep((periodMs_-waited)<100?(periodMs_-waited):100);
        }
    }
public:
    Detector()=default;
    ~Detector(){Stop();}
    Detector(const Detector&)=delete;Detector& operator=(const Detector&)=delete;
    bool Start(std::function<void(const Event&)> sink,HANDLE job=nullptr,uint32_t periodMs=2000){
        std::lock_guard<std::mutex> lock(mu_);
        if(running_.load() || !sink)return false;
        sink_=std::move(sink);job_=job;periodMs_=periodMs?periodMs:2000;
        running_.store(true);
        try{worker_=std::thread([this]{loop();});}
        catch(...){running_.store(false);return false;}
        return true;
    }
    void Stop(){
        std::lock_guard<std::mutex> lock(mu_);
        running_.store(false);
        if(worker_.joinable())worker_.join();
        seen_.clear();
    }
};
// Fail-closed identity predicate: never treat this as an abandonment proof.
// Termination requires a separate verified, persistent task lease and authorization.
inline bool sameProcessIdentity(const Process& p){
    if(p.pid==GetCurrentProcessId() || !p.created || p.path.empty())return false;
    Handle h(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE,FALSE,p.pid));
    return h && WaitForSingleObject(h.get(),0)==WAIT_TIMEOUT &&
           started(h.get())==p.created && image(h.get())==p.path;
}
} // namespace rawrxd::snap
