#pragma once
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include "ReapShardIndex.hpp"
#include <vector>
#include <algorithm>
#include <mutex>
#include <memory>

namespace Deep2 { namespace ReapQuant {
class NativeShardReader {
    struct File {
        HANDLE handle=INVALID_HANDLE_VALUE;
        uint64_t size=0;
        ~File(){if(handle!=INVALID_HANDLE_VALUE)CloseHandle(handle);}
    };
    mutable std::mutex mutex_;
    std::unordered_map<uint32_t,std::shared_ptr<File>> files_;
    bool sealed_=false;
public:
    bool Open(uint32_t id,const std::wstring& path,uint64_t expectedBytes) {
        auto f=std::make_shared<File>();
        f->handle=CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,
            OPEN_EXISTING,FILE_FLAG_OVERLAPPED|FILE_FLAG_RANDOM_ACCESS,nullptr);
        if(f->handle==INVALID_HANDLE_VALUE)return false;
        LARGE_INTEGER size{};
        if(GetFileType(f->handle)!=FILE_TYPE_DISK||!GetFileSizeEx(f->handle,&size)||
           size.QuadPart<=0||uint64_t(size.QuadPart)!=expectedBytes)return false;
        f->size=expectedBytes;
        std::lock_guard<std::mutex> lock(mutex_);
        return !sealed_&&files_.emplace(id,std::move(f)).second;
    }
    bool Seal(){
        std::lock_guard<std::mutex> lock(mutex_);
        if(files_.empty())return false;
        sealed_=true;return true;
    }
    bool Read(ShardRange range,uint64_t maxBytes,std::vector<uint8_t>& out) const {
        std::shared_ptr<File> f;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            const auto it=files_.find(range.shard);
            if(!sealed_||it==files_.end())return false;
            f=it->second;
        }
        if(!range.bytes||range.bytes>maxBytes||range.bytes>SIZE_MAX||
           range.offset>f->size||range.bytes>f->size-range.offset)return false;
        std::vector<uint8_t> pending;
        if(range.bytes>pending.max_size())return false;
        try {pending.resize(size_t(range.bytes));} catch(...) {return false;}
        struct Event {
            HANDLE h=CreateEventW(nullptr,TRUE,FALSE,nullptr);
            ~Event(){if(h)CloseHandle(h);}
        } event;
        if(!event.h)return false;
        uint64_t done=0;
        while(done<range.bytes){
            const DWORD count=DWORD((std::min)(range.bytes-done,uint64_t(1u<<20)));
            const uint64_t position=range.offset+done;
            OVERLAPPED ov{};
            ov.Offset=DWORD(position);ov.OffsetHigh=DWORD(position>>32);ov.hEvent=event.h;
            if(!ResetEvent(event.h))return false;
            DWORD got=0;
            if(!ReadFile(f->handle,pending.data()+size_t(done),count,nullptr,&ov)&&
               GetLastError()!=ERROR_IO_PENDING)return false;
            if(!GetOverlappedResult(f->handle,&ov,&got,TRUE)||got!=count)return false;
            done+=got;
        }
        out.swap(pending);return true;
    }
};
} }
#endif
