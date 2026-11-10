#pragma once
// Standalone, opt-in IR activation dump. No new runtime dependencies.
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>

namespace RawrXD_IR_Trace {
inline bool interesting(uint32_t op) {
    return op<=11 || op==12 || op==13 || op==14 || op==15 || op==16 ||
           op==17 || op==18 || op==19 || op==20 || op==21 || op==22 ||
           op==298 || op==299;
}
inline void save(uint32_t op,const float* ptr,size_t count) {
    if (!interesting(op)) return;
    const char* dir=std::getenv("RAWRXD_PARITY_DIR");
    if (!dir||!*dir) return; // disabled by default
    if (!ptr || count==0 || count>102400) {
        std::fprintf(stderr,"PARITY_DUMP_FAIL OP=%u BAD_LENGTH=%zu\n",op,count);return;
    }
    size_t bad=0;
    for(size_t i=0;i<count;++i)bad+=!std::isfinite(ptr[i]);
    char basename[32]; std::snprintf(basename,sizeof(basename),"op_%03u.bin",op);
    std::filesystem::path path = std::filesystem::path(dir)/basename;
    std::error_code ec; std::filesystem::create_directories(path.parent_path(),ec);
    if(ec){std::fprintf(stderr,"PARITY_DUMP_FAIL OP=%u DIR_ERROR=%d\n",op,ec.value());return;}
    FILE* f=nullptr;
#ifdef _MSC_VER
    const auto wide=path.wstring();
    if(_wfopen_s(&f,wide.c_str(),L"wb")!=0)f=nullptr;
#else
    f=std::fopen(path.string().c_str(),"wb");
#endif
    if(!f){std::fprintf(stderr,"PARITY_DUMP_FAIL OP=%u OPEN=0\n",op);return;}
    const size_t written=std::fwrite(ptr,sizeof(float),count,f);
    const bool closeOK=std::fclose(f)==0;
    if(written!=count||!closeOK){std::fprintf(stderr,"PARITY_DUMP_FAIL OP=%u WRITE=0\n",op);return;}
    std::fprintf(stderr,"PARITY_DUMP OP=%u COUNT=%zu NONFINITE=%zu\n",op,count,bad);
}
}
