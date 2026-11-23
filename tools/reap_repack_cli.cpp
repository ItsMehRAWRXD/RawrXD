#include "../src/reap/NativeGGUFPublisher.hpp"
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <string>

int main(int argc, char** argv) {
    if(argc<3 || argc>6) {
        std::cerr<<"Usage: rawrxd-reap-repack INPUT.gguf OUTPUT.gguf"
                    " [--f16 | --q8-0] [--max-bytes POSITIVE_INTEGER]\n";
        return 2;
    }
    uint64_t budget=UINT64_MAX;
    bool f16=false, q8=false, budgetSeen=false;
    for(int i=3;i<argc;++i) {
        const std::string arg=argv[i];
        if(arg=="--f16"&&!f16&&!q8){f16=true;continue;}
        if(arg=="--q8-0"&&!q8&&!f16){q8=true;continue;}
        if(arg=="--max-bytes"&&!budgetSeen&&i+1<argc) {
            const char* valueText=argv[++i];
            if(!valueText[0]||valueText[0]=='-')return 2;
            errno=0;char* end=nullptr;
            const unsigned long long value=std::strtoull(valueText,&end,10);
            if(errno||!end||*end||!value)return 2;
            budget=static_cast<uint64_t>(value);
            budgetSeen=true;continue;
        }
        std::cerr<<"Invalid option: "<<arg<<"\n";return 2;
    }
    const auto result = RawrXD::REAP::PublishRepackedGGUF(argv[1], argv[2], budget, f16, q8);
    if (result.error != RawrXD::REAP::PublishError::None) {
        std::cerr << "REAP_REPACK_RESULT=FAIL error="
                  << static_cast<int>(result.error) << " repack_error=" << static_cast<int>(result.repack_error) << "\n";
        return 1;
    }
    std::cout << "REAP_REPACK_RESULT=PASS output=" << argv[2] << "\n";
    return 0;
}
