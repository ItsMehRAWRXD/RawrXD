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
                    " [--f16 | --q8-0 | --q4-0 | --q5-0 | --auto] [--max-bytes POSITIVE_INTEGER]\n"
                    "  --q4-0 requantizes eligible FP32/FP16 and quantized tensors.\n"
                    "  --q5-0 requantizes Q6_K tensors only; other types are preserved.\n"
                    "  --auto selects tensor-aware compression: F64->F32, F32->F16 for\n"
                    "  sensitive/unaligned tensors, Q8_0 for ordinary F32/F16 vectors,\n"
                    "  Q4_0 for eligible ordinary matrices/Q4_1 vectors, and Q5_0 for\n"
                    "  eligible Q6_K/Q5_1 sensitive tensors. Lossy conversions may occur.\n"
                    "  No mode guarantees numerical parity; validate the resulting model.\n";
        return 2;
    }
    uint64_t budget=UINT64_MAX;
    bool f16=false, q8=false, q4=false, q5=false, automatic=false, budgetSeen=false;
    for(int i=3;i<argc;++i) {
        const std::string arg=argv[i];
        if(arg=="--f16"&&!f16&&!q8&&!q4&&!q5&&!automatic){f16=true;continue;}
        if(arg=="--q8-0"&&!q8&&!f16&&!q4&&!q5&&!automatic){q8=true;continue;}
        if(arg=="--q4-0"&&!q4&&!f16&&!q8&&!q5&&!automatic){q4=true;continue;}
        if(arg=="--q5-0"&&!q5&&!f16&&!q8&&!q4&&!automatic){q5=true;continue;}
        if(arg=="--auto"&&!automatic&&!f16&&!q8&&!q4&&!q5){automatic=true;continue;}
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
    const auto result = RawrXD::REAP::PublishRepackedGGUF(argv[1], argv[2], budget, f16, q8, q4, q5, automatic);
    if (result.error != RawrXD::REAP::PublishError::None) {
        std::cerr << "REAP_REPACK_RESULT=FAIL error="
                  << static_cast<int>(result.error) << " repack_error=" << static_cast<int>(result.repack_error) << "\n";
        return 1;
    }
    std::cout << "REAP_REPACK_RESULT=PASS output=" << argv[2] << "\n";
    return 0;
}
