#include "../src/reap/NativeBlobStore.hpp"
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>

int main(int argc,char** argv) {
    if(argc==4 && std::string(argv[1])=="--verify") {
        std::string verified;
        const auto status=RawrXD::REAP::VerifyGGUFBlob(argv[2],argv[3],verified);
        if(status!=RawrXD::REAP::BlobVerifyError::None) {
            std::cerr<<"REAP_BLOB_VERIFY=FAIL error="<<static_cast<int>(status)<<"\n";
            return 1;
        }
        std::cout<<"REAP_BLOB_VERIFY=PASS path="<<verified<<"\n";
        return 0;
    }
    if(argc<3||argc>6) {
        std::cerr<<"Usage: rawrxd-reap-blob INPUT.gguf MODEL_ROOT"
                    " [--f16] [--max-bytes POSITIVE_INTEGER]\n"
                    "       rawrxd-reap-blob --verify MODEL_ROOT SHA256_HEX\n";
        return 2;
    }
    uint64_t budget=UINT64_MAX;
    bool f16=false,budgetSeen=false;
    for(int i=3;i<argc;++i) {
        const std::string arg=argv[i];
        if(arg=="--f16"&&!f16){f16=true;continue;}
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
    const auto result=RawrXD::REAP::StoreRepackedGGUFBlob(argv[1],argv[2],budget,f16);
    if(result.error!=RawrXD::REAP::BlobError::None) {
        std::cerr<<"REAP_BLOB_RESULT=FAIL error="<<static_cast<int>(result.error)
                 <<" repack_error="<<static_cast<int>(result.repack_error)<<"\n";
        return 1;
    }
    std::cout<<"REAP_BLOB_RESULT=PASS digest=sha256:"<<result.digest
             <<" bytes="<<result.bytes
             <<" existing="<<(result.already_present?1:0)
             <<" path="<<result.blob_path<<"\n";
    return 0;
}
