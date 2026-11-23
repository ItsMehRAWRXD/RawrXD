#include "../src/reap/NativeGGUFPublisher.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main() {
    namespace fs=std::filesystem;
    const fs::path src="reap_publish_source.gguf";
    const fs::path dst="reap_publish_dest.gguf";
    std::error_code ec;
    fs::remove(src,ec);fs::remove(dst,ec);
    int failures=0;
    auto check=[&](bool ok,const char* name) {
        std::cout<<(ok?"PASS ":"FAIL ")<<name<<"\n";
        if(!ok)++failures;
    };
    {
        std::ofstream out(src,std::ios::binary);
        WriteU32(out,0x46554747);WriteU32(out,3);
        WriteU64(out,1);WriteU64(out,1);
        WriteName(out,"general.alignment");WriteU32(out,4);WriteU32(out,32);
        WriteName(out,"test.weight");WriteU32(out,1);WriteU64(out,4);
        WriteU32(out,0);WriteU64(out,0);
        PadTo(out,32);
        for(int i=0;i<16;++i)out.put(static_cast<char>(i));
    }
    const auto first=PublishRepackedGGUF(src.string(),dst.string(),1024);
    check(first.error==PublishError::None&&first.published_bytes>16,
          "publish_new_artifact");
    const auto before=fs::file_size(dst,ec);
    const auto repeat=PublishRepackedGGUF(src.string(),dst.string(),1024);
    check(repeat.error==PublishError::DestinationExists &&
          fs::file_size(dst,ec)==before,"existing_artifact_never_replaced");
    fs::remove(dst,ec);
    const auto denied=PublishRepackedGGUF(src.string(),dst.string(),16);
    check(denied.error==PublishError::RepackFailed &&
          denied.repack_error==RepackError::Overflow &&
          !fs::exists(dst),"budget_failure_does_not_publish");
    unsigned leftovers=0;
    for(const auto& entry:fs::directory_iterator(fs::current_path())) {
        if(entry.path().filename().string().find("reap_publish_dest.gguf.reap-part-")==0)
            ++leftovers;
    }
    check(leftovers==0,"staging_files_cleaned");
    fs::remove(src,ec);fs::remove(dst,ec);
    std::cout<<"REAP_PUBLISH_RESULT="<<(failures?"FAIL":"PASS")
             <<" failures="<<failures<<"\n";
    return failures?1:0;
}
