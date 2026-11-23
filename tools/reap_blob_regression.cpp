#include "../src/reap/NativeBlobStore.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
using namespace RawrXD::REAP;
int main(){
    namespace fs=std::filesystem;
    const fs::path root="reap_blob_test_root",src="reap_blob_test_input.gguf";
    std::error_code ec;
    fs::remove_all(root,ec);fs::remove(src,ec);
    int failures=0;
    auto check=[&](bool ok,const char* name){
        std::cout<<(ok?"PASS ":"FAIL ")<<name<<"\n";
        if(!ok)++failures;
    };
    {
        std::ofstream out(src,std::ios::binary);
        WriteU32(out,0x46554747);WriteU32(out,3);
        WriteU64(out,1);WriteU64(out,0);
        WriteName(out,"tensor.weight");WriteU32(out,1);WriteU64(out,4);
        WriteU32(out,0);WriteU64(out,0);
        PadTo(out,32);
        for(int i=0;i<16;++i)out.put(static_cast<char>(i));
    }
    const auto first=StoreRepackedGGUFBlob(src.string(),root.string(),1024);
    check(first.error==BlobError::None&&!first.already_present &&
          first.digest.size()==64&&fs::exists(first.blob_path),
          "new_sha256_blob_published");
    const auto second=StoreRepackedGGUFBlob(src.string(),root.string(),1024);
    check(second.error==BlobError::None&&second.already_present &&
          second.digest==first.digest,"identical_blob_deduplicated");
    const auto tooSmall=StoreRepackedGGUFBlob(src.string(),root.string(),16);
    check(tooSmall.error==BlobError::RepackFailure &&
          tooSmall.repack_error==RepackError::Overflow,
          "blob_budget_rejection");
    unsigned temporaryDirectories=0;
    for(const auto& entry:fs::directory_iterator(root/"blobs")) {
        if(entry.path().filename().string().find(".reap-blob-")==0)
            ++temporaryDirectories;
    }
    check(temporaryDirectories==0,"blob_staging_cleanup");
    if(fs::exists(first.blob_path)){
        std::ofstream corrupt(first.blob_path,std::ios::binary|std::ios::trunc);
        corrupt<<"corrupt";
    }
    const auto conflict=StoreRepackedGGUFBlob(src.string(),root.string(),1024);
    check(conflict.error==BlobError::Conflict,"corrupt_existing_digest_rejected");
    fs::remove_all(root,ec);fs::remove(src,ec);
    std::cout<<"REAP_BLOB_RESULT="<<(failures?"FAIL":"PASS")
             <<" failures="<<failures<<"\n";
    return failures?1:0;
}
