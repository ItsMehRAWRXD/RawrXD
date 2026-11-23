#include "../src/reap/NativeSHA256.hpp"
#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>
using namespace RawrXD::REAP;
int main(){
    int failures=0;
    auto check=[&](bool ok,const char* label){
        std::cout<<(ok?"PASS ":"FAIL ")<<label<<"\n";
        if(!ok)++failures;
    };
    SHA256 empty;
    check(empty.Finish()=="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "sha256_empty");
    SHA256 abc;
    const std::string value="abc";
    check(abc.Update(reinterpret_cast<const uint8_t*>(value.data()),value.size()) &&
          abc.Finish()=="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
          "sha256_abc");
    SHA256 chunked;
    const std::string many(1000000,'a');
    for(size_t i=0;i<many.size();i+=777){
        const size_t count=std::min<size_t>(777,many.size()-i);
        if(!chunked.Update(reinterpret_cast<const uint8_t*>(many.data()+i),count))
            ++failures;
    }
    check(chunked.Finish()=="cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
          "sha256_million_a_chunked");
    const char* path="reap_sha256_fixture.bin";
    {
        std::ofstream out(path,std::ios::binary|std::ios::trunc);
        out.write(many.data(),static_cast<std::streamsize>(many.size()));
    }
    std::string fileHash;
    check(HashFileSHA256(path,fileHash)&&
          fileHash=="cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
          "sha256_streaming_file");
    std::remove(path);
    std::cout<<"REAP_SHA256_RESULT="<<(failures?"FAIL":"PASS")
             <<" failures="<<failures<<"\n";
    return failures?1:0;
}
