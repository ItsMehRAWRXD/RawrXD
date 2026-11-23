#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>
using namespace RawrXD::REAP;
int main() {
    int fails=0;
    auto check=[&](bool ok,const char* name) {
        std::cout<<(ok?"PASS ":"FAIL ")<<name<<"\n";
        if(!ok)++fails;
    };
    const char* source="reap_repack_source.gguf";
    const char* dest="reap_repack_dest.gguf";
    {
        std::ofstream out(source,std::ios::binary|std::ios::trunc);
        WriteU32(out,0x46554747);WriteU32(out,3);
        WriteU64(out,1);WriteU64(out,2);
        WriteName(out,"general.alignment");WriteU32(out,4);WriteU32(out,64);
        WriteName(out,"general.name");WriteU32(out,8);WriteName(out,"REAP fixture");
        WriteName(out,"test.weight");WriteU32(out,1);WriteU64(out,4);
        WriteU32(out,0);WriteU64(out,0);
        PadTo(out,64);
        for(unsigned i=0;i<16;++i)out.put(static_cast<char>(i+1));
    }
    check(RepackGGUF(source,dest,1024)==RepackError::None,
          "metadata_preserving_streaming_repack");
    {
        std::ifstream in(dest,std::ios::binary);
        uint32_t magic=0,version=0;
        uint64_t tensors=0,metadata=0;
        check(ReadU32(in,magic)&&ReadU32(in,version)&&
              ReadU64(in,tensors)&&ReadU64(in,metadata)&&
              magic==0x46554747&&version==3&&tensors==1&&metadata==2,
              "output_header_valid");
    }
    std::ifstream a(source,std::ios::binary),b(dest,std::ios::binary);
    const std::vector<char> before((std::istreambuf_iterator<char>(a)),
                                    std::istreambuf_iterator<char>());
    const std::vector<char> after((std::istreambuf_iterator<char>(b)),
                                   std::istreambuf_iterator<char>());
    check(before==after,"lossless_identity_fixture");
    check(RepackGGUF(source,dest,16)==RepackError::Overflow,
          "budget_rejected_before_output_open");
    std::ifstream intact(dest,std::ios::binary);
    const std::vector<char> retained((std::istreambuf_iterator<char>(intact)),
                                      std::istreambuf_iterator<char>());
    check(retained==after,"budget_rejection_preserves_output");
    check(RepackGGUF(source,source)==RepackError::Output,
          "in_place_overwrite_rejected");
    std::remove(source);std::remove(dest);
    std::cout<<"REAP_REPACK_RESULT="<<(fails?"FAIL":"PASS")
             <<" failures="<<fails<<"\n";
    return fails?1:0;
}
