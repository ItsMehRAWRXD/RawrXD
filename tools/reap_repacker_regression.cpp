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
    a.close(); b.close(); intact.close();
    // A GGUF directory may enumerate tensors in a different order from
    // their physical locations. The repacker must preserve both payloads.
    {
        std::ofstream out(source,std::ios::binary|std::ios::trunc);
        WriteU32(out,0x46554747);WriteU32(out,3);
        WriteU64(out,2);WriteU64(out,1);
        WriteName(out,"general.alignment");WriteU32(out,4);WriteU32(out,32);
        WriteName(out,"second.weight");WriteU32(out,1);WriteU64(out,4);
        WriteU32(out,0);WriteU64(out,32);
        WriteName(out,"first.weight");WriteU32(out,1);WriteU64(out,4);
        WriteU32(out,0);WriteU64(out,0);
        PadTo(out,32);
        for(int i=0;i<16;++i)out.put(static_cast<char>(0x11));
        for(int i=0;i<16;++i)out.put('\\0');
        for(int i=0;i<16;++i)out.put(static_cast<char>(0x22));
    }
    check(RepackGGUF(source,dest,1024)==RepackError::None,
          "out_of_order_tensor_directory_repacked");
    {
        std::ifstream in(dest,std::ios::binary);
        uint32_t v=0;uint64_t n=0;
        ReadU32(in,v);ReadU32(in,v);ReadU64(in,n);ReadU64(in,n);
        std::string key;ReadName(in,key);ReadU32(in,v);ReadU32(in,v);
        std::string name;uint64_t offset=0;
        ReadName(in,name);ReadU32(in,v);ReadU64(in,n);ReadU32(in,v);ReadU64(in,offset);
        check(name=="second.weight" && offset==0,
              "first_directory_tensor_relocated_to_zero");
        ReadName(in,name);ReadU32(in,v);ReadU64(in,n);ReadU32(in,v);ReadU64(in,offset);
        check(name=="first.weight" && offset==32,
              "second_directory_tensor_relocated_to_32");
        const auto dirEnd=static_cast<uint64_t>(in.tellg());
        const auto dataStart=(dirEnd+31)&~uint64_t(31);
        in.seekg(static_cast<std::streamoff>(dataStart));
        char first=0;in.get(first);
        in.seekg(static_cast<std::streamoff>(dataStart+32));
        char second=0;in.get(second);
        check(first==static_cast<char>(0x22) && second==static_cast<char>(0x11),
              "out_of_order_tensor_payloads_preserved");
    }
    std::remove(source);std::remove(dest);
    std::cout<<"REAP_REPACK_RESULT="<<(fails?"FAIL":"PASS")
             <<" failures="<<fails<<"\n";
    return fails?1:0;
}
