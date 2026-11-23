#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>
using namespace RawrXD::REAP;
int main() {
    int failures=0;
    auto check=[&](bool ok,const char* name){
        std::cout<<(ok?"PASS ":"FAIL ")<<name<<"\n";
        if(!ok)++failures;
    };
    const std::string source="reap_f16_input.gguf",output="reap_f16_output.gguf";
    {
        std::ofstream out(source,std::ios::binary|std::ios::trunc);
        WriteU32(out,0x46554747);WriteU32(out,3);
        WriteU64(out,2);WriteU64(out,0);
        WriteName(out,"float.weight");WriteU32(out,1);WriteU64(out,8);
        WriteU32(out,0);WriteU64(out,0);
        WriteName(out,"half.weight");WriteU32(out,1);WriteU64(out,2);
        WriteU32(out,1);WriteU64(out,32);
        PadTo(out,32);
        for(uint32_t bits:{0x3f800000u,0xbf800000u,0x7f800000u,0x80000000u,
                           0x33800000u,0x3f801000u,0x3f803000u,0x477fe000u})
            WriteU32(out,bits);
        WriteU32(out,0x00003c00u);
    }
    const std::string tooSmall="reap_f16_budget_rejected.gguf";
    check(RepackGGUF(source,tooSmall,64,true)==RepackError::Overflow,
          "f16_budget_rejected_before_write");
    {std::ifstream absent(tooSmall,std::ios::binary);
     check(!absent.good(),"f16_budget_no_artifact");}
    const auto status=RepackGGUF(source,output,UINT64_MAX,true);
    check(status==RepackError::None,"convert_gguf_success");
    if(status==RepackError::None) {
        std::ifstream in(output,std::ios::binary);
        uint32_t magic=0,version=0,type=0,nd=0;
        uint64_t count=0,kv=0,dim=0,offset=0;
        std::string name;
        ReadU32(in,magic);ReadU32(in,version);ReadU64(in,count);ReadU64(in,kv);
        ReadName(in,name);ReadU32(in,nd);ReadU64(in,dim);
        ReadU32(in,type);ReadU64(in,offset);
        check(magic==0x46554747&&version==3&&count==2&&kv==0&&
              name=="float.weight"&&nd==1&&dim==8&&type==1&&offset==0,
              "f32_directory_rewritten_to_f16");
        ReadName(in,name);ReadU32(in,nd);ReadU64(in,dim);
        ReadU32(in,type);ReadU64(in,offset);
        check(name=="half.weight"&&type==1&&offset==32,
              "preexisting_f16_type_preserved");
        const auto directoryEnd=in.tellg();
        const uint64_t dataStart=(static_cast<uint64_t>(directoryEnd)+31)&~uint64_t(31);
        in.seekg(static_cast<std::streamoff>(dataStart));
        const uint16_t expected[]={0x3c00,0xbc00,0x7c00,0x8000,
                                   0x0001,0x3c00,0x3c02,0x7bff};
        bool correct=true;
        for(uint16_t expectedHalf:expected) {
            unsigned char bytes[2]={};
            in.read(reinterpret_cast<char*>(bytes),2);
            correct &= static_cast<uint16_t>(bytes[0]|(uint16_t(bytes[1])<<8))==expectedHalf;
        }
        check(correct,"converted_f16_payload_exact");
        in.seekg(static_cast<std::streamoff>(dataStart+32));
        uint32_t original=0;
        ReadU32(in,original);
        check(original==0x00003c00u,"original_f16_tensor_unchanged");
    }
    std::remove(source.c_str());std::remove(output.c_str());
    std::remove(tooSmall.c_str());
    std::cout<<"REAP_F16_GGUF_RESULT="<<(failures?"FAIL":"PASS")
             <<" failures="<<failures<<"\n";
    return failures?1:0;
}
