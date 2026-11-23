// Native GGUF parser regression: compile with src/GGUFLoader.cpp (C++17).
#include "../src/GGUFLoader.hpp"
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

static void U32(std::ofstream& o, uint32_t x) { o.write(reinterpret_cast<const char*>(&x),4); }
static void U64(std::ofstream& o, uint64_t x) { o.write(reinterpret_cast<const char*>(&x),8); }
static void Str(std::ofstream& o, const std::string& s) {
    U64(o,s.size()); o.write(s.data(),static_cast<std::streamsize>(s.size()));
}
static bool Fixture(const char* path, uint32_t alignment, bool truncate,
                    bool badType, bool badOffset) {
    std::ofstream o(path,std::ios::binary|std::ios::trunc);
    if (!o) return false;
    U32(o,0x46554747); U32(o,3); U64(o,1); U64(o,3);
    Str(o,"general.alignment"); U32(o,4); U32(o,alignment);
    Str(o,"general.test_u64"); U32(o,10); U64(o,0x1122334455667788ULL);
    Str(o,"general.test_array"); U32(o,badType?99:9);
    U32(o,4); U64(o,2); U32(o,7); U32(o,9);
    Str(o,"test.weight"); U32(o,1); U64(o,4); U32(o,0);
    U64(o,badOffset?999:0);
    if (!truncate) {
        const auto pos=static_cast<uint64_t>(o.tellp());
        const uint64_t aligned=(pos+alignment-1)&~(uint64_t(alignment)-1);
        for(uint64_t i=pos;i<aligned;++i)o.put('\0');
        for(int i=0;i<16;++i)o.put(static_cast<char>(i));
    }
    return static_cast<bool>(o);
}
int main() {
    const char* file="rawrxd_gguf_parser_test.gguf";
    int failures=0;
    auto check=[&](bool ok,const char* name) {
        std::cout<<(ok?"PASS ":"FAIL ")<<name<<"\n";
        if(!ok)++failures;
    };
    for(uint32_t alignment:{32U,64U,256U}) {
        EngineContext ctx;
        check(Fixture(file,alignment,false,false,false) &&
              LoadUniversalBlob(file,&ctx) &&
              ctx.cfg.ggufAlignment==alignment &&
              ctx.tensors.size()==1 &&
              ctx.tensorWeightsPool.size()==16 &&
              ctx.tensorWeightsPool[15]==15,
              "typed_u64_array_and_alignment");
    }
    EngineContext ctx;
    check(Fixture(file,32,true,false,false) && !LoadUniversalBlob(file,&ctx),
          "truncated_tensor_data_rejected");
    check(Fixture(file,32,false,true,false) && !LoadUniversalBlob(file,&ctx),
          "invalid_metadata_type_rejected");
    check(Fixture(file,32,false,false,true) && !LoadUniversalBlob(file,&ctx),
          "invalid_tensor_offset_rejected");
    check(Fixture(file,32,false,false,false) && LoadUniversalBlob(file,&ctx) &&
          ctx.tensors.size()==1,"recovery_after_failure");
    std::remove(file);
    std::cout<<"GGUF_PARSER_RESULT="<<(failures?"FAIL":"PASS")
             <<" failures="<<failures<<"\n";
    return failures?1:0;
}
