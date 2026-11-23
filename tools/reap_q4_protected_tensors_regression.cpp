#include "../src/reap/NativeGGUFRepacker.hpp"
#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>
using namespace RawrXD::REAP;
static bool Check(const std::string& name,bool expected) {
    return IsQualitySensitiveTensor(name)==expected;
}
int main() {
    int failures=0;
    const struct {const char* name;bool protect;} cases[]={
        {"blk.0.attn_norm.weight",true},
        {"blk.0.ffn_norm.weight",true},
        {"token_embd.weight",true},
        {"output.weight",true},
        {"lm_head.weight",true},
        {"blk.0.attn_q.bias",true},
        {"rope_freqs.weight",true},
        {"blk.0.attn_q.weight",false},
        {"blk.0.attn_k.weight",false},
        {"blk.0.attn_v.weight",false},
        {"blk.0.ffn_down.weight",false},
        {"blk.0.ffn_gate.weight",false}
    };
    for(const auto& test:cases)
        if(!Check(test.name,test.protect)) {
            std::cerr<<"FAIL policy "<<test.name<<"\n";++failures;
        }
    std::cout<<"REAP_Q4_PROTECTED_TENSORS="<<(failures?"FAIL":"PASS")
             <<" failures="<<failures<<"\n";
    return failures?1:0;
}
