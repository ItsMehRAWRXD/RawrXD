#include "deep2/ReapTensorBounds.hpp"
#include <cstdio>
using namespace Deep2::ReapBounds;
int main(){
    int pass=0,fail=0;auto check=[&](bool ok,const char* name){std::printf("%s %s\n",ok?"PASS":"FAIL",name);ok?++pass:++fail;};
    uint64_t n=0;uint32_t layer=0;
    check(ByteSize({7168,2048,384},256,144,n)&&n==uint64_t(28)*144*2048*384,"Kimi Q4_K packed rows");
    check(ByteSize({2048,7168,384},256,210,n)&&n==uint64_t(8)*210*7168*384,"Kimi Q6_K packed rows");
    check(ByteSize({7168,384},1,4,n)&&n==7168ull*384*4,"F32 router rows");
    check(!ByteSize({255,2},256,144,n),"partial quantization row rejected");
    check(!ByteSize({0,2},256,144,n)&&!ByteSize({256,0},256,144,n),"zero dimensions rejected");
    check(!ByteSize({UINT64_MAX},1,4,n),"row overflow rejected");
    check(!ByteSize({256,UINT64_MAX},256,144,n),"outer dimension overflow rejected");
    check(!ByteSize({256},0,144,n)&&!ByteSize({256},256,0,n),"unknown block geometry rejected");
    check(SliceStride({256,2,8},256,144,2304,n)&&n==288,"whole expert slice");
    check(SliceStride({384},1,4,1536,n)&&n==4,"scalar expert bias stride");
    check(!SliceStride({256},256,144,144,n),"packed bias cannot be split into scalar experts");
    check(!SliceStride({256,8},256,144,1151,n),"incorrect source byte count rejected");
    check(LayerIndex("blk.59.ffn_gate_exps.weight",layer)&&layer==59,"valid layer index");
    check(!LayerIndex("blk.1junk.ffn_up_exps.weight",layer),"numeric prefix rejected");
    check(!LayerIndex("blk.-1.ffn_up_exps.weight",layer),"negative layer rejected");
    check(!LayerIndex("blk.4294967296.ffn_down_exps.weight",layer),"wrapped layer rejected");
    check(!LayerIndex("blk.4294967295.x",layer)&&!LayerIndex("blk..x",layer)&&!LayerIndex("blk.1.",layer),"invalid layer sentinels rejected");
    check(ValidRanges({{64,17},{0,33},{96,4}},100,32),"unordered nonoverlapping aligned ranges");
    check(!ValidRanges({{0,65},{64,1}},100,32),"overlapping ranges rejected");
    check(!ValidRanges({{0,4},{0,4}},100,32),"duplicate offsets rejected");
    check(!ValidRanges({{33,4}},100,32),"misaligned offset rejected");
    check(!ValidRanges({{96,5}},100,32),"past EOF rejected");
    check(!ValidRanges({{UINT64_MAX-31,64}},UINT64_MAX,32),"offset addition overflow rejected");
    check(!ValidRanges({{0,1}},100,3)&&!ValidRanges({{0,0}},100,32),"invalid alignment and empty payload rejected");
    std::printf("PASS_COUNT=%d FAIL_COUNT=%d\n",pass,fail);return fail?1:0;
}
