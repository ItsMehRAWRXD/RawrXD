#include "deep2/ReapMlaGeometry.hpp"
#include <cstdio>
using namespace Deep2::Mla;
int main() {
    int pass=0, fail=0;
    auto check=[&](bool ok,const char* name){std::printf("%s %s\n",ok?"PASS":"FAIL",name);ok?++pass:++fail;};
    Geometry g;
    check(Build(128,192,128,61,16,3,5,g),"asymmetric MLA geometry");
    check(g.keyElements==24576 && g.valueElements==16384,"key and value float counts");
    check(g.keyCacheElements==uint64_t(61)*16*24576 && g.valueCacheElements==uint64_t(61)*16*16384,"cache storage geometry");
    check(g.keyOffset==53u*24576 && g.valueOffset==53u*16384,"layer-position offsets");
    check(g.p0==192 && g.p1==128 && g.p2==128 && g.p3==6 && g.p4==16 && g.p5==3,"shader push constant ABI");
    check(g.groups==256,"dispatch covers values not keys or positions");
    check(Build(1,3,65,2,8,1,7,g) && g.groups==2,"partial workgroup");
    check(g.keyOffset+g.keyElements==g.keyCacheElements && g.valueOffset+g.valueElements==g.valueCacheElements,"final position boundaries");
    check(Build(2,3,5,2,1,0,0,g) && g.p3==1 && g.groups==1,"first token geometry");
    check(!Build(0,3,5,2,8,0,0,g),"zero heads rejected");
    check(!Build(2,0,5,2,8,0,0,g),"zero key width rejected");
    check(!Build(2,3,0,2,8,0,0,g),"zero value width rejected");
    check(!Build(2,3,5,2,8,2,0,g),"invalid layer rejected");
    check(!Build(2,3,5,2,8,0,8,g),"invalid position rejected");
    check(!Build(2,3,5,2,0,0,0,g),"zero cache capacity rejected");
    check(!Build(UINT32_MAX,UINT32_MAX,1,1,1,0,0,g),"shader element overflow rejected");
    check(!Build(2,3,5,UINT32_MAX,UINT32_MAX,0,0,g),"cache product overflow rejected");
    check(!Build(1,1,4194241,1,1,0,0,g),"dispatch limit rejected");
    check(g.keyElements==0 && g.groups==0,"failure clears output");
    std::printf("PASS_COUNT=%d FAIL_COUNT=%d\n",pass,fail);return fail?1:0;
}
