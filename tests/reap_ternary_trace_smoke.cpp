#include "../src/deep2/reap/ReapTernaryReference.hpp"
#include "../src/deep2/reap/ReapStreamTrace.hpp"
#include <cassert>
#include <vector>
#include <iostream>
int main() {
    using namespace Deep2::ReapRom;
    for(size_t n=0;n<100;++n) {
        std::vector<int8_t> v;
        for(size_t i=0;i<n;++i) v.push_back(static_cast<int8_t>(i%3)-1);
        assert(UnpackTernary4(PackTernary4(v),n)==v);
    }
    bool rejected=false;
    try { (void)UnpackTernary4({255},4); }
    catch(const std::invalid_argument&) { rejected=true; }
    assert(rejected);
    StreamTrace t; t.Token(); t.Storage(4); t.Upload(4); t.Hit();
    assert(t.tokens==1 && t.storageBytes==4 && t.residentHits==1);
    std::cout<<"REAP_TERNARY_TRACE_SMOKE_PASS\n";
}
