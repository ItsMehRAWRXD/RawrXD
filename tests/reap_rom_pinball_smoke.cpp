#include "../src/deep2/reap/ReapRomPinballBridge.hpp"
#include <cassert>
#include <iostream>
using namespace Deep2::ReapRom;
int main() {
    int reads=0, uploads=0, executions=0, fakeGpu=42;
    Bridge b(
        [&](const std::string& path, uint64_t offset, void* dst, size_t n) {
            assert(path=="test.gguf" && offset==128 && n==4);
            ++reads;
            auto* p=static_cast<uint8_t*>(dst);
            for(size_t i=0;i<n;++i) p[i]=static_cast<uint8_t>(i);
            return true;
        },
        [&](const Slice&, const std::vector<uint8_t>& bytes, Binding& binding) {
            assert(bytes.size()==4 && bytes[3]==3);
            ++uploads; binding={&fakeGpu,4,1}; return true;
        },
        [&](const Binding& binding, uint32_t layer, uint32_t expert) {
            assert(binding.deviceHandle==&fakeGpu && layer==2 && expert==7);
            ++executions; return true;
        });
    b.Register({"test.gguf",128,4,2,7,0});
    b.Retain(2,7);
    assert(!b.Run(2,8));
    assert(b.Run(2,7));
    assert(b.Run(2,7));
    assert(reads==1 && uploads==1 && executions==2);
    assert(b.Stats().diskBytes==4 && b.Stats().rejected==1);
    std::cout << "REAP_ROM_PINBALL_BRIDGE_SMOKE_PASS\n";
}
