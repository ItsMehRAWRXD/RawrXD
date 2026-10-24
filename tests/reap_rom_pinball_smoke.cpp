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
    bool replacementRejected=false;
    try { b.BindResident(2,7,Binding{&fakeGpu,4,2}); }
    catch(const std::logic_error&) { replacementRejected=true; }
    assert(replacementRejected);
    b.ForgetAfterGpuIdle(2,7); // Test harness has no asynchronous GPU work.
    b.BindResident(2,7,Binding{&fakeGpu,4,3});
    assert(b.Run(2,7));
    assert(reads==1 && uploads==1 && executions==3);
    bool budgetRejected=false;
    try {
        Bridge bounded(
            [](const std::string&, uint64_t, void*, size_t) { return true; },
            [](const Slice&, const std::vector<uint8_t>&, Binding&) { return true; },
            [](const Binding&, uint32_t, uint32_t) { return true; },
            4);
        bounded.Register({"oversized.gguf", 0, 5, 1, 1, 0});
    } catch(const std::invalid_argument&) { budgetRejected=true; }
    assert(budgetRejected);
    assert(reads==1 && uploads==1);
    b.ForgetAfterGpuIdle(2,7);
    bool undersizedRejected=false;
    try { b.BindResident(2,7,Binding{&fakeGpu,3,4}); }
    catch(const std::invalid_argument&) { undersizedRejected=true; }
    assert(undersizedRejected);
    b.BindResident(2,7,Binding{&fakeGpu,4,5});
    assert(b.Run(2,7));
    assert(reads==1 && uploads==1 && executions==4);
    int invalidGpu=0;
    Bridge badUpload(
        [](const std::string&, uint64_t, void* dst, size_t n) {
            for (size_t i=0; i<n; ++i) static_cast<uint8_t*>(dst)[i]=0;
            return true;
        },
        [&](const Slice&, const std::vector<uint8_t>&, Binding& out) {
            out={&invalidGpu, 1, 1};
            return true;
        },
        [](const Binding&, uint32_t, uint32_t) { return true; });
    badUpload.Register({"test.gguf",0,4,0,0,0});
    badUpload.Retain(0,0);
    bool badUploadRejected=false;
    try { (void)badUpload.Run(0,0); }
    catch(const std::runtime_error&) { badUploadRejected=true; }
    assert(badUploadRejected);
    Bridge partialUpload(
        [](const std::string&, uint64_t, void* dst, size_t n) {
            for(size_t i=0;i<n;++i) static_cast<uint8_t*>(dst)[i]=0;
            return true;
        },
        [&](const Slice&, const std::vector<uint8_t>&, Binding& out) {
            out={&fakeGpu,4,1};
            return false;
        },
        [](const Binding&, uint32_t, uint32_t) { return true; });
    partialUpload.Register({"test.gguf",0,4,0,0,0});
    partialUpload.Retain(0,0);
    bool partialRejected=false;
    try { (void)partialUpload.Run(0,0); }
    catch(const std::runtime_error&) { partialRejected=true; }
    assert(partialRejected);
    int staleReads=0;
    Bridge reused(
        [&](const std::string&, uint64_t, void* dst, size_t n) {
            ++staleReads;
            for(size_t i=0;i<n;++i) static_cast<uint8_t*>(dst)[i]=0;
            return true;
        },
        [&](const Slice&, const std::vector<uint8_t>&, Binding& out) {
            out={&fakeGpu,4,1}; return true;
        },
        [](const Binding&, uint32_t, uint32_t) { return true; });
    reused.Register({"test.gguf",0,4,1,1,0});
    reused.Retain(1,1);
    assert(reused.Run(1,1));
    assert(reused.Run(1,1));
    assert(staleReads==1);
    std::cout << "REAP_ROM_PINBALL_BRIDGE_SMOKE_PASS\n";
}
