#include "../../src/deep2/compression/StoredTensorMatvec.hpp"
#include <cmath>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

int main() {
    using namespace rawrxd::compression;
    constexpr std::size_t rows=2, cols=32, rowBytes=18;
    // GGML Q4_0: fp16 scale=1, then 16 packed bytes. Low nibble encodes
    // columns 0..15, high nibble columns 16..31; quant values are q-8.
    std::vector<std::uint8_t> packed(rows*rowBytes,0);
    for(std::size_t r=0;r<rows;++r) {
        packed[r*rowBytes]=0x00;
        packed[r*rowBytes+1]=0x3c;
        for(std::size_t i=0;i<16;++i) packed[r*rowBytes+2+i]=0x98;
    }

    CompressedWeightStore store(0,64);
    std::string error;
    if(!store.addTensor("q4",packed.data(),packed.size(),&error,2u,true)) return 1;
    if(store.tensorType("q4")!=2u || store.stats().compressed_bytes>=packed.size()) return 2;

    std::vector<float> input(cols,1.0f), output(rows,0.0f);
    StoredTensorMatvec(store,"q4",ResidentWeightType::Q4_0,
                       input.data(),output.data(),rows,cols,1);
    // 16 high nibbles are 9 => q=+1; 16 low nibbles are 8 => q=0.
    for(float value:output) if(std::fabs(value-16.0f)>1e-6f) return 3;

    // Different activation pattern verifies the two nibble lanes are mapped
    // to their correct halves rather than merely summing all quant values.
    for(std::size_t i=0;i<cols;++i) input[i]=float(i+1);
    StoredTensorMatvec(store,"q4",ResidentWeightType::Q4_0,
                       input.data(),output.data(),rows,cols,18);
    float expected=0.0f;
    for(std::size_t i=16;i<32;++i) expected+=float(i+1);
    for(float value:output) if(std::fabs(value-expected)>1e-5f) return 4;

    // Cross the store's compressed-block boundary and verify exact packed bytes.
    std::vector<std::uint8_t> restored(packed.size());
    if(!store.readRange("q4",0,restored.data(),restored.size(),&error) || restored!=packed) return 5;

    bool rejected=false;
    try { StoredTensorMatvec(store,"q4",ResidentWeightType::F16,
                             input.data(),output.data(),rows,cols); }
    catch(const std::invalid_argument&) { rejected=true; }
    if(!rejected) return 6;

    rejected=false;
    try { StoredTensorMatvec(store,"q4",ResidentWeightType::Q4_0,
                             input.data(),output.data(),rows,31); }
    catch(const std::invalid_argument&) { rejected=true; }
    if(!rejected) return 7;
    return 0;
}
