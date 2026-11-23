#include "src/deep2/CompressedMatVecReference.hpp"
#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <vector>
using namespace rawrxd::weights;
int main() {
    constexpr size_t rows=17,cols=257;
    std::vector<float> w(rows*cols),x(cols);
    for(size_t i=0;i<w.size();++i) w[i]=float(int(i%97)-48)*0.0078125f;
    for(size_t i=0;i<x.size();++i) x[i]=float(int(i%31)-15)*0.03125f;
    std::vector<uint8_t> bytes(w.size()*sizeof(float));
    std::memcpy(bytes.data(),w.data(),bytes.size());
    auto t=encode(bytes.data(),bytes.size(),4,1024);
    auto y=compressed_matvec_f32(t,x,rows,cols,2048);
    for(size_t r=0;r<rows;++r) {
        double reference=0;
        for(size_t c=0;c<cols;++c) reference+=double(w[r*cols+c])*x[c];
        assert(std::abs(y[r]-reference)<1e-5);
    }
    bool rejected=false;
    try { (void)compressed_matvec_f32(t,x,rows,cols,100); }
    catch(const std::length_error&) { rejected=true; }
    assert(rejected);
    std::cout<<"PASS compressed FP32 CPU matvec numerical parity and cache budget\n";
}
