#include "../../src/deep2/NativeKQuant.hpp"
#include <array>
#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <iostream>

using namespace RawrXD::NativeKQuant;
int main() {
    const uint32_t types[]={10,11,12,13,14};
    const size_t sizes[]={84,110,144,176,210};
    const double tolerances[]={2.0,2.0,1.0,0.8,0.15};
    for(int t=0;t<5;++t) {
        const auto type=types[t];
        assert(BlockBytes(type)==sizes[t]);
        std::array<uint8_t,210> buf{};
        double v[256]={},decoded[256]={};
        // Every zero block is exactly reproducible in all GGML K layouts.
        assert(EncodeBlock(type,v,0,buf.data()));
        assert(DecodeBlock(type,buf.data(),decoded));
        for(int k=0;k<256;++k)assert(decoded[k]==0);
        // Exercise all groups/lanes/bitplanes with signed nonuniform weights.
        for(int k=0;k<256;++k)
            v[k]=(double((k*37+5)%101)-50.0)*0.125 +
                 double(k/16)*0.01;
        assert(EncodeBlock(type,v,float(tolerances[t]),buf.data()));
        assert(DecodeBlock(type,buf.data(),decoded));
        double maxError=0;
        for(int k=0;k<256;++k){
            assert(std::isfinite(decoded[k]));
            maxError=std::max(maxError,std::abs(v[k]-decoded[k]));
        }
        assert(maxError<=tolerances[t]);
        // A strict tolerance must not silently narrow an unrepresentable F64.
        for(double& x:v)x=0;
        v[0]=1.0+std::ldexp(1.0,-40);
        assert(!EncodeBlock(type,v,0,buf.data()));
        std::cout<<"Q"<<(type-8)<<"_K native block PASS size="<<sizes[t]
                 <<" max_error="<<maxError<<"\n";
    }
    assert(BlockBytes(1)==0);
    std::cout<<"native GGML K-quant codec tests PASS\n";
}
