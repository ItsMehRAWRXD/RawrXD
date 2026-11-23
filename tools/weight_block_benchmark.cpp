// Measure actual weight bytes; no synthetic compression claims.
// Build: c++ -std=c++17 -O2 -I. tools/weight_block_benchmark.cpp -lz -o weight_bench
// Usage: weight_bench path/to/tensor.bin [element_bytes=2] [block_bytes=65536]
// Input is raw tensor bytes extracted from GGUF, not a whole GGUF container.
#include "src/deep2/TensorAwareLossless.hpp"
#include "src/deep2/TensorWeightStorage.hpp"
#include "src/deep2/DecodedBlockCache.hpp"
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>
using namespace rawrxd::weights;
int main(int argc,char** argv) {
    try {
        if(argc<2 || argc>4) {
            std::cerr<<"usage: weight_bench tensor.bin [element_bytes] [block_bytes]\n";
            return 2;
        }
        const unsigned long stride=argc>2?std::stoul(argv[2]):2;
        const unsigned long block=argc>3?std::stoul(argv[3]):65536;
        if(stride>255 || block>UINT32_MAX || block==0)
            throw std::invalid_argument("invalid dimensions");
        std::ifstream in(argv[1],std::ios::binary);
        if(!in) throw std::runtime_error("cannot open tensor");
        std::vector<uint8_t> source((std::istreambuf_iterator<char>(in)),
                                     std::istreambuf_iterator<char>());
        const auto start=std::chrono::steady_clock::now();
        const auto t=encode(source.data(),source.size(),static_cast<uint8_t>(stride),
                            static_cast<uint32_t>(block));
        const auto after_encode=std::chrono::steady_clock::now();
        const auto wire=serialize(t);
        const auto restored=deserialize(wire);
        DecodedBlockCache cache(restored,static_cast<size_t>(block)*2);
        std::vector<uint8_t> roundtrip;
        roundtrip.reserve(source.size());
        for(size_t offset=0;offset<source.size();) {
            const size_t n=std::min<size_t>(block,source.size()-offset);
            auto part=cache.read(offset,n);
            roundtrip.insert(roundtrip.end(),part.begin(),part.end());
            offset+=n;
        }
        const auto after_decode=std::chrono::steady_clock::now();
        if(roundtrip!=source) throw std::runtime_error("byte-exact verification FAILED");
        size_t raw=0,zlib=0,shuffle=0,delta_shuffle=0;
        for(const auto& b:t.blocks) {
            if(b.codec==BlockCodec::Raw) ++raw;
            else if(b.codec==BlockCodec::Zlib) ++zlib;
            else if(b.codec==BlockCodec::ByteShuffleZlib) ++shuffle;
            else ++delta_shuffle;
        }
        const auto enc_ms=std::chrono::duration<double,std::milli>(after_encode-start).count();
        const auto dec_ms=std::chrono::duration<double,std::milli>(after_decode-after_encode).count();
        const double ratio=source.empty()?1.0:double(wire.size())/double(source.size());
        std::cout<<"input_bytes="<<source.size()<<" serialized_bytes="<<wire.size()
                 <<" ratio="<<ratio<<" reduction_pct="<<(1.0-ratio)*100.0
                 <<" raw_blocks="<<raw<<" zlib_blocks="<<zlib
                 <<" shuffled_blocks="<<shuffle<<" delta_shuffled_blocks="<<delta_shuffle<<" encode_ms="<<enc_ms
                 <<" deserialize_and_decode_ms="<<dec_ms
                 <<" decoded_cache_peak_limit="<<static_cast<size_t>(block)*2
                 <<" exact_roundtrip=PASS\n";
        return 0;
    } catch(const std::exception& e) {
        std::cerr<<"benchmark error: "<<e.what()<<"\n";
        return 1;
    }
}
