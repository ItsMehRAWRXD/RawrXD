// Standalone: c++ -std=c++17 -O2 -DNDEBUG -Isrc/deep2 tools/streaming_encoder_test.cpp -lz -o streaming_encoder_test
#include "StreamingTensorEncoder.hpp"
#include "StreamingTensorFile.hpp"
#include "StreamingBlockCache.hpp"
#include <algorithm>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
static void require(bool yes, const char* why) {
    if (!yes) throw std::runtime_error(why);
}
int main() {
    using namespace rawrxd::weights;
    const char* source="streaming_encoder_test.raw";
    const char* dest="streaming_encoder_test.rwt1";
    try {
        std::vector<uint8_t> original(1u<<20);
        for (size_t i=0;i<original.size();++i)
            original[i]=static_cast<uint8_t>((i*131u+(i>>9)*17u)&255u);
        {
            std::ofstream out(source,std::ios::binary|std::ios::trunc);
            require(bool(out.write(reinterpret_cast<const char*>(original.data()),
                                   original.size())),"source write failed");
        }
        const auto stats=encode_file_region(source,13,original.size()-37,dest,4,4096);
        require(stats.plain_bytes==original.size()-37,"plain bytes mismatch");
        require(stats.blocks==256,"block count mismatch");
        require(stats.raw_blocks+stats.zlib_blocks+stats.shuffle_blocks+
                stats.delta_shuffle_blocks==stats.blocks,"codec counts mismatch");
        StreamingTensorFile file(dest);
        require(file.plain_size()==stats.plain_bytes,"RWT1 size mismatch");
        StreamingBlockCache cache(file,8192);
        const auto decoded=cache.read(0,static_cast<size_t>(stats.plain_bytes));
        require(std::equal(decoded.begin(),decoded.end(),original.begin()+13),
                "streamed bytes differ from source");
        require(cache.peak_resident_bytes()<=8192,"cache exceeded budget");
        require(cache.evictions()>0,"expected LRU evictions");
        bool bounds_rejected=false;
        try { (void)encode_file_region(source,original.size()-2,4,dest,4,4096); }
        catch (const std::out_of_range&) { bounds_rejected=true; }
        require(bounds_rejected,"invalid input bounds accepted");
        std::remove(source);std::remove(dest);
        std::cout<<"STREAMING_ENCODER=PASS ROUNDTRIP=PASS LRU=PASS BOUNDS=PASS\n";
        return 0;
    } catch(const std::exception& e) {
        std::remove(source);std::remove(dest);
        std::cerr<<"STREAMING_ENCODER=FAIL "<<e.what()<<"\n";
        return 1;
    }
}
