// Standalone regression: c++ -std=c++17 -O2 -Isrc/deep2 tools/streaming_residency_test.cpp -lz -o streaming_residency_test
#include "TensorAwareLossless.hpp"
#include "TensorWeightStorage.hpp"
#include "StreamingTensorFile.hpp"
#include "StreamingBlockCache.hpp"
#include <cassert>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <vector>
int main() {
    using namespace rawrxd::weights;
    const char* path="streaming_residency_test.rwt1";
    try {
        std::vector<uint8_t> plain(8193);
        for (size_t i=0;i<plain.size();++i)
            plain[i]=static_cast<uint8_t>((i*37u+(i/128u)*19u)&255u);
        const auto tensor=encode(plain.data(),plain.size(),1,1024);
        const auto packed=serialize(tensor);
        {
            std::ofstream f(path,std::ios::binary|std::ios::trunc);
            if (!f.write(reinterpret_cast<const char*>(packed.data()),packed.size()))
                throw std::runtime_error("cannot write test RWT1");
        }
        {
            StreamingTensorFile file(path);
            assert(file.plain_size()==plain.size());
            assert(file.block_count()==9);
            StreamingBlockCache cache(file,2048);
            auto whole=cache.read(0,plain.size());
            assert(whole==plain);
            assert(cache.peak_resident_bytes()<=2048);
            assert(cache.evictions()>0);
            auto cross=cache.read(990,90);
            assert(std::equal(cross.begin(),cross.end(),plain.begin()+990));
            cache.get(0);
            const auto misses=cache.misses();
            cache.get(0);
            assert(cache.misses()==misses && cache.hits()>0);
            assert(cache.resident_bytes()<=2048);
            bool rejected=false;
            try { (void)cache.read(plain.size()-3,10); }
            catch (const std::out_of_range&) { rejected=true; }
            assert(rejected);
        }
        {
            auto bad=packed;
            bad.back()^=0x40;
            std::ofstream f(path,std::ios::binary|std::ios::trunc);
            f.write(reinterpret_cast<const char*>(bad.data()),bad.size());
            f.close();
            StreamingTensorFile file(path);
            bool rejected=false;
            try { (void)file.read_block(file.block_count()-1); }
            catch (const std::exception&) { rejected=true; }
            assert(rejected);
        }
        std::remove(path);
        std::cout<<"STREAMING_RWT1=PASS CACHE_EVICTION=PASS CRC_REJECTION=PASS\n";
        return 0;
    } catch (const std::exception& e) {
        std::remove(path);
        std::cerr<<"STREAMING_RWT1=FAIL "<<e.what()<<"\n";
        return 1;
    }
}
