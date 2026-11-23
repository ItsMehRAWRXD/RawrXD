#include "../../src/quant_kernels.hpp"
#include "../../src/deep2/NativeKQuant.hpp"
#include "../../src/deep2/NativeTensorByteResidencyCache.hpp"
#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>

static void put16(uint8_t* p,uint16_t v){p[0]=uint8_t(v);p[1]=uint8_t(v>>8);}

static void testKBlockRange(uint32_t type) {
    const size_t blockBytes=RawrXD::NativeKQuant::BlockBytes(type);
    assert(blockBytes!=0);
    assert(deep2::tensorStorageBytes(256,static_cast<deep2::TensorType>(type))==blockBytes);
    std::vector<uint8_t> encoded(blockBytes*2);
    double source[256],decoded[256];
    for(int b=0;b<2;++b) {
        for(int i=0;i<256;++i)
            source[i]=double((i*17+b*11)%41-20)*0.03125;
        assert(RawrXD::NativeKQuant::EncodeBlock(type,source,100.0f,
                                                 encoded.data()+size_t(b)*blockBytes));
        assert(RawrXD::NativeKQuant::DecodeBlock(type,encoded.data()+size_t(b)*blockBytes,
                                                  decoded));
        for(int i=0;i<256;++i) assert(std::isfinite(decoded[i]));
    }
    float tile[333]{};
    assert(deep2::dequantizeTensorRange(static_cast<deep2::TensorType>(type),
        512,77,333,encoded.data(),encoded.size(),tile));
    for(size_t i=0;i<333;++i) {
        const size_t global=77+i;
        const size_t block=global/256;
        const size_t lane=global%256;
        double reference[256];
        assert(RawrXD::NativeKQuant::DecodeBlock(type,
            encoded.data()+block*blockBytes,reference));
        assert(tile[i]==static_cast<float>(reference[lane]));
    }
}

static void testFixedBlockRange(uint32_t type) {
    const auto tt=static_cast<deep2::TensorType>(type);
    const size_t blockBytes=static_cast<size_t>(deep2::tensorStorageBytes(32,tt));
    std::vector<uint8_t> encoded(blockBytes*2,0);
    for(int b=0;b<2;++b) {
        uint8_t* p=encoded.data()+size_t(b)*blockBytes;
        if(type==2) { put16(p,0x3c00); for(int i=0;i<16;++i)p[2+i]=0x98; }
        else if(type==3) { put16(p,0x3c00);put16(p+2,0x3800);for(int i=0;i<16;++i)p[4+i]=0x98; }
        else if(type==6) { put16(p,0x3c00);const uint8_t h[4]={0xA5,0x3C,0xF0,0x0F};for(int i=0;i<4;++i)p[2+i]=h[i];for(int i=0;i<16;++i)p[6+i]=0x98; }
        else if(type==7) { put16(p,0x3c00);put16(p+2,0x3800);const uint8_t h[4]={0xA5,0x3C,0xF0,0x0F};for(int i=0;i<4;++i)p[4+i]=h[i];for(int i=0;i<16;++i)p[8+i]=0x98; }
        else if(type==8) { put16(p,0x3c00);for(int i=0;i<32;++i)p[2+i]=uint8_t(int8_t(i-16)); }
        else if(type==9) { put16(p,0x3c00);put16(p+2,0);for(int i=0;i<32;++i)p[4+i]=uint8_t(int8_t(i-16)); }
    }
    float tile[30]{};
    assert(deep2::dequantizeTensorRange(tt,64,13,30,encoded.data(),encoded.size(),tile));
    for(size_t i=0;i<30;++i) {
        const int lane=int((13+i)%32);
        float expected=0.0f;
        if(type==2) expected=(lane<16?0.0f:1.0f);
        if(type==3) expected=(lane<16?8.5f:9.5f);
        if(type==6||type==7) {
            const uint8_t h[4]={0xA5,0x3C,0xF0,0x0F};
            const int high=(h[lane>>3]>>(lane&7))&1;
            const int q=(lane<16?8:9)+(high<<4);
            expected=type==6?float(q-16):float(q)+0.5f;
        }
        if(type==8||type==9) expected=float(lane-16);
        assert(std::fabs(tile[i]-expected)<1e-6f);
    }
}

static void testLosslessByteResidency() {
    Deep2::TensorByteResidencyCache cache(4096);
    std::vector<uint8_t> sparse(512, 0);
    for (size_t i = 0; i < sparse.size(); i += 64) sparse[i] = uint8_t(i / 64 + 1);
    auto reader = [&](size_t offset, size_t count, uint8_t* out) {
        if (offset > sparse.size() || count > sparse.size() - offset) return false;
        std::memcpy(out, sparse.data() + offset, count);
        return true;
    };
    assert(cache.RegisterFromReader("sparse", sparse.size(), reader, 128));
    auto stats = cache.GetStats();
    assert(stats.tensorCount == 1 && stats.compressedBytes < stats.logicalBytes);
    uint8_t actual[190]{};
    std::vector<uint8_t> scratch;
    assert(cache.ReadRange("sparse", 117, sizeof(actual), actual, scratch));
    assert(std::memcmp(actual, sparse.data() + 117, sizeof(actual)) == 0);
    assert(cache.GetStats().hits == 1);

    std::vector<uint8_t> dense(256);
    for (size_t i = 0; i < dense.size(); ++i) dense[i] = uint8_t(i);
    auto denseReader = [&](size_t offset, size_t count, uint8_t* out) {
        std::memcpy(out, dense.data() + offset, count);
        return true;
    };
    assert(!cache.RegisterFromReader("dense", dense.size(), denseReader, 128));
    cache.MarkRawFallback("dense");
    assert(cache.IsRawFallback("dense"));
}

int main() {
    testLosslessByteResidency();
    for(uint32_t type=10;type<=15;++type) testKBlockRange(type);
    for(uint32_t type:{2u,3u,6u,7u,8u,9u}) testFixedBlockRange(type);
    std::cout<<"canonical GGML fixed/K quantized range dequantization PASS\n";
}
