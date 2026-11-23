#include "NativeTensorCompression.hpp"
#include "TensorResidencyCache.hpp"
#include <cstdio>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <memory>
#include <limits>
#include <stdexcept>
#include <utility>
#include <vector>

using RawrXD::TensorCompression::ChunkedF32Storage;

#define CHECK(condition) do { if (!(condition)) { \
    std::fprintf(stderr, "CHECK failed at line %d: %s\n", __LINE__, #condition); \
    return __LINE__; \
} } while (0)

int main() {
    // Exactly representable F32 values must compact to a uniform 16-bit stream.
    std::vector<float> values(8192);
    for (std::size_t i=0;i<values.size();++i)
        values[i]=static_cast<float>(static_cast<int>(i%127)-63) * 0.25f;
    auto compact=ChunkedF32Storage::Build(values.data(),values.size(),0.0f,1024);
    CHECK(compact.storedBytes()==values.size()*2);
    CHECK(compact.residentBytes()>=compact.storedBytes());
    CHECK(compact.residentBytes()<compact.originalBytes());
    RawrXD::TensorCompression::Encoding encoding{};
    std::vector<std::uint8_t> packed;
    CHECK(compact.ExportUniform16Bit(encoding,packed));
    CHECK(packed.size()==values.size()*2);
    const std::uint8_t* packedViewA=nullptr;
    const std::uint8_t* packedViewB=nullptr;
    std::size_t packedViewBytesA=0,packedViewBytesB=0;
    CHECK(compact.GetUniform16BitView(encoding,packedViewA,packedViewBytesA));
    CHECK(compact.GetUniform16BitView(encoding,packedViewB,packedViewBytesB));
    CHECK(packedViewA==packedViewB && packedViewBytesA==packedViewBytesB);
    CHECK(packedViewBytesA==packed.size());
    CHECK(std::memcmp(packedViewA,packed.data(),packed.size())==0);
    std::vector<float> decoded(values.size());
    CHECK(compact.DecodeRange(137,decoded.size()-274,decoded.data()));
    for (std::size_t i=0;i<decoded.size()-274;++i)
        CHECK(decoded[i]==values[i+137]);

    // Matching infinities and NaNs remain representable at zero error tolerance.
    const float specialValues[] = {
        std::numeric_limits<float>::infinity(),
        -std::numeric_limits<float>::infinity(),
        std::numeric_limits<float>::quiet_NaN()
    };
    auto special=ChunkedF32Storage::Build(specialValues,3,0.0f,3);
    float specialOut[3]{};
    CHECK(special.DecodeRange(0,3,specialOut));
    CHECK(std::isinf(specialOut[0]) && specialOut[0]>0.0f);
    CHECK(std::isinf(specialOut[1]) && specialOut[1]<0.0f);
    CHECK(std::isnan(specialOut[2]));

    // Reader-backed construction is bounded to chunk-sized source requests.
    std::size_t readerCalls=0,readerElements=0;
    auto streamed=ChunkedF32Storage::BuildFromReader(
        values.size(),0.0f,
        [&values,&readerCalls,&readerElements](std::size_t offset,std::size_t count,float* out) {
            ++readerCalls;
            readerElements+=count;
            std::memcpy(out,values.data()+offset,count*sizeof(float));
            return true;
        },256,false,values.size()*2);
    CHECK(readerCalls==values.size()/256);
    CHECK(readerElements==values.size());
    CHECK(streamed.storedBytes()==values.size()*2);
    bool budgetRejected=false;
    try {
        (void)ChunkedF32Storage::BuildFromReader(
            values.size(),0.0f,
            [&values](std::size_t offset,std::size_t count,float* out) {
                std::memcpy(out,values.data()+offset,count*sizeof(float));
                return true;
            },256,false,1);
    } catch (const std::length_error&) {
        budgetRejected=true;
    }
    CHECK(budgetRejected);

    // BF16 remains viable when IEEE F16 overflows large finite values.
    const float largeFinite[] = {1000000.0f};
    auto bf16=ChunkedF32Storage::Build(largeFinite,1,1024.0f,1);
    CHECK(bf16.chunks()[0].encoding==RawrXD::TensorCompression::Encoding::BF16);
    float bf16Out[1]{};
    CHECK(bf16.DecodeRange(0,1,bf16Out));
    CHECK(std::fabs(bf16Out[0]-largeFinite[0])<=1024.0f);

    // Lossless LZ4 byte chunks keep already-quantized GGUF blocks packed.
    std::vector<std::uint8_t> byteSource(256u*1024u);
    for (std::size_t i=0;i<byteSource.size();++i)
        byteSource[i]=static_cast<std::uint8_t>(i%97u);
    auto byteStore=RawrXD::TensorCompression::ChunkedByteStorage::BuildFromReader(
        byteSource.size(),
        [&byteSource](std::size_t offset,std::size_t count,std::uint8_t* out) {
            std::memcpy(out,byteSource.data()+offset,count);
            return true;
        },64u*1024u,false,byteSource.size());
    CHECK(byteStore.storedBytes()<byteStore.size());
    CHECK(byteStore.residentBytes()<byteStore.size());
    std::vector<std::uint8_t> byteOut(5000),byteScratch;
    byteStore.ReadRange(61337,byteOut.size(),byteOut.data(),byteScratch);
    CHECK(std::memcmp(byteOut.data(),byteSource.data()+61337,byteOut.size())==0);

    bool oversizedLz4ChunkRejected=false;
    try {
        (void)RawrXD::TensorCompression::ChunkedByteStorage::BuildFromReader(
            1,[](std::size_t,std::size_t,std::uint8_t* out) {
                out[0]=0; return true;
            },static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max())+1u);
    } catch (const std::invalid_argument&) {
        oversizedLz4ChunkRejected=true;
    }
    CHECK(oversizedLz4ChunkRejected);

    // Incompressible payloads fall back to raw bytes and remain lossless.
    std::vector<std::uint8_t> randomBytes(32768);
    std::uint32_t randomState=0x12345678u;
    for (auto& value:randomBytes) {
        randomState=randomState*1664525u+1013904223u;
        value=static_cast<std::uint8_t>(randomState>>24);
    }
    auto rawStore=RawrXD::TensorCompression::ChunkedByteStorage::BuildFromReader(
        randomBytes.size(),
        [&randomBytes](std::size_t offset,std::size_t count,std::uint8_t* out) {
            std::memcpy(out,randomBytes.data()+offset,count);
            return true;
        },8192,false,randomBytes.size());
    CHECK(rawStore.storedBytes()==rawStore.size());
    std::vector<std::uint8_t> rawOut(randomBytes.size()),rawScratch;
    rawStore.ReadRange(0,rawOut.size(),rawOut.data(),rawScratch);
    CHECK(std::memcmp(rawOut.data(),randomBytes.data(),randomBytes.size())==0);

    // Invalid ranges fail closed and do not touch caller memory.
    float untouched[2] = {7.0f,8.0f};
    CHECK(!compact.DecodeRange(compact.elements()-1,2,untouched));
    CHECK(untouched[0]==7.0f && untouched[1]==8.0f);

    // Reader mode can explicitly apply a relative-error tolerance.
    auto relative=ChunkedF32Storage::BuildFromReader(
        1,0.001f,
        [](std::size_t,std::size_t,float* out) { out[0]=1000000.0f; return true; },
        1,true,2);
    CHECK(relative.chunks()[0].encoding==RawrXD::TensorCompression::Encoding::BF16);

    // Lossless fallback must preserve values that are not representable in 16 bits.
    const float difficult[] = {1.0001234f, -3.1415927f, 1.0e-20f, 65520.0f};
    auto exact=ChunkedF32Storage::Build(difficult,4,0.0f,4);
    CHECK(exact.storedBytes()==sizeof(difficult));
    float exactOut[4]{};
    CHECK(exact.DecodeRange(0,4,exactOut));
    for (int i=0;i<4;++i) CHECK(exactOut[i]==difficult[i]);

    // Mixed chunks retain exact F32 only where the configured bound requires it.
    const float mixedValues[] = {1.0f, 1.5f, 1.0001234f, 2.345678f};
    auto mixed=ChunkedF32Storage::Build(mixedValues,4,0.0f,2);
    CHECK(mixed.chunkCount()==2);
    CHECK(mixed.chunks()[0].encoding!=RawrXD::TensorCompression::Encoding::F32);
    CHECK(mixed.chunks()[1].encoding==RawrXD::TensorCompression::Encoding::F32);
    RawrXD::TensorCompression::Encoding mixedEncoding{};
    std::vector<std::uint8_t> mixedPacked;
    CHECK(!mixed.ExportUniform16Bit(mixedEncoding,mixedPacked));
    float mixedOut[4]{};
    CHECK(mixed.DecodeRange(1,3,mixedOut));
    CHECK(mixedOut[0]==mixedValues[1]);
    CHECK(mixedOut[1]==mixedValues[2]);
    CHECK(mixedOut[2]==mixedValues[3]);

    // Bounded cache: active leases prevent eviction; releasing permits trimming.
    Deep2::TensorResidencyCache cache(compact.residentBytes());
    const std::size_t residentBytes=compact.residentBytes();
    auto payload=std::make_shared<const ChunkedF32Storage>(std::move(compact));
    CHECK(cache.Insert("layer0.weight",payload));
    payload.reset();
    auto lease=cache.Acquire("layer0.weight");
    CHECK(lease);
    CHECK(cache.Trim(0)==0);
    CHECK(cache.GetStats().pinnedEntries==1);
    auto secondPayload=std::make_shared<const ChunkedF32Storage>(std::move(exact));
    CHECK(!cache.Insert("layer1.weight",secondPayload));
    CHECK(cache.GetStats().entries==1);
    CHECK(static_cast<bool>(cache.Acquire("layer0.weight")));
    lease=Deep2::TensorResidencyCache::Lease{};
    CHECK(cache.Trim(0)==residentBytes);
    CHECK(cache.GetStats().residentBytes==0);
    return 0;
}
