#include "../../src/deep2/NativeTensorCompression.hpp"
#include <cassert>
#include <cstring>
#include <vector>
#include <stdexcept>
#include <iostream>
#include <cmath>
#include <limits>
#include <algorithm>
using namespace RawrXD::TensorCompression;
int main() {
    const std::vector<uint8_t> repeated(4096,0x5a);
    auto r=Encode(repeated.data(),repeated.size());
    assert(r.encoding==Encoding::RLE && r.payload.size()<repeated.size());
    assert(Decode(r)==repeated);
    // LZ4-block compression captures repeated multi-byte patterns that
    // byte-run RLE cannot represent compactly.
    std::vector<uint8_t> patterned(64 * 1024);
    for(size_t i=0;i<patterned.size();++i)
        patterned[i]=static_cast<uint8_t>((i % 251) ^ ((i / 251) & 7));
    auto lz=Encode(patterned.data(),patterned.size());
    assert(lz.encoding==Encoding::LZ4);
    assert(lz.payload.size()<patterned.size());
    assert(Decode(lz)==patterned);
    std::vector<uint8_t> lzDirect(patterned.size(),0);
    DecodeInto(lz,lzDirect.data(),lzDirect.size());
    assert(lzDirect==patterned);

    // Validate malformed LZ4 streams before modifying the destination.
    Result malformedLz;
    malformedLz.encoding=Encoding::LZ4;
    malformedLz.original_bytes=8;
    malformedLz.payload={0x00,0x01,0x00}; // back-reference before any output
    std::vector<uint8_t> lzUntouched(8,0xA5);
    bool malformedLzRejected=false;
    try { DecodeInto(malformedLz,lzUntouched.data(),lzUntouched.size()); }
    catch(const std::invalid_argument&) { malformedLzRejected=true; }
    assert(malformedLzRejected);
    assert(std::all_of(lzUntouched.begin(),lzUntouched.end(),
                       [](uint8_t value){return value==0xA5;}));

    // Literal and match extension bytes must handle lengths beyond 15.
    Result extendedLz;
    extendedLz.encoding=Encoding::LZ4;
    extendedLz.original_bytes=40;
    extendedLz.payload.push_back(0xF0);
    extendedLz.payload.push_back(25);
    for(uint8_t value=0;value<40;++value) extendedLz.payload.push_back(value);
    std::vector<uint8_t> extendedDecoded(40);
    DecodeInto(extendedLz,extendedDecoded.data(),extendedDecoded.size());
    for(uint8_t i=0;i<40;++i) assert(extendedDecoded[i]==i);
    std::vector<uint8_t> direct(repeated.size(),0);
    DecodeInto(r,direct.data(),direct.size());
    assert(direct==repeated);
    const std::vector<uint8_t> randomish={0,1,2,3,4,5,6,7,8,9};
    auto raw=Encode(randomish.data(),randomish.size());
    DecodeInto(raw,direct.data(),randomish.size());
    assert(std::equal(randomish.begin(),randomish.end(),direct.begin()));
    assert(raw.encoding==Encoding::Raw && Decode(raw)==randomish);
    const float f[]={1.0f,-2.0f,0.5f,65504.0f};
    auto half=Encode(f,sizeof(f),true,0.0f);
    assert(half.encoding==Encoding::F16 && half.payload.size()==sizeof(f)/2);
    auto decoded=Decode(half);
    assert(std::memcmp(decoded.data(),f,sizeof(f))==0);
    uint8_t directHalf[sizeof(f)]{};
    DecodeInto(half,directHalf,sizeof(directHalf));
    assert(std::memcmp(directHalf,f,sizeof(f))==0);
    // BF16 keeps F32's exponent range when FP16 would overflow.
    const float wide[]={1.0e20f,-1.0e20f,3.25f,-0.0f};
    auto bf16=Encode(wide,sizeof(wide),true,1.0e18f,true);
    assert(bf16.encoding==Encoding::BF16 && bf16.payload.size()==sizeof(wide)/2);
    auto wideDecoded=Decode(bf16);
    uint8_t directBf16[sizeof(wide)]{};
    DecodeInto(bf16,directBf16,sizeof(directBf16));
    assert(std::memcmp(directBf16,wideDecoded.data(),sizeof(wide))==0);
    for(size_t i=0;i<4;++i) {
        float value; std::memcpy(&value,wideDecoded.data()+i*4,4);
        assert(std::isfinite(value));
        assert(std::fabs(value-wide[i])<=1.0e18f);
    }
    assert(ToBFloat16(1.0f)==0x3f80);
    assert(Bits(FromBFloat16(0x3f80))==Bits(1.0f));
    assert(ToBFloat16(-0.0f)==0x8000);
    assert(ToBFloat16(std::numeric_limits<float>::infinity())==0x7f80);
    assert((ToBFloat16(std::numeric_limits<float>::quiet_NaN())&0x7fc0)==0x7fc0);
    // Exhaustively round-trip every finite BF16 bit pattern through F32.
    for(uint32_t h=0;h<65536;++h) {
        if((h&0x7f80u)==0x7f80u) continue;
        assert(ToBFloat16(FromBFloat16(uint16_t(h)))==h);
    }
    const float exact_bf[]={1.0f,-2.0f,0.5f,4.0f};
    auto exactBf=Encode(exact_bf,sizeof(exact_bf),false,0.0f,true);
    assert(exactBf.encoding==Encoding::BF16 && Decode(exactBf).size()==sizeof(exact_bf));
    const float bfSpecial[]={std::numeric_limits<float>::quiet_NaN(),1.0f};
    assert(Encode(bfSpecial,sizeof(bfSpecial),false,1.0f,true).encoding!=Encoding::BF16);
    bool badTolerance=false;
    try { (void)Encode(exact_bf,sizeof(exact_bf),false,
                       std::numeric_limits<float>::quiet_NaN(),true); }
    catch(const std::invalid_argument&) { badTolerance=true; }
    assert(badTolerance);
    // Public adaptive API selects one representation for the entire tensor.
    const float adaptiveExact[]={1.0f,-2.0f,0.5f,4.0f};
    auto adaptive=EncodeAdaptiveF32(adaptiveExact,4,0.0f);
    assert(adaptive.encoding==Encoding::F16);
    assert(Decode(adaptive).size()==sizeof(adaptiveExact));
    auto uniformHalfStorage=ChunkedF32Storage::Build(adaptiveExact,4,0.0f,4);
    Encoding exportedEncoding=Encoding::Raw;
    std::vector<uint8_t> exportedHalf;
    assert(uniformHalfStorage.ExportUniform16Bit(exportedEncoding,exportedHalf));
    assert(exportedEncoding==Encoding::F16 && exportedHalf==adaptive.payload);
    const float multiChunkExact[]={1.0f,-2.0f,0.5f,4.0f,8.0f,-16.0f,0.25f,0.125f};
    auto multiChunkStorage=ChunkedF32Storage::Build(multiChunkExact,8,0.0f,4);
    assert(multiChunkStorage.ExportUniform16Bit(exportedEncoding,exportedHalf));
    assert(exportedEncoding==Encoding::F16 && exportedHalf.size()==sizeof(multiChunkExact)/2);
    const float adaptiveWide[]={1.0e20f,-1.0e20f,3.25f,4.0f};
    auto adaptiveBf=EncodeAdaptiveF32(adaptiveWide,4,1.0e18f);
    assert(adaptiveBf.encoding==Encoding::BF16);
    auto uniformBfStorage=ChunkedF32Storage::Build(adaptiveWide,4,1.0e18f,4);
    exportedHalf.clear();
    assert(uniformBfStorage.ExportUniform16Bit(exportedEncoding,exportedHalf));
    assert(exportedEncoding==Encoding::BF16 && exportedHalf==adaptiveBf.payload);
    const float mixedChunks[]={1.0f,-2.0f,0.5f,4.0f,1.0001f,2.0001f,3.0001f,4.0001f};
    auto mixedStorage=ChunkedF32Storage::Build(mixedChunks,8,0.0f,4);
    assert(!mixedStorage.ExportUniform16Bit(exportedEncoding,exportedHalf));
    const float adaptiveReject[]={1.0001f,2.0001f};
    auto adaptiveRaw=EncodeAdaptiveF32(adaptiveReject,2,0.0f);
    assert(adaptiveRaw.encoding==Encoding::Raw);
    assert(Decode(adaptiveRaw).size()==sizeof(adaptiveReject));
    bool nullTensor=false;
    try { (void)EncodeAdaptiveF32(nullptr,1,0.1f); }
    catch(const std::invalid_argument&) { nullTensor=true; }
    assert(nullTensor);
    // Chunked residency decodes only the chunks intersecting an inference
    // tile; compressed storage size is measured independently of F32 size.
    std::vector<float> resident(10003);
    for(size_t i=0;i<resident.size();++i)
        resident[i]=(i%7==0)?float(i)*0.25f:float(int(i%19)-9);
    auto chunked=ChunkedF32Storage::Build(resident.data(),resident.size(),0.0f,1024);
    assert(chunked.size()==resident.size() && chunked.chunkCount()==10);
    // Production admission streams bounded source tiles, rejects a tensor as
    // soon as its first chunk cannot be stored smaller, and never stages a
    // second full F32 copy.
    size_t streamedReads=0;
    auto streamed=ChunkedF32Storage::BuildFromReader(
        resident.size(),0.0f,
        [&](size_t offset,size_t count,float* out) {
            ++streamedReads;
            std::copy(resident.begin()+offset,resident.begin()+offset+count,out);
            return true;
        },1024,true,resident.size()*sizeof(float));
    assert(streamedReads==resident.size()/1024+(resident.size()%1024!=0));
    assert(streamed.size()==resident.size());
    assert(streamed.storedBytes()<resident.size()*sizeof(float));
    std::vector<float> streamedTile(777);
    streamed.ReadRange(777,streamedTile.size(),streamedTile.data());
    for(size_t i=0;i<streamedTile.size();++i)
        assert(streamedTile[i]==resident[777+i]);

    std::vector<float> noisy(8192);
    uint32_t randomState=0x9e3779b9u;
    for(float& value:noisy) {
        randomState^=randomState<<13; randomState^=randomState>>17; randomState^=randomState<<5;
        value=static_cast<float>(randomState & 0x00ffffffu) / 16777216.0f;
    }
    size_t noisyReads=0;
    bool firstChunkRejected=false;
    try {
        (void)ChunkedF32Storage::BuildFromReader(
            noisy.size(),0.0f,
            [&](size_t offset,size_t count,float* out) {
                ++noisyReads;
                std::copy(noisy.begin()+offset,noisy.begin()+offset+count,out);
                return true;
            },1024,true,noisy.size()*sizeof(float));
    } catch(const std::runtime_error&) { firstChunkRejected=true; }
    assert(firstChunkRejected && noisyReads==1);

    size_t budgetReads=0;
    bool budgetRejected=false;
    try {
        (void)ChunkedF32Storage::BuildFromReader(
            resident.size(),0.0f,
            [&](size_t offset,size_t count,float* out) {
                ++budgetReads;
                std::copy(resident.begin()+offset,resident.begin()+offset+count,out);
                return true;
            },1024,true,1);
    } catch(const std::runtime_error&) { budgetRejected=true; }
    assert(budgetRejected && budgetReads==1);
    assert(chunked.chunkElements()==1024);
    assert(chunked.storedBytes()<=resident.size()*sizeof(float));
    std::vector<float> tile(1500,-999.0f);
    chunked.ReadRange(900,tile.size(),tile.data());
    for(size_t i=0;i<tile.size();++i) assert(tile[i]==resident[900+i]);
    std::vector<uint8_t> reusableDecodeScratch;
    std::vector<float> secondTile(700);
    chunked.ReadRange(3000,secondTile.size(),secondTile.data(),reusableDecodeScratch);
    for(size_t i=0;i<secondTile.size();++i)
        assert(secondTile[i]==resident[3000+i]);

    std::vector<float> whole(resident.size());
    chunked.ReadRange(0,whole.size(),whole.data());
    assert(whole==resident);
    bool rangeRejected=false;
    try { chunked.ReadRange(resident.size()-1,2,tile.data()); }
    catch(const std::out_of_range&) { rangeRejected=true; }
    assert(rangeRejected);
    bool zeroChunkRejected=false;
    try { (void)ChunkedF32Storage::Build(resident.data(),resident.size(),0.0f,0); }
    catch(const std::invalid_argument&) { zeroChunkRejected=true; }
    assert(zeroChunkRejected);
    const float not_exact[]={1.0001f,2.0001f};
    auto preserved=Encode(not_exact,sizeof(not_exact),true,0.0f);
    assert(preserved.encoding!=Encoding::F16);
    const float specials[]={std::numeric_limits<float>::infinity(),1.0f};
    assert(Encode(specials,sizeof(specials),true,1.0f).encoding!=Encoding::F16);
    assert(ToHalf(1.0f)==0x3c00 && ToHalf(-0.0f)==0x8000);
    assert(Bits(FromHalf(0x3c00))==Bits(1.0f));
    assert(Bits(FromHalf(0x0001))==Bits(0x1p-24f));
    auto malformed=r;
    malformed.payload.push_back(1);
    std::vector<uint8_t> untouched(repeated.size(),0xa5);
    bool malformedRejected=false;
    try { DecodeInto(malformed,untouched.data(),untouched.size()); }
    catch(const std::invalid_argument&) { malformedRejected=true; }
    assert(malformedRejected);
    assert(std::all_of(untouched.begin(),untouched.end(),[](uint8_t x){return x==0xa5;}));
    bool wrongSize=false;
    try { DecodeInto(r,untouched.data(),untouched.size()-1); }
    catch(const std::invalid_argument&) { wrongSize=true; }
    assert(wrongSize);
    bool rejected=false;
    try { auto bad=r; bad.payload[0]=0; (void)Decode(bad); } catch(const std::invalid_argument&) {rejected=true;}
    assert(rejected);

    // storedBytes() includes the retained chunk directory, not only payload
    // lengths. Four small chunks must account for at least four Result slots.
    std::vector<float> accountingF32(1024, 0.0f);
    auto accountingF32Storage = ChunkedF32Storage::BuildFromReader(
        accountingF32.size(), 0.0f,
        [&](size_t offset, size_t count, float* out) {
            std::copy(accountingF32.begin() + offset,
                      accountingF32.begin() + offset + count, out);
            return true;
        }, 256);
    assert(accountingF32Storage.storedBytes() >= 4 * sizeof(Result));
    assert(accountingF32Storage.storedBytes() < accountingF32.size() * sizeof(float));

    std::vector<uint8_t> accountingBytes(1024, 0x6b);
    auto accountingByteStorage = ChunkedByteStorage::BuildFromReader(
        accountingBytes.size(),
        [&](size_t offset, size_t count, uint8_t* out) {
            std::copy(accountingBytes.begin() + offset,
                      accountingBytes.begin() + offset + count, out);
            return true;
        }, 256, false);
    assert(accountingByteStorage.storedBytes() >= 4 * sizeof(Result));
    assert(accountingByteStorage.storedBytes() < accountingBytes.size());

    // Distinct but correlated 16-bit bit patterns. The predictor is bitwise
    // and must preserve all payload bits without numerical approximation.
    std::vector<uint16_t> correlated16(4096);
    uint16_t running16 = 0x3c00u;
    for (size_t i = 0; i < correlated16.size(); ++i) {
        running16 = uint16_t(running16 ^ uint16_t(i % 11u));
        correlated16[i] = running16;
    }
    correlated16[21] = 0x8000u;
    correlated16[22] = 0x7e55u;
    const auto encoded16 = Encode(correlated16.data(),
                                  correlated16.size() * sizeof(uint16_t));
    const auto restored16 = Decode(encoded16);
    assert(restored16.size() == correlated16.size() * sizeof(uint16_t));
    assert(std::memcmp(restored16.data(), correlated16.data(), restored16.size()) == 0);
    assert(encoded16.payload.size() <= restored16.size());

    // Structured 8-byte records: independent varying payloads and common
    // metadata bytes. Test exact byte restoration regardless of which
    // adaptive lossless codec wins the block.
    std::vector<uint8_t> records(8192);
    for (size_t i = 0; i < records.size() / 8; ++i) {
        for (size_t lane = 0; lane < 8; ++lane)
            records[i * 8 + lane] = lane < 4
                ? uint8_t((i * 29u + lane * 67u) & 0xffu)
                : uint8_t(0x40u + lane);
    }
    const auto recordsEncoded = Encode(records.data(), records.size());
    assert(recordsEncoded.payload.size() < records.size());
    assert(Decode(recordsEncoded) == records);

    // Correlated, non-identical 32-bit patterns. XOR prediction must be
    // lossless, including signed zero and NaN payload bits.
    std::vector<uint32_t> correlated(4096);
    uint32_t state = 0x3f800000u;
    for (size_t i = 0; i < correlated.size(); ++i) {
        state ^= (uint32_t(i % 7u) << (i % 5u));
        correlated[i] = state ^ uint32_t(i & 0xffu);
    }
    correlated[13] = 0x80000000u;
    correlated[14] = 0x7fc12345u;
    const auto correlatedEncoded = Encode(correlated.data(),
                                          correlated.size() * sizeof(uint32_t));
    const auto correlatedDecoded = Decode(correlatedEncoded);
    assert(correlatedDecoded.size() == correlated.size() * sizeof(uint32_t));
    assert(std::memcmp(correlatedDecoded.data(), correlated.data(),
                       correlatedDecoded.size()) == 0);
    assert(correlatedEncoded.payload.size() <= correlatedDecoded.size());

    // Distinct FP16/BF16-like values with a shared exponent byte. The
    // low byte varies, so whole 16-bit words are not a repetitive byte run.
    std::vector<uint16_t> varied16(4096);
    for (size_t i = 0; i < varied16.size(); ++i)
        varied16[i] = uint16_t(0x3c00u | ((i * 73u) & 0x03ffu));
    auto packed16 = Encode(varied16.data(), varied16.size() * sizeof(uint16_t));
    assert(packed16.encoding == Encoding::Shuffle16LZ4 ||
           packed16.encoding == Encoding::ShuffleLZ4 ||
           packed16.encoding == Encoding::LZ4);
    assert(packed16.payload.size() < varied16.size() * sizeof(uint16_t));
    auto decoded16 = Decode(packed16);
    assert(std::memcmp(decoded16.data(), varied16.data(), decoded16.size()) == 0);
    auto corrupt16 = packed16;
    corrupt16.payload.clear();
    std::vector<uint8_t> untouched16(decoded16.size(), 0x5a);
    bool caught16 = false;
    try { DecodeInto(corrupt16, untouched16.data(), untouched16.size()); }
    catch (const std::invalid_argument&) { caught16 = true; }
    assert(caught16);
    assert(std::all_of(untouched16.begin(), untouched16.end(),
                       [](uint8_t x) { return x == 0x5a; }));

    // Non-repeating F32 weights can still have compressible exponent lanes.
    // This lossless shuffled representation must beat raw without relying on
    // repeated whole float values, and must roundtrip bit-for-bit.
    std::vector<uint32_t> variedBits(4096);
    for (size_t i = 0; i < variedBits.size(); ++i)
        variedBits[i] = 0x3f800000u | static_cast<uint32_t>(i * 131u);
    auto varied = Encode(variedBits.data(), variedBits.size() * sizeof(uint32_t));
    assert(varied.encoding == Encoding::ShuffleLZ4);
    assert(varied.payload.size() < variedBits.size() * sizeof(uint32_t));
    const auto restoredVaried = Decode(varied);
    assert(restoredVaried.size() == variedBits.size() * sizeof(uint32_t));
    assert(std::memcmp(restoredVaried.data(), variedBits.data(), restoredVaried.size()) == 0);
    auto damagedVaried = varied;
    damagedVaried.payload.clear();
    std::vector<uint8_t> intactVaried(restoredVaried.size(), 0x7e);
    bool rejectedVaried = false;
    try { DecodeInto(damagedVaried, intactVaried.data(), intactVaried.size()); }
    catch (const std::invalid_argument&) { rejectedVaried = true; }
    assert(rejectedVaried);
    assert(std::all_of(intactVaried.begin(), intactVaried.end(),
                       [](uint8_t byte) { return byte == 0x7e; }));

    // Direct packed row-window staging: no intermediate whole-tensor buffer.
    // Vary every value so RLE cannot beat packed F16. Generate a
    // deterministic high-entropy sequence of exactly representable halves.
    std::vector<float> packedSource(1024);
    uint32_t packedSeed = 0x9e3779b9u;
    for (size_t i = 0; i < packedSource.size(); ++i) {
        packedSeed ^= packedSeed << 13;
        packedSeed ^= packedSeed >> 17;
        packedSeed ^= packedSeed << 5;
        const int32_t signedValue = static_cast<int32_t>(packedSeed & 0x7ffu) - 1024;
        packedSource[i] = static_cast<float>(signedValue) / 16.0f;
    }
    auto packedStorage = ChunkedF32Storage::BuildFromReader(
        packedSource.size(), 0.0f,
        [&](size_t offset, size_t count, float* out) {
            std::copy(packedSource.begin() + offset,
                      packedSource.begin() + offset + count, out);
            return true;
        }, 128);
    Encoding packedEncoding = Encoding::Raw;
    std::vector<uint8_t> packedWindow(130 * sizeof(uint16_t), 0xa5);
    assert(packedStorage.CopyUniform16BitRange(
        127, 129, packedEncoding, packedWindow.data(), packedWindow.size()));
    assert(packedEncoding == Encoding::F16);
    for (size_t i = 0; i < 129; ++i) {
        const uint16_t value = static_cast<uint16_t>(packedWindow[2*i]) |
                               (static_cast<uint16_t>(packedWindow[2*i+1]) << 8);
        assert(FromHalf(value) == packedSource[127 + i]);
    }
    assert(packedWindow[129 * 2] == 0xa5);
    assert(packedWindow[129 * 2 + 1] == 0xa5);
    std::vector<uint8_t> shortWindow(8, 0x5a);
    packedEncoding = Encoding::Raw;
    assert(!packedStorage.CopyUniform16BitRange(
        127, 129, packedEncoding, shortWindow.data(), shortWindow.size()));
    assert(std::all_of(shortWindow.begin(), shortWindow.end(),
                       [](uint8_t value) { return value == 0x5a; }));
    assert(!packedStorage.CopyUniform16BitRange(
        1023, 2, packedEncoding, packedWindow.data(), packedWindow.size()));
    assert(!packedStorage.CopyUniform16BitRange(
        127, 129, packedEncoding, nullptr, packedWindow.size()));

    // Cross-chunk lossless byte reads, including the final partial chunk.
    std::vector<uint8_t> byteSource(1000, 0x3c);
    auto byteStorage = ChunkedByteStorage::BuildFromReader(
        byteSource.size(),
        [&](size_t offset, size_t count, uint8_t* out) {
            std::copy(byteSource.begin() + offset,
                      byteSource.begin() + offset + count, out);
            return true;
        }, 128);
    std::vector<uint8_t> byteWindow(200, 0x7f), byteScratch;
    byteStorage.ReadRange(125, 200, byteWindow.data(), byteScratch);
    assert(std::all_of(byteWindow.begin(), byteWindow.end(),
                       [](uint8_t v) { return v == 0x3c; }));
    std::vector<uint8_t> byteTail(20, 0);
    byteStorage.ReadRange(980, 20, byteTail.data(), byteScratch);
    assert(std::all_of(byteTail.begin(), byteTail.end(),
                       [](uint8_t v) { return v == 0x3c; }));
    bool byteOutOfRange = false;
    try { byteStorage.ReadRange(999, 2, byteTail.data(), byteScratch); }
    catch (const std::out_of_range&) { byteOutOfRange = true; }
    assert(byteOutOfRange);
    assert(byteStorage.storedBytes() < byteSource.size());

    // F32 bounded decode: unaligned cross-chunk and final partial chunk.
    std::vector<float> f32Source(1000, 2.0f);
    auto f32Storage = ChunkedF32Storage::BuildFromReader(
        f32Source.size(), 0.0f,
        [&](size_t offset, size_t count, float* out) {
            std::copy(f32Source.begin() + offset,
                      f32Source.begin() + offset + count, out);
            return true;
        }, 128);
    std::vector<float> f32Window(200, -1.0f);
    std::vector<uint8_t> f32Scratch;
    f32Storage.ReadRange(125, f32Window.size(), f32Window.data(), f32Scratch);
    assert(std::all_of(f32Window.begin(), f32Window.end(),
                       [](float value) { return value == 2.0f; }));
    std::vector<float> f32Tail(20, 0.0f);
    f32Storage.ReadRange(980, 20, f32Tail.data(), f32Scratch);
    assert(std::all_of(f32Tail.begin(), f32Tail.end(),
                       [](float value) { return value == 2.0f; }));
    bool f32OutOfRange = false;
    try { f32Storage.ReadRange(999, 2, f32Tail.data(), f32Scratch); }
    catch (const std::out_of_range&) { f32OutOfRange = true; }
    assert(f32OutOfRange);

    // Count the retained per-chunk directory against the hard budget before
    // source I/O. Tiny chunks cannot create unbounded metadata outside the cap.
    size_t f32MetadataReads = 0;
    bool f32MetadataRejected = false;
    try {
        (void)ChunkedF32Storage::BuildFromReader(
            1024, 0.0f,
            [&](size_t, size_t, float*) { ++f32MetadataReads; return true; },
            1, false, 512);
    } catch (const StorageAdmissionRejected&) {
        f32MetadataRejected = true;
    }
    assert(f32MetadataRejected && f32MetadataReads == 0);

    size_t byteMetadataReads = 0;
    bool byteMetadataRejected = false;
    try {
        (void)ChunkedByteStorage::BuildFromReader(
            1024,
            [&](size_t, size_t, uint8_t*) { ++byteMetadataReads; return true; },
            1, false, 512);
    } catch (const StorageAdmissionRejected&) {
        byteMetadataRejected = true;
    }
    assert(byteMetadataRejected && byteMetadataReads == 0);

    std::cout<<"native tensor compression tests PASS\n";
}
