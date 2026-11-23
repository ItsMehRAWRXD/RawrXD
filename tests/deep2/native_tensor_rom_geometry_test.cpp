#include "../../src/TensorROM.hpp"
#include <cassert>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

static void put32(std::ostream& o,uint32_t v){for(int i=0;i<4;++i)o.put(char(v>>(8*i)));}
static void put64(std::ostream& o,uint64_t v){for(int i=0;i<8;++i)o.put(char(v>>(8*i)));}
static void putString(std::ostream& o,const std::string& s){put64(o,s.size());o.write(s.data(),std::streamsize(s.size()));}

static bool writeMini(const std::filesystem::path& path,uint32_t type,
                      const std::vector<uint64_t>& dims,size_t payloadBytes,
                      uint32_t alignment=32) {
    std::ofstream out(path,std::ios::binary|std::ios::trunc);
    if(!out)return false;
    out.write("GGUF",4);put32(out,3);put64(out,1);put64(out,alignment==32?0:1);
    if(alignment!=32) { putString(out,"general.alignment");put32(out,4);put32(out,alignment); }
    putString(out,"tensor");put32(out,static_cast<uint32_t>(dims.size()));
    for(uint64_t d:dims)put64(out,d);
    put32(out,type);put64(out,0);
    const size_t pos=static_cast<size_t>(out.tellp());
    for(size_t i=pos;i%alignment;++i)out.put('\0');
    std::vector<uint8_t> payload(payloadBytes,0x5A);
    out.write(reinterpret_cast<const char*>(payload.data()),std::streamsize(payload.size()));
    return bool(out);
}

static void testValid(uint32_t type,const std::vector<uint64_t>& dims,size_t bytes,
                      uint32_t alignment=32) {
    const auto path=std::filesystem::temp_directory_path()/
        ("rawrxd-rom-geometry-"+std::to_string(type)+"-"+std::to_string(alignment)+".gguf");
    assert(writeMini(path,type,dims,bytes,alignment));
    {
        deep2::TensorROM rom;
        assert(rom.addShard(path.string()));
        assert(rom.finalizeIndex());
        const auto* entry=rom.findTensor("tensor");
        assert(entry&&static_cast<uint32_t>(entry->type)==type);
        assert(entry->byteSize()==bytes);
        std::vector<uint8_t> payload(bytes);
        assert(rom.readTensorRange(*entry,0,bytes,payload.data()));
        assert(payload.front()==0x5A&&payload.back()==0x5A);
        uint8_t sentinel=0xCC;
        assert(!rom.readTensorRange(*entry,bytes-1,2,&sentinel));
        assert(sentinel==0xCC);
        assert(rom.readTensorRange(*entry,bytes,0,nullptr));
    }
    std::filesystem::remove(path);
}

static void testRejected(uint32_t type,const std::vector<uint64_t>& dims) {
    const auto path=std::filesystem::temp_directory_path()/
        ("rawrxd-rom-reject-"+std::to_string(type)+".gguf");
    assert(writeMini(path,type,dims,0));
    {
        deep2::TensorROM rom;
        assert(!rom.addShard(path.string()));
    }
    std::filesystem::remove(path);
}

static void testRejectedAlignment() {
    const auto path=std::filesystem::temp_directory_path()/"rawrxd-rom-bad-alignment.gguf";
    assert(writeMini(path,0,{16,2},16*2*4,24));
    {
        deep2::TensorROM rom;
        assert(!rom.addShard(path.string()));
    }
    std::filesystem::remove(path);
}

static void testPagerStreamingAndEviction() {
    std::vector<uint8_t> backing(128);
    for (size_t i = 0; i < backing.size(); ++i) backing[i] = static_cast<uint8_t>(i);
    deep2::PageCache cache(32, 16);
    cache.setReader([&](uint32_t, uint64_t pageNo, uint8_t* out, size_t size) {
        const uint64_t offset = pageNo * 16;
        if (offset > backing.size() || size > backing.size() - offset) return false;
        std::memcpy(out, backing.data() + static_cast<size_t>(offset), size);
        return true;
    });
    uint8_t actual[40]{};
    assert(cache.readRange(0, 12, sizeof(actual), actual));
    assert(std::memcmp(actual, backing.data() + 12, sizeof(actual)) == 0);
    assert(cache.residentBytes() <= cache.capacityBytes());
    assert(cache.pageCount() <= 2);

    deep2::Page* pinned = cache.acquire(0, 2);
    assert(pinned != nullptr);
    assert(cache.evictUnleasedRange(0, 32, 16) == 0); // leased pages cannot be reclaimed
    cache.release(pinned);
    assert(cache.evictUnleasedRange(0, 32, 16) == 1);
    assert(cache.residentBytes() <= cache.capacityBytes());

    deep2::Page* pinnedAgain = cache.acquire(0, 3);
    assert(pinnedAgain != nullptr);
    cache.evictUnleasedAll();
    assert(cache.pageCount() == 1); // leased page survives; every other page is reclaimed
    cache.release(pinnedAgain);
    cache.evictUnleasedAll();
    assert(cache.pageCount() == 0);
}

static void testPagerPinnedBudgetFailsClosed() {
    std::vector<uint8_t> backing(64, 0xA5);
    deep2::PageCache cache(16, 16);
    cache.setReader([&](uint32_t, uint64_t pageNo, uint8_t* out, size_t size) {
        const uint64_t offset = pageNo * 16;
        if (offset > backing.size() || size > backing.size() - offset) return false;
        std::memcpy(out, backing.data() + static_cast<size_t>(offset), size);
        return true;
    });
    deep2::Page* held = cache.acquire(0, 0);
    assert(held != nullptr);
    assert(cache.acquire(0, 1) == nullptr); // cannot exceed budget while page zero is pinned
    assert(cache.residentBytes() == cache.capacityBytes());
    cache.release(held);
    deep2::Page* next = cache.acquire(0, 1);
    assert(next != nullptr);
    cache.release(next);
    assert(cache.residentBytes() <= cache.capacityBytes());
}

static void testResetBetweenModels() {
    const auto first = std::filesystem::temp_directory_path()/"rawrxd-rom-reset-first.gguf";
    const auto second = std::filesystem::temp_directory_path()/"rawrxd-rom-reset-second.gguf";
    assert(writeMini(first, 2, {32,1}, 18, 256));
    assert(writeMini(second, 2, {32,1}, 18, 32));
    deep2::TensorROM rom;
    assert(rom.addShard(first.string()) && rom.finalizeIndex());
    assert(rom.shards()[0].dataOffset % 256 == 0);
    rom.Reset();
    assert(rom.shardCount() == 0);
    assert(rom.addShard(second.string()) && rom.finalizeIndex());
    assert(rom.shards()[0].dataOffset < 256); // stale 256-byte alignment metadata was not inherited
    rom.Reset();
    std::filesystem::remove(first);
    std::filesystem::remove(second);
}

int main() {
    testPagerPinnedBudgetFailsClosed();
    testPagerStreamingAndEviction();
    testResetBetweenModels();
    testRejectedAlignment();
    testValid(0,{16,2},16*2*4);
    testValid(1,{16,2},16*2*2);
    testValid(2,{32,2},2*18);
    testValid(2,{32,2},2*18,64); // explicit general.alignment override
    testValid(8,{32,2},2*34);
    testValid(9,{32,2},2*36);
    testValid(20,{32,2},2*18); // IQ4_NL
    testValid(10,{256,2},2*84);
    testValid(11,{256,2},2*110);
    testValid(12,{256,2},2*144);
    testValid(13,{256,2},2*176);
    testValid(14,{256,2},2*210);
    testValid(15,{256,2},2*292);
    testRejected(2,{31,2});   // Q4_0 rows must be block-aligned.
    testRejected(20,{31,2});  // IQ4_NL rows must be block-aligned.
    testRejected(12,{255,2}); // Q4_K rows must be 256-value aligned.
    testRejected(99,{256,2}); // Unknown GGUF types are never assigned guessed strides.
    testRejected(0,{std::numeric_limits<uint64_t>::max(),2}); // Dimension products must not wrap.
    std::cout<<"TensorROM canonical type geometry and bounded range reads PASS\n";
}
