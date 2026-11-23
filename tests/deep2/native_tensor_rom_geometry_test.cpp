#include "../../src/TensorROM.hpp"
#include <cassert>
#include <cstdint>
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

int main() {
    testValid(0,{16,2},16*2*4);
    testValid(1,{16,2},16*2*2);
    testValid(2,{32,2},2*18);
    testValid(2,{32,2},2*18,64); // explicit general.alignment override
    testValid(8,{32,2},2*34);
    testValid(9,{32,2},2*36);
    testValid(10,{256,2},2*84);
    testValid(11,{256,2},2*110);
    testValid(12,{256,2},2*144);
    testValid(13,{256,2},2*176);
    testValid(14,{256,2},2*210);
    testValid(15,{256,2},2*292);
    testRejected(2,{31,2});   // Q4_0 rows must be block-aligned.
    testRejected(12,{255,2}); // Q4_K rows must be 256-value aligned.
    testRejected(99,{256,2}); // Unknown GGUF types are never assigned guessed strides.
    testRejected(0,{std::numeric_limits<uint64_t>::max(),2}); // Dimension products must not wrap.
    std::cout<<"TensorROM canonical type geometry and bounded range reads PASS\n";
}
