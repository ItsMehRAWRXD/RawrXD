#pragma once
#include <cstdint>
#include <string>
#include <vector>
namespace rguf {
static constexpr uint32_t VERSION=1, MAGIC=0x46554752u, PATCH_MAGIC=0x31504752u;
enum class Quant:uint8_t{Raw=0,Q4=1};
struct Header{uint32_t magic=MAGIC,version=VERSION,flags=0;uint64_t manifest_off=0,manifest_size=0,blocks_off=0,block_count=0;uint8_t model_id[32]{};};
struct Tensor{std::string name;uint32_t source_type=0;uint32_t runtime_type=0;uint64_t elements=0,bytes=0,first_block=0,block_count=0;std::vector<uint64_t> dims;};
struct Block{uint64_t tensor=0,index=0,file_off=0,stored=0,plain=0;uint32_t generation=0;Quant quant=Quant::Raw;uint8_t nonce[12]{},tag[16]{};uint32_t crc=0;};
}
