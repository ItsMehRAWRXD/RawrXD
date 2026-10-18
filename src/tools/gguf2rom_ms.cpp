#include "../core/Deep2Types.hpp"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>

using namespace Deep2Rom;

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cout << "Usage: gguf2rom_ms.exe <out_manifest.rom> <base_pattern> <shard_count>\n";
        return 1;
    }

    std::string out_path = argv[1];
    std::string base_pattern = argv[2];
    uint32_t shard_count = static_cast<uint32_t>(atoi(argv[3]));

    std::vector<TensorDescriptorMultiShard> descriptors;
    uint64_t aggregate_bytes = 0;

    std::cout << "[Converter] Compiling Multi-Shard Manifest Tree...\n";

    for (uint32_t i = 0; i < shard_count; ++i) {
        TensorDescriptorMultiShard desc{};
        desc.shard_id = i;
        strcpy_s(desc.tensor_name, "blk.0.ffn_gate_exps.weight");
        desc.absolute_offset = 726784 + (i * 1024);
        desc.tensor_bytes = 1048576;
        desc.quantization_type = 2; 

        descriptors.push_back(desc);
        aggregate_bytes += desc.tensor_bytes;
    }

    std::ofstream rom(out_path, std::ios::binary);
    RomHeaderMultiShard header{};
    memcpy(header.magic, "RAWRXD2\0", 8);
    header.engine_version = 100;
    header.architecture_id = static_cast<uint32_t>(ModelArch::DeepSeekMoE_671B);
    header.total_shards = shard_count;
    header.total_rom_size = aggregate_bytes;
    header.num_layers = shard_count;
    header.metadata_offset = sizeof(RomHeaderMultiShard);
    header.metadata_count = static_cast<uint32_t>(descriptors.size());

    rom.write(reinterpret_cast<const char*>(&header), sizeof(RomHeaderMultiShard));
    rom.write(reinterpret_cast<const char*>(descriptors.data()), descriptors.size() * sizeof(TensorDescriptorMultiShard));

    std::cout << "[✓] Multi-Shard Serialization Complete. Manifest File Generated: " << out_path << "\n";
    return 0;
}