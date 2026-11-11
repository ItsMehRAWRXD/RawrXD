#include "ExecutableRom.hpp"

#include <cstdio>
#include <fstream>

int main(int argc, char** argv) {
    const std::string path = argc > 1 ? argv[1] : "rawrxd_roundtrip.rxrom";
    const bool readOnly = argc > 2 && std::string(argv[2]) == "--read-only";
    if (readOnly) {
        rawrxd::rom::Header header;
        std::vector<rawrxd::rom::TensorRecord> records;
        std::string error;
        if (!rawrxd::rom::Read(path, records, header, error)) {
            std::fprintf(stderr, "ROM_READ_REJECTED %s\n", error.c_str());
            return 1;
        }
        std::printf("ROM_READ_PASS tensors=%zu alignment=%llu\n", records.size(), static_cast<unsigned long long>(header.alignment));
        return 0;
    }
    std::vector<rawrxd::rom::TensorInput> inputs;
    inputs.push_back({"router.weight", 0, {4, 8}, std::vector<uint8_t>(37, 0x5a), 0x5});
    inputs.push_back({"experts.0.w1", 24, {16, 8}, std::vector<uint8_t>(65537, 0xa5), 0xa});

    std::string error;
    if (!rawrxd::rom::Write(path, inputs, error)) {
        std::fprintf(stderr, "ROM_WRITE_FAIL %s\n", error.c_str());
        return 1;
    }
    rawrxd::rom::Header header;
    std::vector<rawrxd::rom::TensorRecord> records;
    if (!rawrxd::rom::Read(path, records, header, error)) {
        std::fprintf(stderr, "ROM_READ_FAIL %s\n", error.c_str());
        return 1;
    }
    if (records.size() != inputs.size() || header.fileBytes == 0) {
        std::fprintf(stderr, "ROM_ROUNDTRIP_FAIL record_count=%zu\n", records.size());
        return 1;
    }
    for (size_t i = 0; i < records.size(); ++i) {
        if (records[i].name != inputs[i].name || records[i].bytes != inputs[i].bytes.size() ||
            records[i].offset % rawrxd::rom::kAlignment != 0 ||
            records[i].paddedBytes % rawrxd::rom::kAlignment != 0) {
            std::fprintf(stderr, "ROM_ROUNDTRIP_FAIL index=%zu\n", i);
            return 1;
        }
    }
    std::printf("ROM_ROUNDTRIP_PASS tensors=%zu alignment=%llu file_bytes=%llu\n",
                records.size(), static_cast<unsigned long long>(header.alignment),
                static_cast<unsigned long long>(header.fileBytes));
    return 0;
}
