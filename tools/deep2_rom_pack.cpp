#include "ExecutableRom.hpp"
#include "GGUFLoader.hpp"

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <cstring>
#include <string>
#include <vector>

namespace {

constexpr uint32_t kMoeGate = 1u << 0;
constexpr uint32_t kMoeExpert = 1u << 1;
constexpr uint32_t kPersistent = 1u << 2;
constexpr uint32_t kStreamed = 1u << 3;

bool Contains(const std::string& name, const char* needle) {
    return name.find(needle) != std::string::npos;
}

uint32_t FlagsFor(const std::string& name) {
    // GGUF tensor names are the execution contract.  Router/shared tensors
    // stay resident; numbered expert projections are independently pageable.
    const bool expert = Contains(name, "ffn_gate_exps") ||
                        Contains(name, "ffn_up_exps") ||
                        Contains(name, "ffn_down_exps") ||
                        Contains(name, "experts.");
    const bool router = Contains(name, "ffn_gate_inp") ||
                        Contains(name, "ffn_gate.weight") ||
                        Contains(name, "mlp.gate");
    if (expert) return kMoeExpert | kStreamed;
    if (router) return kMoeGate | kPersistent;
    // Non-expert tensors are needed by every token and are therefore part of
    // the persistent base image for this first executable-ROM format.
    return kPersistent;
}

void Usage() {
    std::fprintf(stderr, "usage: deep2_rom_pack <model.gguf> <output.rxrom>\n");
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 3) { Usage(); return 2; }
    const std::string input = argv[1];
    const std::string output = argv[2];
    Deep2::GGUFLoader reader;
    if (!reader.load(input)) {
        std::fprintf(stderr, "ROM_PACK_FAIL open=%s reason=%s\n", input.c_str(), reader.error().c_str());
        return 1;
    }

    std::vector<rawrxd::rom::TensorSource> sources;
    const auto names = reader.listTensors();
    sources.reserve(names.size());
    size_t expertCount = 0;
    size_t persistentCount = 0;
    for (const auto& name : names) {
        const Deep2::GGUFTensor* tensor = reader.getTensor(name);
        if (!tensor || tensor->sizeBytes == 0 || !tensor->data) {
            std::fprintf(stderr, "ROM_PACK_FAIL unknown tensor geometry name=%s\n", name.c_str());
            return 1;
        }
        rawrxd::rom::TensorSource source;
        source.name = tensor->name;
        source.dtype = static_cast<uint32_t>(tensor->type);
        source.bytes = tensor->sizeBytes;
        source.flags = FlagsFor(tensor->name);
        source.dims.reserve(tensor->shape.size());
        for (int64_t dim : tensor->shape) {
            if (dim < 0) {
                std::fprintf(stderr, "ROM_PACK_FAIL negative tensor dimension name=%s\n", tensor->name.c_str());
                return 1;
            }
            source.dims.push_back(static_cast<uint64_t>(dim));
        }
        // Read from the owning shard in bounded file I/O. Do not memcpy from
        // the mapped pointer: touching every page of a 600+ GB model defeats
        // the whole residency design and can exhaust consumer RAM.
        source.read = [&reader, tensor](std::vector<uint8_t>& bytes) {
            return reader.readTensor(*tensor, bytes);
        };
        source.readChunk = [&reader, tensor](uint64_t offset, uint8_t* dst, size_t bytes) {
            return reader.readTensorChunk(*tensor, offset, dst, bytes);
        };
        if (source.flags & kMoeExpert) ++expertCount;
        if (source.flags & kPersistent) ++persistentCount;
        sources.push_back(std::move(source));
    }

    std::string error;
    if (!rawrxd::rom::WriteStream(output, sources, error)) {
        std::fprintf(stderr, "ROM_PACK_FAIL write=%s reason=%s\n", output.c_str(), error.c_str());
        return 1;
    }
    std::vector<rawrxd::rom::TensorRecord> records;
    rawrxd::rom::Header header;
    if (!rawrxd::rom::Read(output, records, header, error)) {
        std::fprintf(stderr, "ROM_PACK_FAIL verify=%s reason=%s\n", output.c_str(), error.c_str());
        return 1;
    }
    std::printf("ROM_PACK_PASS arch=%s tensors=%zu experts=%zu persistent=%zu bytes=%llu alignment=%u output=%s\n",
                reader.getMetaString("general.architecture", "unknown").c_str(), records.size(), expertCount, persistentCount,
                static_cast<unsigned long long>(header.fileBytes), header.alignment, output.c_str());
    return 0;
}
