#include "../inference/model_loader.h"
#include "../core/rawrxd_quant_container_writer.h"

#include <cstdint>
#include <filesystem>
#include <iostream>
#include <vector>

int main() {
    using RawrXD::Core::RawrXDQuantTensorWriteSpec;
    using RawrXD::Core::RawrXDQuantWriteOptions;
    using RawrXD::Core::WriteRawrXDQuantContainer;
    using RawrXD::Inference::LoaderConfig;
    using RawrXD::Inference::Model;
    using RawrXD::Inference::ModelFormat;
    using RawrXD::Inference::ModelLoader;

    const std::filesystem::path outPath =
        std::filesystem::current_path() / "rxqf_roundtrip_smoke.tmp.rxqf";

    RawrXDQuantTensorWriteSpec spec{};
    spec.name = "blk.0.attn_q.weight";
    spec.quant_mode = RAWRXD_QUANT_FILE_INT8;
    spec.block_size = 32;
    spec.flags = RAWRXD_QUANT_FLAG_BLOCK_BASED;
    spec.alignment = 64;
    spec.dims = {2, 2};
    spec.element_count = 4;
    spec.payload = {11, 22, 33, 44};

    RawrXDQuantWriteOptions opts{};
    opts.global_alignment = 64;
    opts.emit_name_table = true;

    auto writeRes = WriteRawrXDQuantContainer(outPath.string(), {spec}, opts);
    if (!writeRes.success) {
        std::cerr << "[RXQF smoke] write failed: " << writeRes.detail << "\n";
        return 1;
    }

    LoaderConfig cfg{};
    cfg.useMemoryMapping = false;
    ModelLoader loader(cfg);
    Model model{};

    if (!loader.loadModel(outPath.string(), model)) {
        std::cerr << "[RXQF smoke] loadModel failed\n";
        std::filesystem::remove(outPath);
        return 2;
    }

    if (model.format != ModelFormat::RXQF) {
        std::cerr << "[RXQF smoke] unexpected model format\n";
        std::filesystem::remove(outPath);
        return 3;
    }

    auto it = model.tensors.find("blk.0.attn_q.weight");
    if (it == model.tensors.end()) {
        std::cerr << "[RXQF smoke] missing expected tensor name\n";
        std::filesystem::remove(outPath);
        return 4;
    }

    const std::vector<uint8_t>& loaded = it->second.data;
    if (loaded != spec.payload) {
        std::cerr << "[RXQF smoke] payload mismatch\n";
        std::filesystem::remove(outPath);
        return 5;
    }

    std::filesystem::remove(outPath);
    std::cout << "[RXQF smoke] PASS\n";
    return 0;
}
