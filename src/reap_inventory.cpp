#include "reap_inventory.hpp"
#include "reap_expert_layout.hpp"

#include "deep2/GGUFLoader.hpp"

#include <algorithm>
#include <filesystem>

namespace RawrXD::Reap {
namespace {
namespace fs = std::filesystem;

bool IsExpertTensor(const std::string& name) {
    return name.find(".experts.") != std::string::npos ||
           name.find(".expert.") != std::string::npos ||
           name.find(".ffn_gate_exps.") != std::string::npos ||
           name.find(".ffn_up_exps.") != std::string::npos ||
           name.find(".ffn_down_exps.") != std::string::npos ||
           name.find("experts.") == 0;
}
} // namespace

bool CollectInventory(const std::string& path, Deep2::GGUFLoader& loader,
                      Inventory& out, std::string& error) {
    if (!loader.load(path)) {
        error = loader.error();
        return false;
    }
    const char* archKeys[] = {
        "deepseek2.block_count", "deepseek.block_count", "llama.block_count"};
    for (const char* key : archKeys) {
        const int64_t count = loader.getMetaInt(key, 0);
        if (count > 0) { out.layerCount = static_cast<uint64_t>(count); break; }
    }
    for (const auto& name : loader.listTensors()) {
        const auto* tensor = loader.getTensor(name);
        if (!tensor || !IsExpertTensor(name)) continue;
        out.expertBytes += tensor->sizeBytes;
        ++out.expertTensors;
    }
    for (uint32_t layer = 0; layer < 256; ++layer) {
        const std::string prefix = "blk." + std::to_string(layer) + ".";
        const auto* gate = loader.getTensor(prefix + "ffn_gate_exps.weight");
        const auto* up = loader.getTensor(prefix + "ffn_up_exps.weight");
        const auto* down = loader.getTensor(prefix + "ffn_down_exps.weight");
        if (!gate && !up && !down) continue;
        out.layerCount = (std::max)(out.layerCount, static_cast<uint64_t>(layer + 1));
        const auto decision = ClassifyExpertProjections(
            gate != nullptr, up != nullptr, down != nullptr,
            gate && !gate->shape.empty(), up && !up->shape.empty(), down && !down->shape.empty(),
            gate && !gate->shape.empty() ? gate->shape.back() : 0,
            up && !up->shape.empty() ? up->shape.back() : 0,
            down && !down->shape.empty() ? down->shape.back() : 0);
        if (decision.kind != ExpertLayoutKind::DeepseekTriplet) {
            error = LayoutRejection(decision, layer, loader.getMetaString("general.architecture", ""));
            return false;
        }
        const uint64_t count = static_cast<uint64_t>(gate->shape.back());
        if (count == 0 || gate->sizeBytes % count || up->sizeBytes % count ||
            down->sizeBytes % count) {
            error = "expert projection slices are not divisible at layer " + std::to_string(layer);
            return false;
        }
        out.moeLayers.insert(layer);
        out.logicalExperts += count;
        out.maxExpertsPerLayer = (std::max)(out.maxExpertsPerLayer, count);
    }
    std::error_code ec;
    const fs::path first(path);
    const std::string stem = first.filename().string();
    const auto marker = stem.find("-00001-of-");
    if (marker != std::string::npos) {
        const std::string prefix = stem.substr(0, marker);
        for (const auto& entry : fs::directory_iterator(first.parent_path(), ec)) {
            if (ec || !entry.is_regular_file()) continue;
            const auto name = entry.path().filename().string();
            if (name.rfind(prefix + "-", 0) == 0 && entry.path().extension() == ".gguf")
                out.totalBytes += fs::file_size(entry.path(), ec);
        }
    } else {
        out.totalBytes = fs::file_size(first, ec);
    }
    if (!out.totalBytes) out.totalBytes = loader.mappedBytes();
    if (!out.totalBytes) { error = "model size could not be established"; return false; }
    return true;
}

} // namespace RawrXD::Reap
