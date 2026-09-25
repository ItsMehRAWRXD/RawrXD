#include "gguf_adapter.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <mutex>
#include <unordered_map>
#include <stdexcept>

namespace rawrxd::canonical {

namespace {
    std::string Trim(const std::string& s) {
        size_t start = s.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) return "";
        size_t end = s.find_last_not_of(" \t\r\n");
        return s.substr(start, end - start + 1);
    }

    std::string ToLower(std::string s) {
        for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return s;
    }
}

class GGUFAdapter::Impl {
public:
    mutable std::mutex mutex_;
    CanonicalModelDescriptor descriptor_;
    std::vector<CanonicalTensor> tensors_;
    bool adapted_ = false;

    bool ParseDescriptor(const rawrxd::GGUFLoader& loader) {
        auto arch = loader.GetStringMetadata("general.architecture");
        if (arch) descriptor_.architecture = ParseArchitecture(*arch);
        auto name = loader.GetStringMetadata("general.name");
        if (name) descriptor_.name = *name;
        auto author = loader.GetStringMetadata("general.author");
        if (author) descriptor_.author = *author;
        auto desc = loader.GetStringMetadata("general.description");
        if (desc) descriptor_.description = *desc;
        auto lic = loader.GetStringMetadata("general.license");
        if (lic) descriptor_.license = *lic;
        auto url = loader.GetStringMetadata("general.source.url");
        if (url) descriptor_.source_url = *url;

        auto hparams = {
            std::make_pair("vocab_size", &descriptor_.hparams.vocab_size),
            std::make_pair("hidden_size", &descriptor_.hparams.hidden_size),
            std::make_pair("intermediate_size", &descriptor_.hparams.intermediate_size),
            std::make_pair("num_attention_heads", &descriptor_.hparams.num_attention_heads),
            std::make_pair("num_hidden_layers", &descriptor_.hparams.num_hidden_layers),
            std::make_pair("num_key_value_heads", &descriptor_.hparams.num_key_value_heads),
            std::make_pair("max_position_embeddings", &descriptor_.hparams.max_position_embeddings),
            std::make_pair("sliding_window", &descriptor_.hparams.sliding_window),
        };
        for (const auto& [key, ptr] : hparams) {
            auto v = loader.GetUint32Metadata(key);
            if (v) *ptr = *v;
        }

        auto rope = loader.GetFloat32Metadata("rope_theta");
        if (rope) descriptor_.hparams.rope_theta = *rope;
        auto rms = loader.GetFloat32Metadata("rms_norm_eps");
        if (rms) descriptor_.hparams.rms_norm_eps = *rms;

        auto qtype = loader.GetStringMetadata("general.quantization_type");
        if (qtype) descriptor_.quantization_type = *qtype;
        auto qver = loader.GetUint32Metadata("general.quantization_version");
        if (qver) descriptor_.quantization_version = *qver;
        return true;
    }

    bool BuildTensors(const rawrxd::GGUFLoader& loader) {
        auto names = loader.ListTensors();
        tensors_.clear();
        tensors_.reserve(names.size());
        for (const auto& name : names) {
            auto view = loader.GetTensor(name);
            if (!view) continue;
            CanonicalTensor ct;
            ct.name = view->name();
            ct.layout = ParseTensorType(static_cast<uint32_t>(view->type()));
            ct.shape = view->shape();
            size_t n = view->count() * 4; // approximate
            ct.data.resize(n);
            tensors_.push_back(ct);
        }
        return true;
    }
};

GGUFAdapter::GGUFAdapter() : impl_(std::make_unique<Impl>()) {}
GGUFAdapter::~GGUFAdapter() = default;

bool GGUFAdapter::AdaptFromFile(const std::string& path) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    rawrxd::GGUFLoader loader;
    if (!loader.LoadFromFile(path)) return false;
    return AdaptFromLoader(loader);
}

bool GGUFAdapter::AdaptFromMemory(const std::vector<uint8_t>& buffer) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    rawrxd::GGUFLoader loader;
    if (!loader.LoadFromMemory(buffer)) return false;
    return AdaptFromLoader(loader);
}

bool GGUFAdapter::AdaptFromLoader(const rawrxd::GGUFLoader& loader) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->adapted_ = false;
    impl_->descriptor_ = CanonicalModelDescriptor{};
    impl_->tensors_.clear();
    if (!impl_->ParseDescriptor(loader)) return false;
    if (!impl_->BuildTensors(loader)) return false;
    impl_->adapted_ = true;
    return true;
}

bool GGUFAdapter::IsAdapted() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->adapted_;
}

const CanonicalModelDescriptor* GGUFAdapter::GetDescriptor() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->adapted_ ? &impl_->descriptor_ : nullptr;
}

std::optional<CanonicalTensorView> GGUFAdapter::GetTensor(const std::string& name) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    for (const auto& t : impl_->tensors_) {
        if (t.name == name) return CanonicalTensorView(&t);
    }
    return std::nullopt;
}

std::vector<std::string> GGUFAdapter::ListTensorNames() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<std::string> names;
    for (const auto& t : impl_->tensors_) names.push_back(t.name);
    return names;
}

size_t GGUFAdapter::TensorCount() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->tensors_.size();
}

std::optional<CanonicalTensorView> GGUFAdapter::GetWeightTensor(const std::string& layer_prefix,
                                                               const std::string& weight_name) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    for (const auto& t : impl_->tensors_) {
        if (t.name.find(layer_prefix) == 0 && t.name.find(weight_name) != std::string::npos) {
            return CanonicalTensorView(&t);
        }
    }
    return std::nullopt;
}

bool GGUFAdapter::HasTensor(const std::string& name) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    for (const auto& t : impl_->tensors_) {
        if (t.name == name) return true;
    }
    return false;
}

std::string GGUFAdapter::ArchitectureString() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    switch (impl_->descriptor_.architecture) {
        case ModelArchitecture::Llama: return "llama";
        case ModelArchitecture::Mamba: return "mamba";
        case ModelArchitecture::GPTNeoX: return "gpt_neox";
        case ModelArchitecture::Falcon: return "falcon";
        case ModelArchitecture::Gemma: return "gemma";
        case ModelArchitecture::Phi: return "phi";
        case ModelArchitecture::Qwen: return "qwen";
        case ModelArchitecture::DeepSeek2: return "deepseek2";
        case ModelArchitecture::CommandR: return "command-r";
        case ModelArchitecture::Granite: return "granite";
        case ModelArchitecture::Cohere: return "cohere";
        case ModelArchitecture::Nomic: return "nomic";
        default: return "unknown";
    }
}

ModelArchitecture GGUFAdapter::ParseArchitecture(const std::string& arch_str) {
    std::string s = ToLower(Trim(arch_str));
    if (s == "llama" || s == "llama4") return ModelArchitecture::Llama;
    if (s == "mamba") return ModelArchitecture::Mamba;
    if (s == "gpt_neox" || s == "gptneox") return ModelArchitecture::GPTNeoX;
    if (s == "gptbigcode" || s == "gpt_bigcode") return ModelArchitecture::GPTBigCode;
    if (s == "falcon") return ModelArchitecture::Falcon;
    if (s == "gptj" || s == "gpt_j") return ModelArchitecture::GPTJ;
    if (s == "persimmon") return ModelArchitecture::Persimmon;
    if (s == "refact") return ModelArchitecture::Refact;
    if (s == "bert") return ModelArchitecture::Bert;
    if (s == "nomic_bert") return ModelArchitecture::NomicBert;
    if (s == "jais") return ModelArchitecture::Jais;
    if (s == "gemma" || s == "gemma2") return ModelArchitecture::Gemma;
    if (s == "starcoder2") return ModelArchitecture::Starcoder2;
    if (s == "orion") return ModelArchitecture::Orion;
    if (s == "command-r" || s == "command_r") return ModelArchitecture::CommandR;
    if (s == "xverse") return ModelArchitecture::Xverse;
    if (s == "phi" || s == "phi3" || s == "phi4") return ModelArchitecture::Phi;
    if (s == "phimoe") return ModelArchitecture::PhiMoE;
    if (s == "grok") return ModelArchitecture::Grok;
    if (s == "chatglm") return ModelArchitecture::ChatGLM;
    if (s == "olmo") return ModelArchitecture::OLMo;
    if (s == "olmoe") return ModelArchitecture::OLMoE;
    if (s == "granite") return ModelArchitecture::Granite;
    if (s == "chameleon") return ModelArchitecture::Chameleon;
    if (s == "exaone") return ModelArchitecture::EXAONE;
    if (s == "deepseek2" || s == "deepseek") return ModelArchitecture::DeepSeek2;
    if (s == "minimax") return ModelArchitecture::MiniMax;
    if (s == "qwen" || s == "qwen2") return ModelArchitecture::Qwen;
    if (s == "qwen2moe" || s == "qwen_moe") return ModelArchitecture::Qwen2MoE;
    if (s == "nemotron") return ModelArchitecture::Nemotron;
    if (s == "llama4") return ModelArchitecture::Llama4;
    if (s == "cohere" || s == "cohere2") return ModelArchitecture::Cohere;
    if (s == "nomic") return ModelArchitecture::Nomic;
    return ModelArchitecture::Unknown;
}

TensorLayout GGUFAdapter::ParseTensorType(uint32_t ggml_type) {
    switch (ggml_type) {
        case 0: return TensorLayout::RowMajor;           // F32
        case 1: return TensorLayout::RowMajor;           // F16
        case 2: return TensorLayout::BlockQ4_0;
        case 3: return TensorLayout::BlockQ4_1;
        case 6: return TensorLayout::BlockQ5_0;
        case 7: return TensorLayout::BlockQ5_1;
        case 8: return TensorLayout::BlockQ8_0;
        case 10: return TensorLayout::BlockQ2_K;
        case 11: return TensorLayout::BlockQ3_K;
        case 12: return TensorLayout::BlockQ4_K;
        case 13: return TensorLayout::BlockQ5_K;
        case 14: return TensorLayout::BlockQ6_K;
        case 16: return TensorLayout::BlockIQ2_XXS;
        case 17: return TensorLayout::BlockIQ2_XS;
        case 18: return TensorLayout::BlockIQ2_S;
        case 19: return TensorLayout::BlockIQ3_XXS;
        case 20: return TensorLayout::BlockIQ3_S;
        case 21: return TensorLayout::BlockIQ4_XS;
        case 22: return TensorLayout::BlockIQ4_NL;
        case 30: return TensorLayout::BF16;
        default: return TensorLayout::RowMajor;
    }
}

void GGUFAdapter::Clear() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->adapted_ = false;
    impl_->descriptor_ = CanonicalModelDescriptor{};
    impl_->tensors_.clear();
}

CanonicalTensorView::CanonicalTensorView(const CanonicalTensor* tensor) : tensor_(tensor) {}

bool CanonicalTensorView::IsValid() const { return tensor_ != nullptr; }
const std::string& CanonicalTensorView::Name() const { return tensor_->name; }
TensorLayout CanonicalTensorView::Layout() const { return tensor_->layout; }
const std::vector<uint64_t>& CanonicalTensorView::Shape() const { return tensor_->shape; }
size_t CanonicalTensorView::ByteSize() const { return tensor_->data.size(); }

std::string CanonicalTensorView::ShapeString() const {
    std::ostringstream oss;
    oss << "[";
    for (size_t i = 0; i < tensor_->shape.size(); ++i) {
        if (i > 0) oss << ",";
        oss << tensor_->shape[i];
    }
    oss << "]";
    return oss.str();
}

} // namespace rawrxd::canonical
