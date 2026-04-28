#include "gguf_loader.h"

#include <fstream>

GGUFLoader::GGUFLoader() : is_open_(false) {}

GGUFLoader::~GGUFLoader() {
    Close();
}

bool GGUFLoader::Open(const std::string& filepath) {
    filepath_ = filepath;
    file_.open(filepath, std::ios::binary);
    is_open_ = file_.is_open();
    return is_open_;
}

bool GGUFLoader::Close() {
    if (file_.is_open()) {
        file_.close();
    }
    is_open_ = false;
    return true;
}

bool GGUFLoader::ParseHeader() {
    return is_open_;
}

bool GGUFLoader::ParseMetadata() {
    return is_open_;
}

bool GGUFLoader::VerifyIntegrity(std::string* reason) {
    if (reason) {
        reason->clear();
    }
    return true;
}

bool GGUFLoader::RepairTrivialIssues(std::string* report) {
    if (report) {
        report->clear();
    }
    return true;
}

bool GGUFLoader::LoadTensorRange(size_t start_idx, size_t count, std::vector<uint8_t>& data) {
    (void)start_idx;
    (void)count;
    data.clear();
    return true;
}

std::string GGUFLoader::GetTypeString(RawrXD::GGMLType type) const {
    switch (type) {
        case RawrXD::GGMLType::F32: return "F32";
        case RawrXD::GGMLType::F16: return "F16";
        case RawrXD::GGMLType::Q4_0: return "Q4_0";
        case RawrXD::GGMLType::Q4_1: return "Q4_1";
        case RawrXD::GGMLType::Q8_0: return "Q8_0";
        default: return "UNKNOWN";
    }
}

bool GGUFLoader::BuildTensorIndex() {
    return true;
}

bool GGUFLoader::LoadZone(const std::string& zone_name, uint64_t max_memory_mb) {
    (void)zone_name;
    (void)max_memory_mb;
    return true;
}

bool GGUFLoader::UnloadZone(const std::string& zone_name) {
    (void)zone_name;
    return true;
}

bool GGUFLoader::LoadTensorZone(const std::string& tensor_name, std::vector<uint8_t>& data) {
    (void)tensor_name;
    data.clear();
    return true;
}

uint64_t GGUFLoader::GetFileSize() const {
    return fileSize;
}

uint64_t GGUFLoader::GetCurrentMemoryUsage() const {
    return current_memory_usage_;
}

std::vector<std::string> GGUFLoader::GetLoadedZones() const {
    return loaded_zones_;
}

bool GGUFLoader::Load(VkDevice vkDevice, VkPhysicalDevice vkPhysDevice) {
    device = vkDevice;
    physDevice = vkPhysDevice;
    return true;
}

void GGUFLoader::CreateVulkanResources() {
    vulkanResourcesCreated_ = true;
}

bool GGUFLoader::SetCompressionType(CompressionType type) {
    compression_type_ = type;
    return true;
}

bool GGUFLoader::DecompressData(const std::vector<uint8_t>& in, std::vector<uint8_t>& out) {
    out = in;
    return true;
}

bool GGUFLoader::CompressData(const std::vector<uint8_t>& in, std::vector<uint8_t>& out) {
    out = in;
    return true;
}

bool GGUFLoader::HasUnsupportedQuantizationTypes() const {
    return !unsupported_types_structs_.empty();
}

std::vector<GGUFLoader::UnsupportedTypeInfo> GGUFLoader::GetUnsupportedQuantizationTypes() const {
    return unsupported_types_structs_;
}

std::string GGUFLoader::GetRecommendedConversionType() const {
    return "q4_k_m";
}

template <typename T>
bool GGUFLoader::ReadValue(T& val) {
    if (!file_.is_open()) {
        return false;
    }
    file_.read(reinterpret_cast<char*>(&val), sizeof(T));
    return file_.good();
}

bool GGUFLoader::ReadString(std::string& str) {
    str.clear();
    return true;
}

size_t GGUFLoader::CalculateTensorSize(const std::vector<uint64_t>& shape, RawrXD::GGMLType type) const {
    (void)type;
    if (shape.empty()) {
        return 0;
    }

    uint64_t elements = 1;
    for (uint64_t d : shape) {
        elements *= d;
    }
    return static_cast<size_t>(elements);
}

void GGUFLoader::LoadTensorAsync(RawrXD::TensorInfo& info) {
    (void)info;
}

void GGUFLoader::UploadF32(RawrXD::TensorInfo& info, void* src, size_t count) {
    (void)info;
    (void)src;
    (void)count;
}

void GGUFLoader::DequantAndUploadQ4_0(RawrXD::TensorInfo& info, void* src, size_t count) {
    (void)info;
    (void)src;
    (void)count;
}

void GGUFLoader::BeginCommandBuffer() {
    commandBufferActive_ = true;
}

void GGUFLoader::EndCommandBuffer() {
    commandBufferActive_ = false;
}

uint32_t GGUFLoader::FindMemoryType(uint32_t typeFilter, uint32_t props) {
    (void)typeFilter;
    (void)props;
    return 0;
}

uint32_t GGUFLoader::FindQueueFamilyIndex(VkPhysicalDevice device_, uint32_t queueFlags) {
    (void)device_;
    (void)queueFlags;
    return 0;
}
