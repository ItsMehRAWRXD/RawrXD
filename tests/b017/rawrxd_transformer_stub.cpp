// ============================================================================
// rawrxd_transformer_stub.cpp — Minimal stub for B017 host certification
// ============================================================================
#include "rawrxd_transformer_minimal.h"
#include <vector>

bool RawrXDTransformer::Initialize(void*, void*, const Config& cfg, RawrXDModelLoader*)
{
    config_ = cfg;
    initialized_ = true;
    return true;
}

std::vector<float> RawrXDTransformer::Forward(const std::vector<uint32_t>&, int)
{
    if (!initialized_) return {};
    return std::vector<float>(config_.vocab_size, 0.0f);
}

std::vector<float> RawrXDTransformer::ForwardBatch(const std::vector<uint32_t>&, int)
{
    if (!initialized_) return {};
    return std::vector<float>(config_.vocab_size, 0.0f);
}

bool RawrXDModelLoader::Load(const wchar_t*, void*, void*)
{
    return true;
}

float* RawrXDModelLoader::GetTensor(const std::string&)
{
    return nullptr;
}

bool RawrXDModelLoader::GetTensorRow(const std::string&, size_t, float*, size_t)
{
    return false;
}

void RawrXDModelLoader::ReleaseTensor(const std::string&)
{
}

bool RawrXDTokenizer::Load(const char*)
{
    return true;
}

std::vector<uint32_t> RawrXDTokenizer::Encode(const std::string&)
{
    return {1};
}
