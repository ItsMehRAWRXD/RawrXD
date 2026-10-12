$content = [IO.File]::ReadAllText("F:\rawrxd\tools\rawrxd_modelgenie_token0_execution.cpp")

# ==========================================
# FIX 1: GGUF parser - 5-type fail-closed mapping
# ==========================================
$old1 = @"
            // Map GGML type ID to ModelGenie::GGMLType
            ModelGenie::GGMLType type = ModelGenie::GGMLType::F32;
            switch (typeId)
            {
                case 0: type = ModelGenie::GGMLType::F32; break;
                case 1: type = ModelGenie::GGMLType::Q4_K; break;
                case 2: type = ModelGenie::GGMLType::Q4_0; break;
                case 3: type = ModelGenie::GGMLType::Q4_1; break;
                case 4: type = ModelGenie::GGMLType::Q5_0; break;
                case 5: type = ModelGenie::GGMLType::Q5_1; break;
                case 6: type = ModelGenie::GGMLType::Q8_0; break;
                case 7: type = ModelGenie::GGMLType::Q8_1; break;
                case 8: type = ModelGenie::GGMLType::Q2_K; break;
                case 9: type = ModelGenie::GGMLType::Q3_K; break;
                case 10: type = ModelGenie::GGMLType::Q4_K; break;
                case 11: type = ModelGenie::GGMLType::Q5_K; break;
                case 12: type = ModelGenie::GGMLType::Q6_K; break;
                case 13: type = ModelGenie::GGMLType::Q8_K; break;
                case 14: type = ModelGenie::GGMLType::F16_HALF; break;
                case 15: type = ModelGenie::GGMLType::F32; break;
                case 16: type = ModelGenie::GGMLType::Q2_K; break;
                case 17: type = ModelGenie::GGMLType::Q3_K; break;
                case 18: type = ModelGenie::GGMLType::Q4_K; break;
                case 19: type = ModelGenie::GGMLType::Q5_K; break;
                case 20: type = ModelGenie::GGMLType::Q6_K; break;
                case 21: type = ModelGenie::GGMLType::F16_HALF; break;
                default: type = ModelGenie::GGMLType::F32; break;
            }
"
$new1 = @"
            // Map GGML type ID to ModelGenie::GGMLType (fail-closed: only 5 supported types)
            ModelGenie::GGMLType type;
            switch (typeId)
            {
                case 0:   // GGML_TYPE_F32
                    type = ModelGenie::GGMLType::F32;
                    break;
                case 6:   // GGML_TYPE_Q5_0
                    type = ModelGenie::GGMLType::Q5_0;
                    break;
                case 8:   // GGML_TYPE_Q8_0
                    type = ModelGenie::GGMLType::Q8_0;
                    break;
                case 12:  // GGML_TYPE_Q4_K
                    type = ModelGenie::GGMLType::Q4_K;
                    break;
                case 14:  // GGML_TYPE_Q6_K
                    type = ModelGenie::GGMLType::Q6_K;
                    break;
                default:
                    std::fprintf(stderr,
                        "[GGUF] Unsupported tensor type: tensor=%s raw_type=%u\n",
                        name.c_str(),
                        typeId);
                    return false;
            }
"

if ($content.Contains($old1)) {
    $content = $content.Replace($old1, $new1)
    Write-Host "FIX 1: Applied 5-type GGUF mapping"
} else {
    Write-Host "FIX 1: Pattern NOT found"
}

# ==========================================
# FIX 2: Encoded bytes with fail-closed validation
# ==========================================
$old2 = @"
            // Calculate encoded bytes from dims and type
            uint64_t elementCount = 1;
            for (auto d : dims) elementCount *= d;
            
            uint64_t encodedBytes = 0;
            switch (type)
            {
                case ModelGenie::GGMLType::F32: encodedBytes = elementCount * 4; break;
                case ModelGenie::GGMLType::F16_HALF: encodedBytes = elementCount * 2; break;
                case ModelGenie::GGMLType::Q4_K: encodedBytes = (elementCount + 255) / 256 * 144; break;
                case ModelGenie::GGMLType::Q5_K: encodedBytes = (elementCount + 255) / 256 * 168; break;
                case ModelGenie::GGMLType::Q6_K: encodedBytes = (elementCount + 255) / 256 * 210; break;
                case ModelGenie::GGMLType::Q8_0: encodedBytes = (elementCount + 31) / 32 * 34; break;
                default: encodedBytes = elementCount * 2; break;
            }
"
$new2 = @"
            // Calculate encoded bytes from dims and type (fail-closed)
            uint64_t elementCount = 1;
            for (auto d : dims) elementCount *= d;
            
            uint64_t encodedBytes = 0;
            switch (type)
            {
                case ModelGenie::GGMLType::F32:
                    encodedBytes = elementCount * 4;
                    break;
                case ModelGenie::GGMLType::Q5_0:
                    if (elementCount % 32 != 0) return false;
                    encodedBytes = (elementCount / 32) * 22;
                    break;
                case ModelGenie::GGMLType::Q8_0:
                    if (elementCount % 32 != 0) return false;
                    encodedBytes = (elementCount / 32) * 34;
                    break;
                case ModelGenie::GGMLType::Q4_K:
                    if (elementCount % 256 != 0) return false;
                    encodedBytes = (elementCount / 256) * 144;
                    break;
                case ModelGenie::GGMLType::Q6_K:
                    if (elementCount % 256 != 0) return false;
                    encodedBytes = (elementCount / 256) * 210;
                    break;
                default:
                    return false;
            }
"

if ($content.Contains($old2)) {
    $content = $content.Replace($old2, $new2)
    Write-Host "FIX 2: Applied encoded bytes validation"
} else {
    Write-Host "FIX 2: Pattern NOT found"
}

# ==========================================
# FIX 3: Metadata parsing - remove extra ptr += 4
# ==========================================
$old3 = @"
            if (ptr + 8 > base + size) return false;
            uint32_t valueType = *reinterpret_cast<const uint32_t*>(ptr);
            ptr += 4;
            if (ptr + 4 > base + size) return false;
            ptr += 4; // skip value type and padding?
            
            // Skip value based on type (simplified - just advance ptr)
            // This is a minimal parser; real implementation would decode each type
            // For now, we assume standard metadata and advance appropriately
            switch (valueType)
"
$new3 = @"
            if (ptr + 8 > base + size) return false;
            uint32_t valueType = *reinterpret_cast<const uint32_t*>(ptr);
            ptr += 4;
            
            // Skip value based on type (simplified - just advance ptr)
            // This is a minimal parser; real implementation would decode each type
            // For now, we assume standard metadata and advance appropriately
            switch (valueType)
"

if ($content.Contains($old3)) {
    $content = $content.Replace($old3, $new3)
    Write-Host "FIX 3: Removed extra ptr += 4 in metadata parsing"
} else {
    Write-Host "FIX 3: Pattern NOT found"
}

# ==========================================
# FIX 4: Add liveTypeMap_ to ModelExportRuntime class
# ==========================================
$old4 = @"
class ModelExportRuntime
{
  public:
    std::vector<TensorView> views_;
    std::unordered_map<Generated::TensorId, TensorView> viewMap_;
    std::vector<float> hidden_;
    std::vector<float> logits_;

    // Execution tracking for RAWRXD_MODELGENIE_TOKEN0_EXECUTION_001
    uint32_t opsExecuted_ = 0;
    uint32_t stubPaths_ = 0;
    uint32_t zeroFillFallbacks_ = 0;
    uint32_t syntheticOutputs_ = 0;
    uint32_t quantDecodes_ = 0;
    uint32_t mlaOps_ = 0;
    uint32_t moeOps_ = 0;
    uint32_t finalNormExecuted_ = 0;
    uint32_t lmHeadExecuted_ = 0;
    bool executionIrConsumed_ = false;
"

$new4 = @"
class ModelExportRuntime
{
  public:
    std::vector<TensorView> views_;
    std::unordered_map<Generated::TensorId, TensorView> viewMap_;
    std::vector<float> hidden_;
    std::vector<float> logits_;

    // Live GGUF tensor type map (for dequant type correction)
    std::unordered_map<std::string, ModelGenie::GGMLType> liveTypeMap_;

    // Execution tracking for RAWRXD_MODELGENIE_TOKEN0_EXECUTION_001
    uint32_t opsExecuted_ = 0;
    uint32_t stubPaths_ = 0;
    uint32_t zeroFillFallbacks_ = 0;
    uint32_t syntheticOutputs_ = 0;
    uint32_t quantDecodes_ = 0;
    uint32_t mlaOps_ = 0;
    uint32_t moeOps_ = 0;
    uint32_t finalNormExecuted_ = 0;
    uint32_t lmHeadExecuted_ = 0;
    bool executionIrConsumed_ = false;
"

if ($content.Contains($old4)) {
    $content = $content.Replace($old4, $new4)
    Write-Host "FIX 4: Added liveTypeMap_ to ModelExportRuntime"
} else {
    Write-Host "FIX 4: Pattern NOT found"
}

# ==========================================
# FIX 5: DequantizeTensor with liveTypeMap parameter
# ==========================================
$old5 = @"
void DequantizeTensor(const TensorView& tv, std::vector<float>& out)
{
    // Use live GGUF type if available, otherwise fall back to generated type
    ModelGenie::GGMLType effectiveType = tv.type;
    if (tv.name && !liveTypeMap_.empty())
    {
        auto it = liveTypeMap_.find(tv.name);
        if (it != liveTypeMap_.end())
        {
            effectiveType = it->second;
        }
    }
"
$new5 = @"
void DequantizeTensor(const TensorView& tv, std::vector<float>& out,
                       const std::unordered_map<std::string, ModelGenie::GGMLType>& liveTypeMap)
{
    // Use live GGUF type if available, otherwise fall back to generated type
    ModelGenie::GGMLType effectiveType = tv.type;
    if (tv.name && !liveTypeMap.empty())
    {
        auto it = liveTypeMap.find(tv.name);
        if (it != liveTypeMap.end())
        {
            effectiveType = it->second;
        }
    }
"

if ($content.Contains($old5)) {
    $content = $content.Replace($old5, $new5)
    Write-Host "FIX 5: Updated DequantizeTensor signature"
} else {
    Write-Host "FIX 5: Pattern NOT found"
}

# ==========================================
# FIX 6: BindTensor using ggufDataOffset
# ==========================================
$old6 = @"
// Tensor Binding
//=============================================================================
static TensorView BindTensor(const Generated::TensorROM& rom, const GGUFROM& romFile)
{
    // GGUF tensor offsets in TensorROM are relative to the GGUF data section start.
    // The generated dataOffset field stores that relative offset.
    // Convert to absolute file offset by adding ModelConfig::kDataStart.
    uint64_t absoluteOffset = Generated::ModelConfig::kDataStart + rom.dataOffset;
    fprintf(stderr, "[BindTensor] name=%s dataOffset=%llu kDataStart=%llu absoluteOffset=%llu\n",
        rom.name,
        (unsigned long long)rom.dataOffset,
        (unsigned long long)Generated::ModelConfig::kDataStart,
        (unsigned long long)absoluteOffset);
    fflush(stderr);
    if (absoluteOffset > romFile.size || rom.encodedBytes > romFile.size - absoluteOffset)
    {
        throw std::runtime_error("TensorROM range outside model ROM");
    }

    return {static_cast<Generated::TensorId>(rom.tensorId),
            romFile.base + absoluteOffset,
            rom.encodedBytes,
            rom.type,
            rom.dims.data(),
            rom.rank,
            rom.elementCount,
            rom.name};
"
$new6 = @"
// Tensor Binding
//=============================================================================
static TensorView BindTensor(const Generated::TensorROM& rom, const GGUFROM& romFile)
{
    // GGUF tensor offsets in TensorROM are relative to the GGUF data section start.
    // The generated dataOffset field stores that relative offset.
    // Use the live GGUF's data section start for correct physical addressing.
    uint64_t absoluteOffset = romFile.ggufDataOffset + rom.dataOffset;
    fprintf(stderr, "[BindTensor] name=%s dataOffset=%llu ggufDataOffset=%llu absoluteOffset=%llu\n",
        rom.name,
        (unsigned long long)rom.dataOffset,
        (unsigned long long)romFile.ggufDataOffset,
        (unsigned long long)absoluteOffset);
    fflush(stderr);
    if (absoluteOffset > romFile.size || rom.encodedBytes > romFile.size - absoluteOffset)
    {
        throw std::runtime_error("TensorROM range outside model ROM");
    }

    return {static_cast<Generated::TensorId>(rom.tensorId),
            romFile.base + absoluteOffset,
            rom.encodedBytes,
            rom.type,
            rom.dims.data(),
            rom.rank,
            rom.elementCount,
            rom.name};
"

if ($content.Contains($old6)) {
    $content = $content.Replace($old6, $new6)
    Write-Host "FIX 6: Updated BindTensor to use ggufDataOffset"
} else {
    Write-Host "FIX 6: Pattern NOT found"
}

# ==========================================
# FIX 7: ExecuteMLADecompressForward latentDim = weightElements / inputDim
# ==========================================
$old7 = @"
    // Step 1: Project input to latent space via kv_a_mqa
    // kvAMqaW layout: [kv_lora_rank, inputDim] or [inputDim, kv_lora_rank] depending on storage
    uint32_t latentDim = 0;
    if (kvAMqa.rank >= 2) {
        latentDim = kvAMqa.dims[0];
    }
    
    if (latentDim == 0) {
        return std::vector<float>(outputDim, 0.0f);
    }
"
$new7 = @"
    // Step 1: Project input to latent space via kv_a_mqa
    // kvAMqaW layout: [kv_lora_rank, inputDim] or [inputDim, kv_lora_rank] depending on storage
    // latentDim = total_weight_elements / inputDim (must be exact division)
    if (inputDim == 0) {
        std::fprintf(stderr, "[IR][MLA] inputDim is zero\n");
        fflush(stderr);
        return std::vector<float>(outputDim, 0.0f);
    }
    if (kvAMqaW.empty() || (kvAMqaW.size() % inputDim) != 0) {
        std::fprintf(stderr,
            "[IR][MLA] kv_a_mqa weight shape incompatible: weightElements=%zu inputDim=%u\n",
            kvAMqaW.size(), inputDim);
        fflush(stderr);
        return std::vector<float>(outputDim, 0.0f);
    }

    const uint32_t latentDim = static_cast<uint32_t>(kvAMqaW.size() / inputDim);
    if (latentDim == 0) {
        std::fprintf(stderr, "[IR][MLA] derived latentDim is zero\n");
        fflush(stderr);
        return std::vector<float>(outputDim, 0.0f);
    }

    std::fprintf(stderr,
        "[IR][MLA] inputDim=%u weightElements=%zu latentDim=%u\n",
        inputDim, kvAMqaW.size(), latentDim);
    fflush(stderr);
"

if ($content.Contains($old7)) {
    $content = $content.Replace($old7, $new7)
    Write-Host "FIX 7: Applied MLA latentDim fix (weightElements / inputDim)"
} else {
    Write-Host "FIX 7: Pattern NOT found"
}

# ==========================================
# Write the fixed file
# ==========================================
[IO.File]::WriteAllText("F:\rawrxd\tools\rawrxd_modelgenie_token0_execution.cpp", $content)
Write-Host "All fixes applied"