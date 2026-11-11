$content = [IO.File]::ReadAllText("F:\rawrxd\tools\rawrxd_modelgenie_token0_execution.cpp")

# Fix 1: Replace type mapping with fail-closed 5-type mapping
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
    Write-Host "Fixed type mapping"
} else {
    Write-Host "Type mapping pattern NOT found"
}

# Fix 2: Replace encoded bytes with fail-closed
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
    Write-Host "Fixed encoded bytes"
} else {
    Write-Host "Encoded bytes pattern NOT found"
}

# Fix 3: Fix metadata parsing switch cases with braces
$old3 = @"
            switch (valueType)
            {
                case 0: ptr += 1; break;   // u8
                case 1: ptr += 1; break;   // i8
                case 2: ptr += 2; break;   // u16
                case 3: ptr += 2; break;   // i16
                case 4: ptr += 4; break;   // u32
                case 5: ptr += 4; break;   // i32
                case 6: ptr += 4; break;   // f32
                case 7: ptr += 1; break;   // bool
                case 8: 
                    if (ptr + 8 > base + size) return false;
                    uint64_t strLen = *reinterpret_cast<const uint64_t*>(ptr);
                    ptr += 8 + strLen;
                    break; // string
                case 9: 
                    if (ptr + 8 > base + size) return false;
                    uint64_t arrLen = *reinterpret_cast<const uint64_t*>(ptr);
                    ptr += 8;
                    // Skip array elements (simplified)
                    ptr += arrLen * 8; // assume u64
                    break; // array
                default: return false;
            }
"

$new3 = @"
            switch (valueType)
            {
                case 0: ptr += 1; break;   // u8
                case 1: ptr += 1; break;   // i8
                case 2: ptr += 2; break;   // u16
                case 3: ptr += 2; break;   // i16
                case 4: ptr += 4; break;   // u32
                case 5: ptr += 4; break;   // i32
                case 6: ptr += 4; break;   // f32
                case 7: ptr += 1; break;   // bool
                case 8: 
                {
                    if (ptr + 8 > base + size) return false;
                    uint64_t strLen = *reinterpret_cast<const uint64_t*>(ptr);
                    ptr += 8;
                    if (strLen > static_cast<uint64_t>(base + size - ptr))
                        return false;
                    ptr += strLen;
                    break; // string
                }
                case 9: 
                {
                    if (ptr + 8 > base + size) return false;
                    uint64_t arrLen = *reinterpret_cast<const uint64_t*>(ptr);
                    ptr += 8;
                    if (ptr + 4 > base + size) return false;
                    uint32_t elemType = *reinterpret_cast<const uint32_t*>(ptr);
                    ptr += 4;
                    // Array element size lookup (GGUF type -> bytes)
                    uint64_t elemSize = 0;
                    switch (elemType) {
                        case 0: case 1: elemSize = 1; break; // u8/i8
                        case 2: case 3: elemSize = 2; break; // u16/i16
                        case 4: case 5: case 6: elemSize = 4; break; // u32/i32/f32
                        case 7: elemSize = 1; break; // bool
                        case 8: 
                            if (ptr + 8 > base + size) return false;
                            elemSize = 8; 
                            ptr += 8; // nested string length then skipped
                            break;
                        case 9: elemSize = 8; break; // array (pointer)
                        default: return false;
                    }
                    if (arrLen > static_cast<uint64_t>(base + size - ptr) / elemSize)
                        return false;
                    ptr += arrLen * elemSize;
                    break; // array
                }
                default: return false;
            }
"

if ($content.Contains($old3)) {
    $content = $content.Replace($old3, $new3)
    Write-Host "Fixed metadata parsing"
} else {
    Write-Host "Metadata parsing pattern NOT found"
}

# Fix 4: Add liveTypeMap_ to ModelExportRuntime class
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
    std::unordered_map<Generated::TensorId, TensorView> viewMap_
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
    Write-Host "Added liveTypeMap_ to class"
} else {
    Write-Host "Class definition pattern NOT found"
}

[IO.File]::WriteAllText("F:\rawrxd\tools\rawrxd_modelgenie_token0_execution.cpp", $content)
Write-Host "Applied all fixes"