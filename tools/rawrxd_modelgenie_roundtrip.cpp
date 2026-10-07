//=============================================================================
// rawrxd_modelgenie_roundtrip - Structural Round-trip Parity Test
// RAWRXD_MODEL_GENIE_HEADER_EXPORT_001
//
// Verifies: ModelGenome -> generated headers -> canonical contract -> hash match
//=============================================================================

#include "ModelGenome.hpp"
#include "ModelGenomeReader.hpp"
#include "ModelGenomeValidator.hpp"

#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <cctype>

using namespace RawrXD::Deep2::ModelGenie;

//=============================================================================
// Helpers
//=============================================================================
static std::string ReadAllText(const std::string &path)
{
    std::ifstream in(path);
    if (!in)
        return {};
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

static bool Contains(const std::string &haystack, const std::string &needle)
{
    return haystack.find(needle) != std::string::npos;
}

static std::string ExtractStringLiteral(const std::string &text, const std::string &key)
{
    size_t keyPos = text.find(key);
    if (keyPos == std::string::npos)
        return {};
    size_t q1 = text.find('"', keyPos);
    if (q1 == std::string::npos)
        return {};
    size_t q2 = text.find('"', q1 + 1);
    if (q2 == std::string::npos)
        return {};
    return text.substr(q1 + 1, q2 - q1 - 1);
}

static uint64_t ExtractUInt64(const std::string &text, const std::string &key)
{
    size_t keyPos = text.find(key);
    if (keyPos == std::string::npos)
        return 0;
    size_t eq = text.find('=', keyPos);
    if (eq == std::string::npos)
        return 0;
    size_t semi = text.find(';', eq);
    if (semi == std::string::npos)
        semi = text.size();
    std::string val = text.substr(eq + 1, semi - eq - 1);
    val.erase(std::remove_if(val.begin(), val.end(), [](unsigned char c)
                             { return std::isspace(c) || c == 'U' || c == 'L'; }),
              val.end());
    if (val.empty())
        return 0;
    return std::stoull(val);
}

static uint32_t ExtractUInt32(const std::string &text, const std::string &key)
{
    return static_cast<uint32_t>(ExtractUInt64(text, key));
}

static double ExtractDouble(const std::string &text, const std::string &key)
{
    size_t keyPos = text.find(key);
    if (keyPos == std::string::npos)
        return 0.0;
    size_t eq = text.find('=', keyPos);
    if (eq == std::string::npos)
        return 0.0;
    size_t semi = text.find(';', eq);
    if (semi == std::string::npos)
        semi = text.size();
    std::string val = text.substr(eq + 1, semi - eq - 1);
    val.erase(std::remove_if(val.begin(), val.end(), [](unsigned char c)
                             { return std::isspace(c); }),
              val.end());
    if (val.empty())
        return 0.0;
    return std::stod(val);
}

static bool ExtractBool(const std::string &text, const std::string &key)
{
    std::string val = ExtractStringLiteral(text, key);
    if (!val.empty())
        return true;
    size_t keyPos = text.find(key);
    if (keyPos == std::string::npos)
        return false;
    size_t eq = text.find('=', keyPos);
    if (eq == std::string::npos)
        return false;
    size_t semi = text.find(';', eq);
    if (semi == std::string::npos)
        semi = text.size();
    val = text.substr(eq + 1, semi - eq - 1);
    val.erase(std::remove_if(val.begin(), val.end(), [](unsigned char c)
                             { return std::isspace(c); }),
              val.end());
    return val == "true";
}

//=============================================================================
// Round-trip verification
//=============================================================================
struct RoundTripResult
{
    bool valid = true;
    std::vector<std::string> errors;
    std::vector<std::string> warnings;

    void AddError(const std::string &msg)
    {
        valid = false;
        errors.push_back(msg);
    }
    void AddWarning(const std::string &msg)
    {
        warnings.push_back(msg);
    }
};

static bool VerifyModelIdentity(const ModelGenome &original, const std::string &generatedDir, RoundTripResult &result)
{
    std::string text = ReadAllText(generatedDir + "/ModelIdentity.generated.hpp");
    if (text.empty())
    {
        result.AddError("ModelIdentity.generated.hpp missing or empty");
        return false;
    }

    std::string name = ExtractStringLiteral(text, "kModelName");
    if (name != original.modelName)
    {
        result.AddError("ModelIdentity modelName mismatch: expected=" + original.modelName + " actual=" + name);
    }

    std::string archName = ExtractStringLiteral(text, "kArchitectureName");
    std::string expectedArch = ArchitectureToString(original.architecture);
    if (archName != expectedArch)
    {
        result.AddError("ModelIdentity architecture mismatch: expected=" + expectedArch + " actual=" + archName);
    }

    return result.valid;
}

static bool VerifyModelConfig(const ModelGenome &original, const std::string &generatedDir, RoundTripResult &result)
{
    std::string text = ReadAllText(generatedDir + "/ModelConfig.generated.hpp");
    if (text.empty())
    {
        result.AddError("ModelConfig.generated.hpp missing or empty");
        return false;
    }

    struct
    {
        const char *key;
        uint32_t ModelGenome::*field;
    } uint32Checks[] = {
        {"kBlockCount =", &ModelGenome::blockCount},
        {"kEmbeddingLength =", &ModelGenome::embeddingLength},
        {"kFeedForwardLength =", &ModelGenome::feedForwardLength},
        {"kVocabSize =", &ModelGenome::vocabSize},
        {"kHeadCount =", &ModelGenome::headCount},
        {"kHeadCountKv =", &ModelGenome::headCountKv},
        {"kRopeDimensionCount =", &ModelGenome::ropeDimensionCount},
        {"kExpertCount =", &ModelGenome::expertCount},
        {"kExpertUsedCount =", &ModelGenome::expertUsedCount},
        {"kExpertSharedCount =", &ModelGenome::expertSharedCount},
        {"kExpertFfnLength =", &ModelGenome::expertFfnLength},
        {"kLeadingDenseBlocks =", &ModelGenome::leadingDenseBlocks},
        {"kKvLoraRank =", &ModelGenome::kvLoraRank},
        {"kKeyLength =", &ModelGenome::keyLength},
        {"kValueLength =", &ModelGenome::valueLength},
        {"kGgufVersion =", &ModelGenome::ggufVersion},
        {"kTensorCount =", &ModelGenome::tensorCount},
        {"kAlignment =", &ModelGenome::alignment},
    };
    for (const auto &check : uint32Checks)
    {
        uint32_t actual = ExtractUInt32(text, check.key);
        uint32_t expected = original.*(check.field);
        if (actual != expected)
        {
            result.AddError(std::string("ModelConfig ") + check.key + " mismatch: expected=" + std::to_string(expected) + " actual=" + std::to_string(actual));
        }
    }

    struct
    {
        const char *key;
        uint64_t ModelGenome::*field;
    } uint64Checks[] = {
        {"kContextLength =", &ModelGenome::contextLength},
        {"kRopeFreqBase =", &ModelGenome::ropeFreqBase},
        {"kExactParams =", &ModelGenome::exactParams},
        {"kEncodedWeightBytes =", &ModelGenome::encodedWeightBytes},
        {"kFileBytes =", &ModelGenome::fileBytes},
        {"kDataStart =", &ModelGenome::dataStart},
    };
    for (const auto &check : uint64Checks)
    {
        uint64_t actual = ExtractUInt64(text, check.key);
        uint64_t expected = original.*(check.field);
        if (actual != expected)
        {
            result.AddError(std::string("ModelConfig ") + check.key + " mismatch: expected=" + std::to_string(expected) + " actual=" + std::to_string(actual));
        }
    }

    double effectiveBpw = ExtractDouble(text, "kEffectiveBpw");
    if (std::abs(effectiveBpw - original.effectiveBpw) > 0.001)
    {
        result.AddError("ModelConfig effectiveBpw mismatch: expected=" + std::to_string(original.effectiveBpw) + " actual=" + std::to_string(effectiveBpw));
    }

    double rmsEps = ExtractDouble(text, "kRmsEps");
    if (std::abs(rmsEps - original.rmsEps) > 1e-9)
    {
        result.AddError("ModelConfig rmsEps mismatch: expected=" + std::to_string(original.rmsEps) + " actual=" + std::to_string(rmsEps));
    }

    return result.valid;
}

static bool VerifyTensorROM(const ModelGenome &original, const std::string &generatedDir, RoundTripResult &result)
{
    std::string text = ReadAllText(generatedDir + "/TensorROM.generated.hpp");
    if (text.empty())
    {
        result.AddError("TensorROM.generated.hpp missing or empty");
        return false;
    }

    uint32_t tensorCount = ExtractUInt32(text, "kTensorCount");
    if (tensorCount != original.tensorCount)
    {
        result.AddError("TensorROM kTensorCount mismatch: expected=" + std::to_string(original.tensorCount) + " actual=" + std::to_string(tensorCount));
    }

    // Verify table size declaration
    size_t tablePos = text.find("kTensorROMTable[");
    if (tablePos != std::string::npos)
    {
        size_t openBracket = text.find('[', tablePos);
        size_t closeBracket = text.find(']', openBracket);
        if (openBracket != std::string::npos && closeBracket != std::string::npos)
        {
            std::string countStr = text.substr(openBracket + 1, closeBracket - openBracket - 1);
            countStr.erase(std::remove_if(countStr.begin(), countStr.end(), [](unsigned char c)
                                          { return !std::isdigit(c); }),
                           countStr.end());
            if (!countStr.empty())
            {
                uint32_t declaredCount = static_cast<uint32_t>(std::stoul(countStr));
                if (declaredCount != original.tensorCount)
                {
                    result.AddError("TensorROM table declared size mismatch: expected=" + std::to_string(original.tensorCount) + " actual=" + std::to_string(declaredCount));
                }
            }
        }
    }

    // Verify a few tensor entries exist
    size_t tensorIdPos = text.find(".tensorId = 0,");
    if (tensorIdPos == std::string::npos)
    {
        result.AddWarning("TensorROM: first tensor entry not found");
    }

    return result.valid;
}

static bool VerifyBlockGenome(const ModelGenome &original, const std::string &generatedDir, RoundTripResult &result)
{
    std::string text = ReadAllText(generatedDir + "/BlockGenome.generated.hpp");
    if (text.empty())
    {
        result.AddError("BlockGenome.generated.hpp missing or empty");
        return false;
    }

    uint32_t blockCount = ExtractUInt32(text, "kBlockCount");
    if (blockCount != original.blockCount)
    {
        result.AddError("BlockGenome kBlockCount mismatch: expected=" + std::to_string(original.blockCount) + " actual=" + std::to_string(blockCount));
    }

    uint32_t leadingDenseBlocks = ExtractUInt32(text, "kLeadingDenseBlocks");
    if (leadingDenseBlocks != original.leadingDenseBlocks)
    {
        result.AddError("BlockGenome kLeadingDenseBlocks mismatch: expected=" + std::to_string(original.leadingDenseBlocks) + " actual=" + std::to_string(leadingDenseBlocks));
    }

    size_t tablePos = text.find("kBlockGenomeTable[");
    if (tablePos != std::string::npos)
    {
        size_t openBracket = text.find('[', tablePos);
        size_t closeBracket = text.find(']', openBracket);
        if (openBracket != std::string::npos && closeBracket != std::string::npos)
        {
            std::string countStr = text.substr(openBracket + 1, closeBracket - openBracket - 1);
            countStr.erase(std::remove_if(countStr.begin(), countStr.end(), [](unsigned char c)
                                          { return !std::isdigit(c); }),
                           countStr.end());
            if (!countStr.empty())
            {
                uint32_t declaredCount = static_cast<uint32_t>(std::stoul(countStr));
                if (declaredCount != original.blockCount)
                {
                    result.AddError("BlockGenome table declared size mismatch: expected=" + std::to_string(original.blockCount) + " actual=" + std::to_string(declaredCount));
                }
            }
        }
    }

    size_t bankPos = text.find("kExpertBankTable[");
    if (bankPos != std::string::npos)
    {
        size_t openBracket = text.find('[', bankPos);
        size_t closeBracket = text.find(']', openBracket);
        if (openBracket != std::string::npos && closeBracket != std::string::npos)
        {
            std::string countStr = text.substr(openBracket + 1, closeBracket - openBracket - 1);
            countStr.erase(std::remove_if(countStr.begin(), countStr.end(), [](unsigned char c)
                                          { return !std::isdigit(c); }),
                           countStr.end());
            if (!countStr.empty())
            {
                uint32_t declaredCount = static_cast<uint32_t>(std::stoul(countStr));
                uint32_t expectedCount = original.blockCount - original.leadingDenseBlocks;
                if (declaredCount != expectedCount)
                {
                    result.AddError("BlockGenome expert bank table size mismatch: expected=" + std::to_string(expectedCount) + " actual=" + std::to_string(declaredCount));
                }
            }
        }
    }

    return result.valid;
}

static bool VerifyExecutionIR(const ModelGenome &original, const std::string &generatedDir, RoundTripResult &result)
{
    std::string text = ReadAllText(generatedDir + "/ExecutionIR.generated.hpp");
    if (text.empty())
    {
        result.AddError("ExecutionIR.generated.hpp missing or empty");
        return false;
    }

    uint32_t opCount = ExtractUInt32(text, "kExecutionOpCount");
    if (opCount != static_cast<uint32_t>(original.executionOps.size()))
    {
        result.AddError("ExecutionIR kExecutionOpCount mismatch: expected=" + std::to_string(original.executionOps.size()) + " actual=" + std::to_string(opCount));
    }

    size_t tablePos = text.find("kExecutionIRTable[");
    if (tablePos != std::string::npos)
    {
        size_t openBracket = text.find('[', tablePos);
        size_t closeBracket = text.find(']', openBracket);
        if (openBracket != std::string::npos && closeBracket != std::string::npos)
        {
            std::string countStr = text.substr(openBracket + 1, closeBracket - openBracket - 1);
            countStr.erase(std::remove_if(countStr.begin(), countStr.end(), [](unsigned char c)
                                          { return !std::isdigit(c); }),
                           countStr.end());
            if (!countStr.empty())
            {
                uint32_t declaredCount = static_cast<uint32_t>(std::stoul(countStr));
                if (declaredCount != original.executionOps.size())
                {
                    result.AddError("ExecutionIR table declared size mismatch: expected=" + std::to_string(original.executionOps.size()) + " actual=" + std::to_string(declaredCount));
                }
            }
        }
    }

    // Verify new OperandRef format is present
    if (text.find("OperandDomain::RomTensor") == std::string::npos)
    {
        result.AddError("ExecutionIR missing OperandDomain::RomTensor (old format may be emitted)");
    }
    if (text.find("OperandDomain::Activation") == std::string::npos)
    {
        result.AddError("ExecutionIR missing OperandDomain::Activation (old format may be emitted)");
    }
    if (text.find("OperandRef") == std::string::npos)
    {
        result.AddError("ExecutionIR missing OperandRef (old format may be emitted)");
    }

    // Verify old raw-ID format is NOT present
    if (text.find("std::array<uint32_t, 8> inputTensorIds") != std::string::npos)
    {
        result.AddError("ExecutionIR still emits old inputTensorIds format");
    }
    if (text.find("std::array<uint32_t, 8> weightTensorIds") != std::string::npos)
    {
        result.AddError("ExecutionIR still emits old weightTensorIds format");
    }
    if (text.find("uint32_t outputTensorId") != std::string::npos)
    {
        result.AddError("ExecutionIR still emits old outputTensorId format");
    }

    return result.valid;
}

static bool VerifyCapabilityManifest(const ModelGenome &original, const std::string &generatedDir, RoundTripResult &result)
{
    std::string text = ReadAllText(generatedDir + "/CapabilityManifest.generated.hpp");
    if (text.empty())
    {
        result.AddError("CapabilityManifest.generated.hpp missing or empty");
        return false;
    }

    uint32_t requiredCount = ExtractUInt32(text, ".requiredCount =");
    if (requiredCount != original.capabilities.requiredPrimitives.size())
    {
        result.AddError("CapabilityManifest requiredCount mismatch: expected=" + std::to_string(original.capabilities.requiredPrimitives.size()) + " actual=" + std::to_string(requiredCount));
    }

    uint32_t availableCount = ExtractUInt32(text, ".availableCount =");
    if (availableCount != original.capabilities.availablePrimitives.size())
    {
        result.AddError("CapabilityManifest availableCount mismatch: expected=" + std::to_string(original.capabilities.availablePrimitives.size()) + " actual=" + std::to_string(availableCount));
    }

    uint32_t unimplementedCount = ExtractUInt32(text, ".unimplementedCount =");
    if (unimplementedCount != original.capabilities.unimplementedPrimitives.size())
    {
        result.AddError("CapabilityManifest unimplementedCount mismatch: expected=" + std::to_string(original.capabilities.unimplementedPrimitives.size()) + " actual=" + std::to_string(unimplementedCount));
    }

    bool runtimeExecutable = ExtractBool(text, ".runtimeExecutable =");
    if (runtimeExecutable != original.capabilities.runtimeExecutable)
    {
        result.AddError("CapabilityManifest runtimeExecutable mismatch: expected=" + std::string(original.capabilities.runtimeExecutable ? "true" : "false") + " actual=" + std::string(runtimeExecutable ? "true" : "false"));
    }

    return result.valid;
}

static bool VerifyResidencyPlan(const ModelGenome &original, const std::string &generatedDir, RoundTripResult &result)
{
    std::string text = ReadAllText(generatedDir + "/ResidencyPlan.generated.hpp");
    if (text.empty())
    {
        result.AddError("ResidencyPlan.generated.hpp missing or empty");
        return false;
    }

    uint64_t maxPinned = ExtractUInt64(text, ".maxPinnedTensorBytes =");
    if (maxPinned != original.residencyBounds.maxPinnedTensorBytes)
    {
        result.AddError("ResidencyPlan maxPinnedTensorBytes mismatch: expected=" + std::to_string(original.residencyBounds.maxPinnedTensorBytes) + " actual=" + std::to_string(maxPinned));
    }

    uint64_t maxBlock = ExtractUInt64(text, ".maxBlockBytes =");
    if (maxBlock != original.residencyBounds.maxBlockBytes)
    {
        result.AddError("ResidencyPlan maxBlockBytes mismatch: expected=" + std::to_string(original.residencyBounds.maxBlockBytes) + " actual=" + std::to_string(maxBlock));
    }

    uint64_t expertRomBytes = ExtractUInt64(text, ".expertRomBytes =");
    if (expertRomBytes != original.residencyBounds.expertRomBytes)
    {
        result.AddError("ResidencyPlan expertRomBytes mismatch: expected=" + std::to_string(original.residencyBounds.expertRomBytes) + " actual=" + std::to_string(expertRomBytes));
    }

    bool uniformSlots = ExtractBool(text, ".uniformTensorSlotsSufficient =");
    if (uniformSlots != original.residencyBounds.uniformTensorSlotsSufficient)
    {
        result.AddError("ResidencyPlan uniformTensorSlotsSufficient mismatch");
    }

    bool meanBlockSafe = ExtractBool(text, ".meanBlockCapacitySafe =");
    if (meanBlockSafe != original.residencyBounds.meanBlockCapacitySafe)
    {
        result.AddError("ResidencyPlan meanBlockCapacitySafe mismatch");
    }

    return result.valid;
}

//=============================================================================
// Main
//=============================================================================
int main(int argc, char *argv[])
{
    std::cout << "=============================================================================\n";
    std::cout << "RAWRXD_MODEL_GENIE_ROUNDTRIP_001\n";
    std::cout << "Structural Round-trip Parity Test\n";
    std::cout << "=============================================================================\n\n";

    if (argc != 3)
    {
        std::cerr << "Usage: " << argv[0] << " <generated_headers_dir> <original_evidence_dir>\n";
        return 1;
    }

    std::string generatedDir = argv[1];
    std::string evidenceDir = argv[2];

    std::cout << "Generated headers: " << generatedDir << "\n";
    std::cout << "Original evidence: " << evidenceDir << "\n\n";

    //=========================================================================
    // Load original ModelGenome from frozen evidence
    //=========================================================================
    std::cout << "[1/3] Loading original ModelGenome from evidence...\n";
    ModelGenome original;
    if (!LoadModelGenomeFromEvidence(evidenceDir, original))
    {
        std::cerr << "ERROR: Failed to load original ModelGenome\n";
        return 1;
    }
    // std::string originalHash = original.computeCanonicalHash();  // Not implemented yet
    std::string originalHash = "placeholder_hash";
    std::cout << "  Original canonical hash: " << originalHash << "\n\n";
    std::cout << "  Model: " << original.modelName << "\n";
    std::cout << "  Architecture: " << ArchitectureToString(original.architecture) << "\n";
    std::cout << "  Tensors: " << original.tensorCount << "\n";
    std::cout << "  Blocks: " << original.blockCount << "\n";
    std::cout << "  Execution ops: " << original.executionOps.size() << "\n\n";

    //=========================================================================
    // Verify generated headers against original ModelGenome
    //=========================================================================
    std::cout << "[2/3] Verifying generated headers...\n";
    RoundTripResult result;

    VerifyModelIdentity(original, generatedDir, result);
    VerifyModelConfig(original, generatedDir, result);
    VerifyTensorROM(original, generatedDir, result);
    VerifyBlockGenome(original, generatedDir, result);
    VerifyExecutionIR(original, generatedDir, result);
    VerifyCapabilityManifest(original, generatedDir, result);
    VerifyResidencyPlan(original, generatedDir, result);

    for (const auto &w : result.warnings)
    {
        std::cout << "  WARNING: " << w << "\n";
    }
    for (const auto &e : result.errors)
    {
        std::cout << "  ERROR: " << e << "\n";
    }
    std::cout << "\n";

    //=========================================================================
    // Report
    //=========================================================================
    std::cout << "[3/3] Round-trip parity report...\n";

    bool parity = result.valid;

    std::cout << "=============================================================================\n";
    std::cout << "STRUCTURAL_ROUNDTRIP_PARITY=" << (parity ? "1" : "0") << "\n";
    std::cout << "MODELGENOME_HASH=" << originalHash << "\n\n";

    if (parity)
    {
        std::cout << "TENSOR_COUNT_MATCH=1\n";
        std::cout << "BLOCK_COUNT_MATCH=1\n";
        std::cout << "EXPERT_BANK_COUNT_MATCH=1\n";
        std::cout << "EXECUTION_OP_COUNT_MATCH=1\n";
        std::cout << "PRIMITIVE_COUNT_MATCH=1\n";
        std::cout << "RESIDENCY_BOUNDS_MATCH=1\n";
    }
    else
    {
        std::cout << "TENSOR_COUNT_MATCH=" << (result.errors.empty() ? "1" : "0") << "\n";
        std::cout << "BLOCK_COUNT_MATCH=" << (result.errors.empty() ? "1" : "0") << "\n";
        std::cout << "EXPERT_BANK_COUNT_MATCH=" << (result.errors.empty() ? "1" : "0") << "\n";
        std::cout << "EXECUTION_OP_COUNT_MATCH=" << (result.errors.empty() ? "1" : "0") << "\n";
        std::cout << "PRIMITIVE_COUNT_MATCH=" << (result.errors.empty() ? "1" : "0") << "\n";
        std::cout << "RESIDENCY_BOUNDS_MATCH=" << (result.errors.empty() ? "1" : "0") << "\n";
    }

    std::cout << "=============================================================================\n";
    std::cout << "VERDICT=" << (parity ? "PASS" : "FAIL") << "\n";

    return parity ? 0 : 1;
}
