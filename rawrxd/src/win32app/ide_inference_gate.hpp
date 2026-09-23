#pragma once
#include <string>

namespace RawrXD::IDE {

struct InferenceGateResult {
    bool modelFound     = false;
    bool modelLoaded    = false;
    bool tokenizerReady = false;
    bool forwardPassOk  = false;
    bool logitsFinite   = false;
    int  tokenCount     = 0;
    int  generatedToken = -1;
    std::string modelPath;
    std::string diagnostics;

    // Granular diagnostic fields for MODEL_LOADED failure root-causing
    bool   modelPathValid      = false;
    bool   modelFileOpen       = false;
    int64_t modelFileSizeBytes = 0;
    bool   ggufMagicOk         = false;
    int    ggufVersion         = 0;
    bool   ggufMetadataParseOk = false;
    int    ggufTensorCount     = 0;
    bool   ggufTensorTableOk   = false;
    std::string detectedArch;
    bool   backendCreateOk     = false;
    bool   modelContextCreateOk = false;
    std::string failStage;
    int    failCode              = 0;
    std::string failMessage;

    // RAWRXD_MODEL_ADMISSION_DIAG_001 specific fields
    std::string modelLoader      = "";
    std::string modelExtension   = "";
    bool   weightStorageCreate   = false;
    bool   weightTensorDirProbe  = false;
    int    weightTensorDirCount  = 0;
    bool   hasTokenEmbed         = false;
    bool   hasLmHead             = false;
    bool   hasFinalNorm          = false;
    int    firstLayerTensorCount = 0;
    std::string ggufArchFromMeta = "";
    bool   ggufMetadataHasArch   = false;

    // Gate 2B/C — real Deep2 engine fields
    bool syntheticOutput = false;
    bool deep2EntryUsed = false;
    bool modelArchValid = false;
    bool tensorCountGt0   = false;
    bool weightsLoaded    = false;
    bool tokenizerInit    = false;
    bool tokenizeOk       = false;
    bool kvCacheInit      = false;
    bool prefillOk        = false;
    bool decodeOk         = false;
    bool firstTokenEmitted = false;
    bool streamToIdeOk    = false;
    int  promptTokens     = 0;
    int  generatedTokens  = 0;
    int  firstTokenId     = -1;
    std::string modelArch;
    std::string firstTokenText;
    double firstTokenMs   = 0.0;
    double decodeTps      = 0.0;

    // ------------------------------------------------------------------
    // Gate-evidence provenance flags (added to fix synthetic PASS defects)
    // ------------------------------------------------------------------
    bool syntheticPromptTokens      = false;   // set when tokenizer fails & we inject {1}
    bool tokenizerMetadataPresent   = false;   // true if GGUF contains tokenizer.ggml.tokens
    bool logitsRangeNonzero         = false;   // true if min & max logits are separated (>1e-6)
    bool generatedTokenFromModel    = false;   // true if firstTokenId came from engine.sampleToken()
    // Per-stage BLOCKED vs FAIL tri-state helpers (default false = never attempted)
    bool   backendCreateAttempted      = false;
    bool   modelContextCreateAttempted = false;
    bool   modelLoadedAttempted        = false;
    bool   weightsLoadedAttempted      = false;
};

InferenceGateResult runLocalInferenceGate();

// RAWRXD_MODEL_ADMISSION_DIAG_001
struct DiagnosticGateResult {
    bool        modelFound        = false;
    bool        pathReadable      = false;
    bool        extensionOk       = false;
    int64_t     fileSizeBytes     = 0;
    bool        ggufMagicOk       = false;
    int         ggufVersion       = 0;
    bool        metadataHasArch   = false;
    std::string detectedArch;
    bool        hasTokenEmbed     = false;
    bool        hasLmHead         = false;
    bool        hasFinalNorm      = false;
    int         layerTensorCount  = 0;
    int         tensorCount       = 0;
    std::string diagnostics;
    std::string failStage;
    int         failCode          = 0;
};

DiagnosticGateResult runDiagnosticGate();

} // namespace RawrXD::IDE
