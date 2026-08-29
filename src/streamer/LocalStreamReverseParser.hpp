#pragma once

// From-scratch streaming reverse parser for local GGUF files and embedded
// GGUF blobs. Does not call Ollama, HuggingFace, or any network service.
// Reads header + metadata + tensor names only (no weight payloads).

#include <cstdint>
#include <string>
#include <vector>

namespace rawrxd::streamer {

enum class ArtifactKind {
    Model,
    Agent,
    Extension,
    File
};

enum class ReverseParseError {
    Ok = 0,
    EmptyPath,
    NotFound,
    Unreadable,
    Truncated,
    InvalidFormat
};

struct MissingItem {
    std::string id;
    std::string detail;
};

struct ReverseParseReport {
    ArtifactKind kind = ArtifactKind::File;
    ReverseParseError error = ReverseParseError::Ok;
    std::string path;
    uint64_t fileSize = 0;
    uint64_t ggufOffset = 0;
    uint32_t ggufVersion = 0;
    uint64_t tensorCount = 0;
    uint64_t metadataCount = 0;
    std::string architecture;
    std::string modelName;
    std::string tokenizerModel;
    uint64_t vocabSize = 0;
    uint64_t layerCount = 0;
    uint64_t tensorsNamed = 0;
    bool magicAtZero = false;
    bool payloadParsed = false;
    bool hasEmbedTensor = false;
    bool hasOutputTensor = false;
    bool hasFirstBlock = false;
    std::vector<std::string> present;
    std::vector<MissingItem> missing;
};

const char* artifactKindName(ArtifactKind kind);
const char* reverseParseErrorName(ReverseParseError error);
ArtifactKind artifactKindFromName(const std::string& name);

// Stream-parse a local path. Always fills `report` (including missing[]).
// Returns false when the file could not be opened or the payload is unusable.
bool parseLocalArtifact(ArtifactKind kind, const std::string& path, ReverseParseReport& report);
ReverseParseReport parseLocalArtifact(const std::string& kindName, const std::string& path);

std::string formatReverseParseReport(const ReverseParseReport& report);

}  // namespace rawrxd::streamer
