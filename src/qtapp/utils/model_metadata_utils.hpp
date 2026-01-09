#pragma once

#include <QString>
#include <optional>

namespace model_metadata {

struct GgufMetadata {
    QString name;
    QString architecture;
    int contextLength = 0;
    std::optional<uint64_t> parameterCount;
    QString quantization; // e.g., q4_0, q8_0, mxfp4
    double sizeMB = 0.0;
};

// Extracts metadata from a GGUF file if possible. Uses StreamingGGUFLoaderQt
// under the hood; returns an empty optional on failure.
std::optional<GgufMetadata> extractGgufMetadata(const QString& filePath);

// Heuristic parsers that don't touch the file system.
QString parseQuantFromFilename(const QString& filename);
std::optional<uint64_t> parseParamCountFromFilename(const QString& filename);

// Formats a large parameter count into a human-friendly string (e.g. 7B)
QString formatParamCount(uint64_t params);

} // namespace model_metadata
