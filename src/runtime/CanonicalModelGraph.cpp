// ============================================================================
// RawrXD Canonical Model Graph - Implementation
// ============================================================================

#include "CanonicalModelGraph.hpp"
#include "UniversalHeaderSniffer.hpp"

#include <fstream>
#include <algorithm>
#include <sstream>

namespace RawrXD {

// ============================================================================
// FormatParserRegistry Implementation
// ============================================================================

FormatParserRegistry& FormatParserRegistry::Instance() {
    static FormatParserRegistry instance;
    return instance;
}

void FormatParserRegistry::Register(std::unique_ptr<IFormatParser> parser) {
    if (parser) {
        parsers_.push_back(std::move(parser));
    }
}

void FormatParserRegistry::Clear() {
    parsers_.clear();
}

IFormatParser* FormatParserRegistry::FindParser(std::string_view formatName) const {
    for (const auto& p : parsers_) {
        if (p->GetName() == formatName) {
            return p.get();
        }
    }
    return nullptr;
}

bool FormatParserRegistry::AutoParse(const void* data, size_t size,
                                      CanonicalModelGraph& outGraph,
                                      std::string& detectedFormat) {
    UniversalHeaderSniffer sniffer;
    FileFormat fmt = sniffer.Sniff(data, std::min(size, size_t(64)));
    
    // Map FileFormat to parser name
    switch (fmt) {
        case FileFormat::GGUF:
        case FileFormat::GGML:
            detectedFormat = "gguf";
            break;
        case FileFormat::Safetensors:
            detectedFormat = "safetensors";
            break;
        case FileFormat::ONNX:
            detectedFormat = "onnx";
            break;
        case FileFormat::PyTorch:
            detectedFormat = "pytorch";
            break;
        case FileFormat::RawFloat32:
        case FileFormat::RawFloat16:
        case FileFormat::RawInt8:
            detectedFormat = "raw";
            break;
        default:
            detectedFormat = "unknown";
            break;
    }
    
    auto* parser = FindParser(detectedFormat);
    if (!parser) {
        return false;
    }
    
    return parser->Parse(data, size, outGraph);
}

std::vector<std::string_view> FormatParserRegistry::ListParsers() const {
    std::vector<std::string_view> names;
    for (const auto& p : parsers_) {
        names.push_back(p->GetName());
    }
    return names;
}

// ============================================================================
// UniversalFormatParser Implementation
// ============================================================================

bool UniversalFormatParser::Parse(const void* data, size_t size,
                                   CanonicalModelGraph& outGraph) {
    std::string detected;
    return FormatParserRegistry::Instance().AutoParse(data, size, outGraph, detected);
}

bool UniversalFormatParser::ParseFile(const std::string& path,
                                       CanonicalModelGraph& outGraph) {
    // Memory-map the file
    MemoryMappedStream stream(path);
    if (!stream.IsValid()) {
        return false;
    }
    
    outGraph.sourcePath = path;
    
    bool result = Parse(stream.Data(), stream.Size(), outGraph);
    
    if (result) {
        lastFormat_ = outGraph.sourceFormat;
    }
    
    return result;
}

} // namespace RawrXD
