#pragma once
#include "../wire_format.h"

namespace RawrXD::Serve {

class AnthropicAdapter : public WireFormatAdapter {
public:
    std::string name() const override { return "anthropic"; }
    bool match(const std::string& path, const std::string& method) const override;
    GenerateRequest parseRequest(const std::string& body) const override;
    std::string buildStreamingChunk(
        const std::string& model,
        const GenerationChunk& chunk,
        const GenerateRequest& req) const override;
    std::string buildFinalResponse(
        const std::string& model,
        const std::string& fullText,
        const GenerateRequest& req) const override;
    std::string listModelsJson(const std::vector<ModelEntry>& models) const override;
    std::string streamContentType() const override { return "text/event-stream"; }
    std::string streamTerminator() const override { return ""; }
};

} // namespace RawrXD::Serve
