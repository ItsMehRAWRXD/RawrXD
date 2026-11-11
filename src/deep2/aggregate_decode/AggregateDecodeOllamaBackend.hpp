// AggregateDecodeOllamaBackend.hpp — live Ollama /api/generate decode backend.
#pragma once
#include "IAggregateDecodeBackend.hpp"

namespace rawr::aggdec {

class AggregateDecodeOllamaBackend final : public IAggregateDecodeBackend {
public:
    AggregateDecodeOllamaBackend(std::string host, std::string model);
    BackendKind kind() const override { return BackendKind::OllamaHttp; }
    const char* label() const override { return "OLLAMA_HTTP"; }
    const char* model() const override { return model_.c_str(); }
    bool open() override;
    void close() override;
    SessionMetrics decode(const DecodeRequest& req, TokenEmitFn on_token) override;

private:
    std::string host_;
    std::string model_;
    bool open_ = false;
};

} // namespace rawr::aggdec
