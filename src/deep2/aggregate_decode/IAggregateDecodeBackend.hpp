// IAggregateDecodeBackend.hpp — product decode backend contract.
#pragma once
#include "AggregateDecodeTypes.hpp"
#include <functional>
#include <string>

namespace rawr::aggdec {

struct DecodeRequest {
    uint32_t session_id = 0;
    std::string prompt;
    uint32_t max_tokens = 32;
    bool warm = false;
};

using TokenEmitFn = std::function<bool(uint32_t /*token_index*/)>;

class IAggregateDecodeBackend {
public:
    virtual ~IAggregateDecodeBackend() = default;
    virtual BackendKind kind() const = 0;
    virtual const char* label() const = 0;
    virtual const char* model() const = 0;
    virtual bool open() = 0;
    virtual void close() = 0;
    // Real decode only — must produce tokens via engine/HTTP; no hardcoded strings.
    virtual SessionMetrics decode(const DecodeRequest& req, TokenEmitFn on_token) = 0;
};

} // namespace rawr::aggdec
