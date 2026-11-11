// AggregateDecodeDeep2Backend.hpp — Deep2Engine generateStream product path.
// Compile with AGGREGATE_DECODE_USE_DEEP2=1 and link deep2_engine_lib.
#pragma once
#include "IAggregateDecodeBackend.hpp"
#include <memory>
#include <mutex>
#include <string>

namespace Deep2 { class Deep2Engine; }

namespace rawr::aggdec {

class AggregateDecodeDeep2Backend final : public IAggregateDecodeBackend {
public:
    explicit AggregateDecodeDeep2Backend(std::string gguf_path);
    ~AggregateDecodeDeep2Backend() override;
    BackendKind kind() const override { return BackendKind::Deep2Engine; }
    const char* label() const override { return "DEEP2_ENGINE"; }
    const char* model() const override { return gguf_path_.c_str(); }
    bool open() override;
    void close() override;
    SessionMetrics decode(const DecodeRequest& req, TokenEmitFn on_token) override;
    bool linked() const;

private:
    std::string gguf_path_;
#if defined(AGGREGATE_DECODE_USE_DEEP2)
    std::unique_ptr<Deep2::Deep2Engine> engine_;
    std::mutex decode_mu_;
#endif
    bool open_ = false;
};

} // namespace rawr::aggdec
