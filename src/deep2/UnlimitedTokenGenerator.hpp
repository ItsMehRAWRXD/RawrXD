#pragma once
/* Deep2 alias — canonical is lavapath/UnlimitedTokenGenerator.hpp */
#include "lavapath/UnlimitedTokenGenerator.hpp"

namespace Deep2 {

using UnlimitedTokenSink = ::rawr::TokenSink;

class UnlimitedTokenGenerator {
public:
    using Config = ::rawr::UnlimitedTokenGenerator::Config;

    explicit UnlimitedTokenGenerator(Deep2Engine& engine) : eng_(&engine) {}

    uint32_t generate(const Config& cfg, UnlimitedTokenSink sink) {
        return impl_.generate(*eng_, cfg, sink);
    }
    void cancel() { impl_.cancel(); }

private:
    Deep2Engine* eng_;
    ::rawr::UnlimitedTokenGenerator impl_;
};

} // namespace Deep2
