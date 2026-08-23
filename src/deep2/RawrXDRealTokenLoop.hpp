#pragma once

#include "RawrXDTokenStreamer.hpp"
#include "GGUFTokenSource.hpp"

#include <cstdint>
#include <vector>
#include <functional>
#include <string>

namespace RawrXD {

class RealTokenLoop {
public:
    using ForwardFn =
        std::function<bool(
            uint32_t token_id,
            uint32_t position,
            std::vector<float>& logits)>;

    using EmitFn =
        std::function<bool(
            uint32_t token_id,
            const std::string& text,
            float score)>;

    bool Run(
        const std::vector<uint32_t>& prompt,
        ForwardFn forward,
        const GGUFTokenSource& vocabulary,
        const StreamConfig& config,
        EmitFn emit)
    {
        if (prompt.empty())
            return false;

        if (!forward || !emit)
            return false;

        if (vocabulary.Empty())
            return false;

        TokenStreamDecoder decoder;

        decoder.SetConfig(config);

        if (vocabulary.EOS() >= 0) {
            decoder.SetEOS(
                static_cast<uint32_t>(vocabulary.EOS()));
        }

        decoder.Reset();

        std::vector<uint32_t> context = prompt;

        context.reserve(
            prompt.size() + config.max_tokens);

        for (uint32_t step = 0;
             step < config.max_tokens;
             ++step) {

            if (context.empty())
                return false;

            const uint32_t input =
                context.back();

            const uint32_t position =
                static_cast<uint32_t>(context.size() - 1);

            std::vector<float> logits;

            if (!forward(
                    input,
                    position,
                    logits)) {
                return false;
            }

            if (logits.size() < vocabulary.Size())
                return false;

            const bool consumed =
                decoder.Consume(
                    logits.data(),
                    vocabulary.Size(),
                    "",
                    [&](const StreamToken& token) {

                        const std::string& text =
                            vocabulary.Decode(token.id);

                        if (!emit(
                                token.id,
                                text,
                                token.score)) {
                            return false;
                        }

                        return true;
                    });

            if (!consumed)
                return false;

            if (decoder.History().empty())
                return false;

            const uint32_t next =
                decoder.History().back();

            context.push_back(next);

            if (decoder.Stopped())
                break;
        }

        return decoder.Emitted() > 0;
    }
};

} // namespace RawrXD
