// ============================================================================
// AgentOllamaClient.h — Ollama LLM client for agent subsystem
// Extracted from unlinked_symbols_batch_018.cpp / link_stubs_production.cpp
// ============================================================================
#pragma once

#include <string>
#include <vector>
#include <cstdint>

#include <nlohmann/json_fwd.hpp>

namespace RawrXD {
namespace Agent {

struct ChatMessage {
    std::string role;
    std::string content;
    std::string name;
};

struct InferenceResult {
    bool    success = false;
    std::string content;
    std::string error;
    uint64_t tokensGenerated = 0;
    uint64_t tokensPrompt    = 0;

    // RAWRXD_AGENTOLLAMACLIENT_001 -- `response` is the answer text under the
    // name the agent subsystem reads it by.
    //
    // The header's own first line says it was "Extracted from
    // unlinked_symbols_batch_018.cpp / link_stubs_production.cpp", and the
    // extraction dropped this member: src/core/link_stubs_production.cpp:271
    // still carries `struct InferenceResult { bool success; std::string
    // response; std::string metadata; }` and
    // src/core/ssot_handlers_ext.cpp reads .response at lines 4740, 4919,
    // 4975, 5012, 5047, 5082 and 5117 -- while AgentOllamaClient.cpp writes
    // .content. Two names for one value, so the invariant is stated rather than
    // left to chance:
    //
    //     INVARIANT: on a successful result, response == content.
    //                on a failed result, both are empty.
    //
    // Every producer in this pair of files assigns both. A reader may use
    // either. If a future producer sets only one, that is a bug, and the
    // comments at each assignment say so.
    //
    // This is deliberately NOT a reference or a proxy to `content`. A reference
    // member would make InferenceResult non-assignable, and the whole tree
    // assigns these by value.
    std::string response;
};

struct OllamaConfig {
    std::string host         = "localhost";
    int         port         = 11434;
    std::string defaultModel = "llama3";
    int         timeoutMs    = 30000;
    bool        useGPU       = true;
    int         contextLength = 4096;

    // RAWRXD_AGENTOLLAMACLIENT_002 -- model routing for the two endpoints.
    //
    // Required by src/core/ssot_handlers_ext.cpp:153-156, which reads the
    // config, sets both to the selected model, and writes it back:
    //     auto cfg = client.GetConfig();
    //     cfg.chat_model = model;
    //     cfg.fim_model  = model;
    //     client.SetConfig(cfg);
    //
    // Empty means "fall back to defaultModel". They are kept distinct from
    // defaultModel because chat completion and fill-in-the-middle are
    // different tasks and are routinely pointed at different models; collapsing
    // them would remove a distinction the caller explicitly makes.
    std::string chat_model;
    std::string fim_model;
};

class AgentOllamaClient {
public:
    explicit AgentOllamaClient(const OllamaConfig& config);
    ~AgentOllamaClient();

    bool TestConnection();
    std::vector<std::string> ListModels();

    InferenceResult ChatSync(const std::vector<ChatMessage>& messages,
                             const nlohmann::json& options);

    // RAWRXD_AGENTOLLAMACLIENT_003 -- overload restored.
    //
    // ssot_handlers_ext.cpp calls client.ChatSync(msgs) at eleven sites (4915,
    // 4974, 5011, 5046, 5081, 5116, 5153 and others) with one argument, and got
    //     error C2660: 'AgentOllamaClient::ChatSync': function does not take 1
    //                arguments
    // The two-argument form above is the original, and this is a genuine
    // overload rather than a replacement: it forwards with an empty options
    // object, so the model comes from chat_model or defaultModel instead of from
    // the caller's JSON. Callers that want to pass options keep using the
    // two-argument form.
    InferenceResult ChatSync(const std::vector<ChatMessage>& messages);

    // RAWRXD_AGENTOLLAMACLIENT_004 -- fill-in-the-middle completion.
    //
    // ssot_handlers_ext.cpp:4739 calls client.FIMSync(ctx.args, "") -- two
    // arguments, prefix and suffix -- and the member did not exist:
    //     error C2039: 'FIMSync': is not a member of 'AgentOllamaClient'
    // The form that DID exist before the extraction is in
    // unlinked_symbols_batch_018.cpp:130 and took a third `requestId`; that is
    // kept as a defaulted parameter so both call shapes compile and the
    // two-argument caller is unaffected.
    InferenceResult FIMSync(const std::string& prefix,
                            const std::string& suffix,
                            const std::string& requestId = std::string());

    // RAWRXD_AGENTOLLAMACLIENT_005 -- config accessors.
    //
    // ssot_handlers_ext.cpp:153-156 reads the config, edits two fields and
    // writes it back, which needs both halves:
    //     error C2039: 'GetConfig': is not a member of 'AgentOllamaClient'
    //     error C2039: 'SetConfig': is not a member of 'AgentOllamaClient'
    // SetConfig alone existed, as a private helper in the pre-extraction class
    // (unlinked_symbols_batch_018.cpp:154). GetConfig did not exist in any
    // version found in the tree; it is added because the read-modify-write
    // pattern requires it, and returning by value is what makes that pattern
    // safe without exposing a reference to internal state.
    OllamaConfig GetConfig() const;
    void         SetConfig(const OllamaConfig& config);

private:
    OllamaConfig config_;
    bool         m_connected = false;
    bool         m_streaming = false;

    void CancelStream();
};

} // namespace Agent
} // namespace RawrXD
