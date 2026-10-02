// ============================================================================
// http_template_marker_probe_001.cpp
// RAWRXD_HTTP_TEMPLATE_MARKER_PROBE_001
//
// Answers the question the HTTP gate left open: when the chat template emits
// <|system|> / <|user|> / <|assistant|>, what does THIS model's own tokenizer
// actually do with those bytes?
//
// The previous attempt used a hand-written Python tensor-info walk that
// desynchronised and raised MemoryError. This probe uses the production
// GGUFLoader (header-only) and the production BPETokenizer, so the vocabulary
// it reports is the vocabulary the server used.
//
// It is a DIAGNOSTIC. It changes no behavior. It prints observations and a
// machine-readable verdict derived from them; it never asserts a root cause it
// did not measure.
//
// Fields per marker:
//   EXACT_VOCAB_ENTRY  the literal string is present in tokenizer.ggml.tokens
//   TOKEN_IDS          what encode() produces for the literal
//   TOKEN_COUNT        how many tokens the literal costs
//   DECODE_ROUNDTRIP   decode(encode(x)) == x
//   TOKEN_TYPE         GGUF token_type for the exact entry (3 == CONTROL)
//   SPECIAL_TOKEN      BPETokenizer::isSpecial on the exact entry
//
// Fields for the rendered prompt:
//   RENDERED_PROMPT, RENDERED_TOKEN_IDS, RENDERED_DETOKENIZED,
//   CONTROL_MARKERS_AT_GENERATION_BOUNDARY
// ============================================================================

#include "GGUFLoader.hpp"
#include "Tokenizer.hpp"
#include "ChatTemplate.hpp"

#include <cstdio>
#include <string>
#include <vector>

namespace {

std::string escapeForPrint(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        if (c == '\n')      { out += "\\n"; }
        else if (c == '\r') { out += "\\r"; }
        else if (c == '\t') { out += "\\t"; }
        else if (c < 0x20)  { char buf[8]; std::snprintf(buf, sizeof buf, "\\x%02X", c); out += buf; }
        else                { out.push_back(static_cast<char>(c)); }
    }
    return out;
}

std::string joinIds(const std::vector<int>& ids) {
    std::string out;
    for (size_t i = 0; i < ids.size(); ++i) {
        if (i) out += ",";
        out += std::to_string(ids[i]);
    }
    return out;
}

const char* typeName(int32_t t) {
    switch (t) {
        case 1:  return "NORMAL";
        case 2:  return "UNKNOWN";
        case 3:  return "CONTROL";
        case 4:  return "USER_DEFINED";
        case 5:  return "UNUSED";
        case 6:  return "BYTE";
        default: return "OTHER";
    }
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: http_template_marker_probe_001 <model.gguf>\n");
        return 2;
    }
    const std::string ggufPath = argv[1];

    // ---------------------------------------------------------------- loader
    Deep2::GGUFLoader loader;
    if (!loader.load(ggufPath)) {
        std::fprintf(stderr, "GGUF_LOAD=0 ERROR=%s\n", loader.error().c_str());
        return 3;
    }
    std::printf("GGUF_LOAD=1\n");
    std::printf("GGUF_VERSION=%u\n", loader.version());

    const std::string arch = loader.getMetaString("general.architecture");
    std::printf("ARCH=%s\n", arch.c_str());

    // --------------------------------------------------------------- vocab
    std::vector<std::string> tokens;
    if (!loader.getMetaStringArray("tokenizer.ggml.tokens", tokens) || tokens.empty()) {
        std::fprintf(stderr, "VOCAB_READ=0\n");
        return 4;
    }
    std::vector<int32_t> types;
    const bool haveTypes =
        loader.getMetaInt32Array("tokenizer.ggml.token_type", types) &&
        types.size() == tokens.size();

    std::printf("VOCAB_READ=1\n");
    std::printf("VOCAB_SIZE=%zu\n", tokens.size());
    std::printf("TOKEN_TYPES_PRESENT=%d\n", haveTypes ? 1 : 0);
    std::printf("TOKENIZER_MODEL=%s\n",
                loader.getMetaString("tokenizer.ggml.model").c_str());

    // ---------------------------------------------------------- tokenizer
    Deep2::BPETokenizer tok;
    if (!tok.loadFromGGUF(loader)) {
        std::fprintf(stderr, "TOKENIZER_LOAD=0\n");
        return 5;
    }
    std::printf("TOKENIZER_READY=1\n");
    std::printf("TOKENIZER_KIND=%d\n", static_cast<int>(tok.kind()));
    std::printf("TOKENIZER_VOCAB_SIZE=%zu\n", tok.vocabSize());
    std::printf("TOKENIZER_BOS=%d\n", tok.bosTokenId());
    std::printf("TOKENIZER_EOS=%d\n", tok.eosTokenId());
    std::printf("TOKENIZER_ADD_BOS=%d\n", tok.addBos() ? 1 : 0);

    // ------------------------------------------------------- marker probes
    const std::vector<std::string> markers = {
        "<|system|>", "<|user|>", "<|assistant|>",
        "<s>", "</s>", "[INST]", "[/INST]", "<<SYS>>", "<</SYS>>"
    };

    int markersFound = 0;
    int markersAsSingleToken = 0;
    std::printf("\n-- MARKERS --\n");
    for (const std::string& m : markers) {
        // exact vocab entry
        long exactId = -1;
        for (size_t i = 0; i < tokens.size(); ++i) {
            if (tokens[i] == m) { exactId = static_cast<long>(i); break; }
        }

        const std::vector<int> ids = tok.encode(m);
        const std::string roundtrip = tok.decode(ids);
        const int32_t tt = (exactId >= 0 && haveTypes)
            ? types[static_cast<size_t>(exactId)]
            : -1;

        if (exactId >= 0) ++markersFound;
        if (exactId >= 0 && ids.size() == 1) ++markersAsSingleToken;

        std::printf("MARKER=%s\n", m.c_str());
        std::printf("  EXACT_VOCAB_ENTRY=%d\n", exactId >= 0 ? 1 : 0);
        if (exactId >= 0) {
            std::printf("  EXACT_VOCAB_ID=%ld\n", exactId);
            std::printf("  TOKEN_TYPE=%s\n", typeName(tt));
            std::printf("  SPECIAL_TOKEN=%d\n", tok.isSpecial(static_cast<int>(exactId)) ? 1 : 0);
            std::printf("  USABLE_IN_TRIE=%d\n",
                        (tt != 3 && tt != 5 && tt != 2 && tt != 6 && !tokens[static_cast<size_t>(exactId)].empty())
                            ? 1 : 0);
        }
        std::printf("  TOKEN_COUNT=%zu\n", ids.size());
        std::printf("  TOKEN_IDS=%s\n", joinIds(ids).c_str());
        for (size_t i = 0; i < ids.size(); ++i) {
            if (ids[i] >= 0 && static_cast<size_t>(ids[i]) < tokens.size()) {
                std::printf("  TOKEN_PIECE[%zu]=%s\n", i,
                            escapeForPrint(tokens[static_cast<size_t>(ids[i])]).c_str());
            }
        }
        std::printf("  DECODE_ROUNDTRIP=%d\n", roundtrip == m ? 1 : 0);
        std::printf("  DETOKENIZED=%s\n", escapeForPrint(roundtrip).c_str());
        std::printf("\n");
    }

    std::printf("MARKERS_PROBED=%zu\n", markers.size());
    std::printf("MARKERS_WITH_EXACT_VOCAB_ENTRY=%d\n", markersFound);
    std::printf("MARKERS_ENCODING_TO_ONE_TOKEN=%d\n", markersAsSingleToken);

    // ------------------------------------------------- rendered full prompt
    std::printf("\n-- RENDERED PROMPT --\n");
    const std::string tmplStr = loader.getMetaString("tokenizer.chat_template");
    std::printf("TEMPLATE_SOURCE=%s\n",
                tmplStr.empty() ? "NONE" : "GGUF");
    std::printf("TEMPLATE_BYTES=%zu\n", tmplStr.size());

    Deep2::ChatTemplate chatTemplate;
    const bool tmplReady = chatTemplate.initFromGGUF(ggufPath);
    std::printf("TEMPLATE_INIT=%d\n", tmplReady ? 1 : 0);
    std::printf("TEMPLATE_TYPE=%s\n", chatTemplate.getTypeName());

    std::vector<Deep2::ChatMessage> msgs;
    msgs.push_back({"user", "The capital of France is", ""});
    const std::string rendered = tmplReady ? chatTemplate.format(msgs) : std::string();

    std::printf("RENDERED_PROMPT=%s\n", escapeForPrint(rendered).c_str());

    const std::vector<int> rIds = tok.encode(rendered);
    std::printf("RENDERED_TOKEN_COUNT=%zu\n", rIds.size());
    std::printf("RENDERED_TOKEN_IDS=%s\n", joinIds(rIds).c_str());
    const std::string rDetok = tok.decode(rIds);
    std::printf("RENDERED_DETOKENIZED=%s\n", escapeForPrint(rDetok).c_str());
    std::printf("RENDERED_ROUNDTRIP_EXACT=%d\n", rDetok == rendered ? 1 : 0);

    // Control markers at the generation boundary: does the prompt end with a
    // marker the model is expected to answer after?
    //
    // The window length MUST come from the literal, not a hand-counted
    // constant. "<|assistant|>" is 13 characters; a hardcoded 12 silently
    // reports "does not end at marker" for a prompt that visibly does, which
    // is the same failure mode as a mis-keyed parity mask: a specific,
    // confident, wrong answer from a working instrument.
    const std::string kAssistantMarker = "<|assistant|>";
    const bool endsWithAssistant =
        rendered.size() >= kAssistantMarker.size() &&
        rendered.compare(rendered.size() - kAssistantMarker.size(),
                         kAssistantMarker.size(), kAssistantMarker) == 0;
    std::printf("MARKER_WINDOW_BYTES=%zu\n", kAssistantMarker.size());
    std::printf("PROMPT_ENDS_WITH_ASSISTANT_MARKER=%d\n", endsWithAssistant ? 1 : 0);

    int controlIdsInPrompt = 0;
    std::vector<int> controlIdList;
    for (int id : rIds) {
        if (tok.isSpecial(id)) { ++controlIdsInPrompt; controlIdList.push_back(id); }
    }
    std::printf("SPECIAL_TOKEN_COUNT_IN_PROMPT=%d\n", controlIdsInPrompt);
    std::printf("SPECIAL_TOKEN_IDS_IN_PROMPT=%s\n", joinIds(controlIdList).c_str());

    const bool boundaryIsControl =
        !rIds.empty() && tok.isSpecial(rIds.back());
    std::printf("CONTROL_MARKERS_AT_GENERATION_BOUNDARY=%d\n", boundaryIsControl ? 1 : 0);
    std::printf("LAST_PROMPT_TOKEN=%d\n", rIds.empty() ? -1 : rIds.back());
    if (!rIds.empty() && rIds.back() >= 0 &&
        static_cast<size_t>(rIds.back()) < tokens.size()) {
        std::printf("LAST_PROMPT_TOKEN_PIECE=%s\n",
                    escapeForPrint(tokens[static_cast<size_t>(rIds.back())]).c_str());
    }

    // ------------------------------------------------ marker leak mechanism
    // The observed bad response contained visible marker text such as
    // "|assistant|". That can only happen one of two ways: the model emitted a
    // token whose type renders visibly and whose piece happens to spell part
    // of a marker, or a special token is being rendered instead of suppressed.
    // Classify each fragment of the assistant marker so the two are not
    // confused.
    std::printf("\n-- MARKER FRAGMENT VISIBILITY --\n");
    {
        const std::vector<int> aIds = tok.encode("<|assistant|>");
        int visible = 0;
        int hidden = 0;
        for (int id : aIds) {
            const std::string piece = tok.decode(id);
            const bool isSp = tok.isSpecial(id);
            const std::string pieceText =
                (id >= 0 && static_cast<size_t>(id) < tokens.size())
                    ? tokens[static_cast<size_t>(id)] : std::string();
            if (piece.empty()) ++hidden;
            else            ++visible;
            std::printf("FRAGMENT_ID=%d SPECIAL=%d DECODED_VISIBLE=%d PIECE=%s\n",
                        id, isSp ? 1 : 0, piece.empty() ? 0 : 1,
                        escapeForPrint(pieceText).c_str());
        }
        std::printf("MARKER_FRAGMENTS_VISIBLE_ON_DECODE=%d\n", visible);
        std::printf("MARKER_FRAGMENTS_SUPPRESSED_ON_DECODE=%d\n", hidden);
        std::printf("MARKER_TEXT_IS_GENERATABLE_VISIBLE_TEXT=%d\n",
                    visible > 0 ? 1 : 0);
    }

    // ------------------------------------------------------- verdict
    // Derived only from the observations printed above. No root cause is
    // asserted here; the classification is a lookup-table over measurements.
    // Role markers and boundary markers are DIFFERENT classes and must not be
    // counted together. <s> and </s> are expected to exist in a SentencePiece
    // vocab and to be suppressed on decode; <|user|> and friends are expected
    // to exist only if the model was trained with that role vocabulary.
    // Collapsing them produced "MARKERS_PRESENT_BUT_FRAGMENTED" for a model
    // that has NO role markers at all -- a specific, confident, wrong verdict
    // from correct sub-measurements.
    const std::vector<std::string> roleMarkers = {
        "<|system|>", "<|user|>", "<|assistant|>"
    };
    const std::vector<std::string> boundaryMarkers = {
        "<s>", "</s>", "[INST]", "[/INST]", "<<SYS>>", "<</SYS>>"
    };
    int roleFound = 0;
    int boundaryFound = 0;
    for (const std::string& m : roleMarkers)
        for (const std::string& t : tokens)
            if (t == m) { ++roleFound; break; }
    for (const std::string& m : boundaryMarkers)
        for (const std::string& t : tokens)
            if (t == m) { ++boundaryFound; break; }
    std::printf("ROLE_MARKERS_PROBED=%zu\n", roleMarkers.size());
    std::printf("ROLE_MARKERS_WITH_EXACT_VOCAB_ENTRY=%d\n", roleFound);
    std::printf("BOUNDARY_MARKERS_PROBED=%zu\n", boundaryMarkers.size());
    std::printf("BOUNDARY_MARKERS_WITH_EXACT_VOCAB_ENTRY=%d\n", boundaryFound);

    std::string verdict;
    if (!tmplReady) {
        verdict = "NO_TEMPLATE_USED";
    } else if (roleFound == 0 && endsWithAssistant) {
        // The template asks the model to speak a role language its own
        // tokenizer does not have. Every role marker is fragmented into
        // ordinary, freely generatable, VISIBLY decoded pieces.
        verdict = "TEMPLATE_EMITS_ROLE_MARKERS_ABSENT_FROM_VOCAB";
    } else if (roleFound == 0 && !endsWithAssistant) {
        verdict = "ROLE_MARKERS_ABSENT_AND_NO_GENERATION_BOUNDARY";
    } else if (roleFound < static_cast<int>(roleMarkers.size())) {
        verdict = "ROLE_MARKERS_PARTIALLY_PRESENT";
    } else {
        verdict = "ROLE_MARKERS_PRESENT_AS_SINGLE_TOKENS";
    }
    std::printf("\nVERDICT=%s\n", verdict.c_str());
    return 0;
}