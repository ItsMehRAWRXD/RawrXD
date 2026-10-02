// ============================================================================
// http_oracle_suite_001.cpp
// RAWRXD_HTTP_ORACLE_SUITE_001
//
// A byte-count gate cannot detect a wrong answer. This harness runs the same
// five deterministic oracle prompts through TWO paths on ONE loaded engine:
//
//   RAW        plain prompt text, no chat template
//   TEMPLATE   ChatTemplate::format(), i.e. what rawr-server actually sends
//
// and reports a 2x2 verdict matrix:
//
//   RAW PASS  / TEMPLATE PASS  -> healthy
//   RAW PASS  / TEMPLATE FAIL  -> serving or template corruption
//   RAW FAIL  / TEMPLATE FAIL  -> underlying inference or model problem
//   RAW FAIL  / TEMPLATE PASS  -> harness or template artifact; investigate
//
// This is the measurement RAWRXD_HTTP_AUTHORITY_CHAIN_001 needed and did not
// have. Both columns come from the same engine, the same weights, the same
// sampler settings and the same seed, so a column disagreement cannot be
// attributed to the model.
//
// Greedy (temperature 0, topK 1) so the result is deterministic per run.
//
// Every field printed is an observation. The PASS/FAIL per cell is a
// substring test against a declared expected answer, and both the text and
// the test are printed, so the verdict can be argued with.
//
// Limitation, stated rather than hidden: substring matching is a weak oracle.
// A model may answer "Paris, France." for "capital of France", which this
// scores PASS, and may answer "The capital of France is Paris" for the same,
// which it also scores PASS. It is designed to catch control-marker leakage
// and gross wrongness, not to grade prose.
// ============================================================================

#include "deep2/Deep2Engine.h"
#include "deep2/ChatTemplate.hpp"
#include "deep2/Tokenizer.hpp"
#include "deep2/GGUFLoader.hpp"

#include <cstdio>
#include <cctype>
#include <string>
#include <vector>

namespace {

struct Oracle {
    const char* name;
    const char* prompt;
    const char* expected;
};

const std::vector<Oracle>& oracles() {
    // EXPECTED is matched as a WHOLE WORD, not as a raw substring. A substring
    // oracle for "first letter of the alphabet is a" scores every English
    // sentence as PASS because "a" appears in "capital". A gate that cannot
    // fail is not a gate, and this one reported PASS/PASS on a row whose real
    // text was "\n<|user|>\nWrite a|assistant| I's".
    static const std::vector<Oracle> v = {
        {"capital_of_france", "The capital of France is",        "paris"},
        {"two_plus_two",       "2 + 2 =",                         "4"},
        {"opposite_of_hot",    "The opposite of hot is",          "cold"},
        {"first_letter",       "The first letter of the alphabet is", "a"},
        {"repeat_exactly",     "Repeat exactly: zebra42",         "zebra42"},
    };
    return v;
}

std::string lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// Whole-word containment. "4" must not match "10.00"; "a" must not match
// "capital". Digits and other non-alphanumerics bound on themselves.
bool wholeWordMatch(const std::string& hayLower, const std::string& needleLower) {
    if (needleLower.empty()) return false;
    size_t pos = 0;
    auto isWord = [](unsigned char c) {
        return std::isalnum(c) != 0 || c == '_';
    };
    while ((pos = hayLower.find(needleLower, pos)) != std::string::npos) {
        const bool leftOk  = pos == 0 ||
            !isWord(static_cast<unsigned char>(hayLower[pos - 1]));
        const size_t end = pos + needleLower.size();
        const bool rightOk = end >= hayLower.size() ||
            !isWord(static_cast<unsigned char>(hayLower[end]));
        if (leftOk && rightOk) return true;
        pos = end;
    }
    return false;
}

std::string escapeForPrint(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        if (c == '\n')      { out += "\\n"; }
        else if (c == '\r') { out += "\\r"; }
        else if (c == '\t') { out += "\\t"; }
        else if (c < 0x20)  { char b[8]; std::snprintf(b, sizeof b, "\\x%02X", c); out += b; }
        else                { out.push_back(static_cast<char>(c)); }
    }
    return out;
}

// Control-marker contamination is a separate dimension from semantic
// correctness: a response can contain the right word AND leak "|assistant|".
// The user was explicit that a search for the literal "|assistant|" is too
// narrow, so this derives the forbidden vocabulary from the markers the active
// template actually emits.
std::string activeMarkerVocabulary(const std::string& rendered) {
    static const char* kCandidateMarkers[] = {
        "<|system|>", "<|user|>", "<|assistant|>", "<|end|>",
        "[INST]", "[/INST]", "<<SYS>>", "<</SYS>>",
        "<start_of_turn>", "<end_of_turn>", "<|im_start|>", "<|im_end|>",
        "<|start_header_id|>", "<|end_header_id|>",
    };
    std::string active;
    for (const char* m : kCandidateMarkers) {
        if (rendered.find(m) != std::string::npos) {
            if (!active.empty()) active += ",";
            active += m;
        }
    }
    return active;
}

} // namespace

int main(int argc, char** argv) {
    std::string model;
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--model" && i + 1 < argc) model = argv[++i];
    }
    if (model.empty()) {
        std::fprintf(stderr, "usage: http_oracle_suite_001 --model <gguf>\n");
        return 2;
    }

    Deep2::Deep2Engine eng;
    Deep2::ModelLoadDiag diag;
    if (!eng.loadModel(model, &diag)) {
        std::fprintf(stderr, "MODEL_LOAD=0 stage=%d name=%s detail=%s\n",
                     diag.stageCode, diag.stageName.c_str(), diag.message.c_str());
        return 3;
    }
    std::printf("MODEL_LOAD=1\n");
    std::printf("MODEL=%s\n", model.c_str());

    // The template is derived from the same GGUF the server reads, so the
    // TEMPLATE column is the server's column, not a reimplementation.
    Deep2::ChatTemplate tmpl;
    const bool tmplReady = tmpl.initFromGGUF(model);
    std::printf("TEMPLATE_INIT=%d\n", tmplReady ? 1 : 0);
    std::printf("TEMPLATE_TYPE=%s\n", tmpl.getTypeName());

    Deep2::GenerationOptions base;
    base.maxTokens = 16;
    base.temperature = 0.0f;
    base.topK = 1;
    base.topP = 1.0f;
    base.seed = 1234;

    int rawPass = 0, tplPass = 0, rawFail = 0, tplFail = 0;
    int contaminatedRaw = 0, contaminatedTpl = 0;
    std::string matrix;

    for (const Oracle& o : oracles()) {
        std::string rawPrompt = o.prompt;

        std::vector<Deep2::ChatMessage> msgs;
        msgs.push_back({"user", o.prompt, ""});
        const std::string tplPrompt = tmplReady ? tmpl.format(msgs) : rawPrompt;
        const std::string markerVocab = activeMarkerVocabulary(tplPrompt);

        std::string rawText, tplText;
        Deep2::GenerationResult rawR, tplR;

        // GenerationResult carries counts and status, NOT text. The text
        // arrives only through the stream callback, so it is accumulated
        // there. Capturing it anywhere else would silently measure an empty
        // string and score every oracle FAIL.
        eng.reset();
        rawR = eng.generateStream(rawPrompt, base,
            [&](int32_t, const std::string& piece) {
                rawText += piece;
                return true;
            });

        eng.reset();
        tplR = eng.generateStream(tplPrompt, base,
            [&](int32_t, const std::string& piece) {
                tplText += piece;
                return true;
            });

        // Contamination is checked by searching the OUTPUT for each marker the
        // active template actually emits. It is NOT checked by searching the
        // marker vocabulary for a delimiter: that flags every row whenever the
        // template is marker-shaped, including rows whose output is clean, and
        // reports a constant instead of a measurement.
        bool rawContam = false, tplContam = false;
        {
            std::string mv = markerVocab;
            size_t p = 0;
            while ((p = mv.find(',', p)) != std::string::npos) {
                const std::string marker = mv.substr(0, p);
                if (rawText.find(marker) != std::string::npos) rawContam = true;
                if (tplText.find(marker) != std::string::npos) tplContam = true;
                mv.erase(0, p + 1);
            }
            if (!mv.empty()) {
                if (rawText.find(mv) != std::string::npos) rawContam = true;
                if (tplText.find(mv) != std::string::npos) tplContam = true;
            }
        }

        // Fragment-level leakage. A complete-marker search UNDERSTATES the damage:
        // the observed " Yes, the French is a|assistant|system|enjokeeps" does
        // not contain the literal "<|assistant|>", because the model emitted
        // the marker's PIECES ("|", "assistant", "|") as ordinary tokens. That
        // is precisely the fragmentation the vocabulary probe measured, so the
        // detector has to run at fragment granularity or it reports 0 on the
        // exact symptom it exists to catch.
        auto fragmentLeak = [](const std::string& text, const std::string& vocab) {
            std::string mv = vocab;
            size_t p = 0;
            while ((p = mv.find(',', p)) != std::string::npos) {
                const std::string marker = mv.substr(0, p);
                // inner role name, e.g. "<|user|>" -> "user"
                const size_t a = marker.find('<'), b = marker.rfind('>');
                if (a != std::string::npos && b != std::string::npos && b > a + 1) {
                    const std::string inner = marker.substr(a + 1, b - a - 1);
                    size_t q = 0;
                    while ((q = text.find(inner, q)) != std::string::npos) {
                        const bool leftBar  = q > 0 && text[q - 1] == '|';
                        const bool rightBar = q + inner.size() < text.size() &&
                                              text[q + inner.size()] == '|';
                        if (leftBar || rightBar) return true;
                        q += inner.size();
                    }
                }
                mv.erase(0, p + 1);
            }
            return false;
        };
        const bool rawFrag = fragmentLeak(rawText, markerVocab);
        const bool tplFrag = fragmentLeak(tplText, markerVocab);
        if (rawFrag) rawContam = true;
        if (tplFrag) tplContam = true;

        const std::string rawLower = lower(rawText);
        const std::string tplLower  = lower(tplText);
        const bool rawSemantic = wholeWordMatch(rawLower, lower(o.expected));
        const bool tplSemantic = wholeWordMatch(tplLower,  lower(o.expected));

        if (rawSemantic) rawPass++; else rawFail++;
        if (tplSemantic) tplPass++; else tplFail++;
        if (rawContam) contaminatedRaw++;
        if (tplContam) contaminatedTpl++;

        std::printf("\n=== ORACLE %s ===\n", o.name);
        std::printf("PROMPT=%s\n", escapeForPrint(o.prompt).c_str());
        std::printf("EXPECTED_SUBSTRING=%s\n", o.expected);
        std::printf("ACTIVE_MARKER_VOCAB=%s\n", markerVocab.empty() ? "(none)" : markerVocab.c_str());

        std::printf("RAW_STATUS=%d RAW_GENERATED=%zu RAW_DETAIL=%s\n",
                    (int)rawR.status, rawR.generatedTokens, rawR.failureDetail.c_str());
        std::printf("RAW_TEXT=%s\n", escapeForPrint(rawText).c_str());
        std::printf("RAW_SEMANTIC=%d\n", rawSemantic ? 1 : 0);
        std::printf("RAW_CONTROL_CONTAMINATED=%d\n", rawContam ? 1 : 0);
        std::printf("RAW_FRAGMENT_LEAK=%d\n", rawFrag ? 1 : 0);

        std::printf("TPL_PROMPT=%s\n", escapeForPrint(tplPrompt).c_str());
        std::printf("TPL_STATUS=%d TPL_GENERATED=%zu TPL_DETAIL=%s\n",
                    (int)tplR.status, tplR.generatedTokens, tplR.failureDetail.c_str());
        std::printf("TPL_TEXT=%s\n", escapeForPrint(tplText).c_str());
        std::printf("TPL_SEMANTIC=%d\n", tplSemantic ? 1 : 0);
        std::printf("TPL_CONTROL_CONTAMINATED=%d\n", tplContam ? 1 : 0);
        std::printf("TPL_FRAGMENT_LEAK=%d\n", tplFrag ? 1 : 0);

        matrix += rawSemantic ? "PASS" : "FAIL";
        matrix += "/";
        matrix += tplSemantic ? "PASS" : "FAIL";
        matrix += " ";
    }

    std::printf("\n--- MATRIX (RAW/TEMPLATE) ---\n");
    std::printf("%s\n", matrix.c_str());
    std::printf("RAW_PASS=%d RAW_FAIL=%d\n", rawPass, rawFail);
    std::printf("TPL_PASS=%d TPL_FAIL=%d\n", tplPass, tplFail);
    std::printf("RAW_CONTROL_CONTAMINATED=%d\n", contaminatedRaw);
    std::printf("TPL_CONTROL_CONTAMINATED=%d\n", contaminatedTpl);
    std::printf("ORACLES_TOTAL=%d\n", (int)oracles().size());

    // The 2x2 is read with BOTH columns scored, and marker contamination is
    // reported separately because it is a different defect from answering
    // wrongly: an answer can be right AND leak "|assistant|", or wrong AND
    // clean. Collapsing them hides which one occurred.
    const int total = (int)oracles().size();
    std::string verdict;
    if (rawPass == total && tplPass == total) {
        verdict = contaminatedTpl > 0
            ? "SEMANTICS_OK_BUT_TEMPLATE_MARKER_LEAK"
            : "HEALTHY";
    } else if (rawPass == total) {
        verdict = "SERVING_OR_TEMPLATE_CORRUPTION";
    } else if (tplPass == total) {
        verdict = "HARNESS_OR_TEMPLATE_ARTIFACT_INVESTIGATE";
    } else {
        verdict = contaminatedTpl > contaminatedRaw
            ? "BOTH_FAIL_TEMPLATE_ADDITIONALLY_LEAKS_MARKERS"
            : "UNDERLYING_INFERENCE_OR_MODEL_PROBLEM";
    }
    std::printf("VERDICT=%s\n", verdict.c_str());
    return 0;
}