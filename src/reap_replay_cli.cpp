#include "Deep2Engine.h"
#include "deep2/ReapRouteTracker.hpp"
#include "deep2/MlaCertAuthority.hpp"
#include "deep2/deep2_sha256.hpp"
#include <nlohmann/json.hpp>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <regex>
#include <cstdlib>
#include <chrono>
#include <cmath>
#include <algorithm>
#include <cctype>
#ifdef _WIN32
#include <cstdio>
#include <io.h>
#endif

using json = nlohmann::json;

static std::string jsonText(const std::string& line) {
    const std::string key="\"text\":\""; auto p=line.find(key); if(p==std::string::npos) return {};
    p+=key.size(); std::string out; bool esc=false;
    for(;p<line.size();++p){ char c=line[p]; if(esc){ if(c=='n')out+='\n'; else if(c=='r')out+='\r'; else if(c=='t')out+='\t'; else out+=c; esc=false; continue;} if(c=='\\'){esc=true;continue;} if(c=='\"')break; out+=c; } return out;
}

static std::string jsonEscape(const std::string& value) {
    std::string out;
    out.reserve(value.size() + 16);
    for (unsigned char c : value) {
        switch (c) {
        case '\\': out += "\\\\"; break;
        case '"': out += "\\\""; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (c < 0x20) {
                static constexpr char hex[] = "0123456789abcdef";
                out += "\\u00";
                out += hex[(c >> 4) & 0x0f];
                out += hex[c & 0x0f];
            } else {
                out.push_back(static_cast<char>(c));
            }
            break;
        }
    }
    return out;
}

struct ReplayResponse {
    std::string prompt;
    std::string response;
};

template <typename MetricsMap>
static void writeMetrics(std::ostream& out, const MetricsMap& metrics) {
    out << '[';
    bool first = true;
    for (const auto& kv : metrics) {
        if (!first) out << ',';
        first = false;
        out << "{\"layer\":" << kv.first.first
            << ",\"expert\":" << kv.first.second
            << ",\"route_count\":" << kv.second.routeCount
            << ",\"activation_sum\":" << kv.second.activationSum
            << ",\"weight_sum\":" << kv.second.weightSum << '}';
    }
    out << ']';
}

static void writeResponses(std::ostream& out, const std::vector<ReplayResponse>& responses) {
    out << '[';
    bool first = true;
    for (const auto& item : responses) {
        if (!first) out << ',';
        first = false;
        out << "{\"prompt\":\"" << jsonEscape(item.prompt)
            << "\",\"response\":\"" << jsonEscape(item.response)
            << "\",\"response_bytes\":" << item.response.size() << '}';
    }
    out << ']';
}

static bool readText(const std::string& path, std::string& text) {
    std::ifstream input(path, std::ios::binary);
    if (!input) return false;
    std::ostringstream buffer;
    buffer << input.rdbuf();
    text = buffer.str();
    return input.good() || input.eof();
}

struct ReferenceEvidence {
    bool provided = false;
    bool parsed = false;
    bool pass = false;
    std::string receiptPath;
    std::string engine;
    std::string reason;
    std::string modelFirstShardSha256;
    std::string corpusSha256;
    std::vector<int32_t> expectedTokenIds;
};

static bool sha256FileHex(const std::string& path, std::string& digest) {
    std::array<uint8_t, 32> bytes{};
    if (!deep2::sha256_file(path, bytes, nullptr)) return false;
    digest = deep2::hex32(bytes);
    return true;
}

static bool referenceEngineIsExternal(const std::string& engine) {
    std::string lower = engine;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return !engine.empty() && lower.find("rawrxd") == std::string::npos &&
           lower.find("deep2") == std::string::npos;
}

static bool loadReferenceEvidence(const std::string& path,
                                  const std::string& model,
                                  const std::string& corpus,
                                  uint32_t promptTokens,
                                  const std::vector<int32_t>& actualTokenIds,
                                  ReferenceEvidence& out) {
    out.provided = true;
    out.receiptPath = path;
    std::string text;
    if (!readText(path, text)) {
        out.reason = "reference receipt could not be read";
        return false;
    }
    try {
        const json doc = json::parse(text);
        if (doc.value("schema", std::string{}) != "RAWRXD_REAP_REFERENCE_001") {
            out.reason = "unsupported reference receipt schema";
            return false;
        }
        out.engine = doc.value("engine", std::string{});
        if (!referenceEngineIsExternal(out.engine)) {
            out.reason = "reference engine is missing or is not independent of RawrXD/Deep2";
            return false;
        }
        if (doc.value("model", std::string{}) != model) {
            out.reason = "reference model path does not match replay model";
            return false;
        }
        if (doc.value("corpus", std::string{}) != corpus) {
            out.reason = "reference corpus path does not match replay corpus";
            return false;
        }

        std::string actualModelHash;
        std::string actualCorpusHash;
        if (!sha256FileHex(model, actualModelHash)) {
            out.reason = "could not hash replay model first shard";
            return false;
        }
        if (!sha256FileHex(corpus, actualCorpusHash)) {
            out.reason = "could not hash replay corpus";
            return false;
        }
        out.modelFirstShardSha256 = actualModelHash;
        out.corpusSha256 = actualCorpusHash;
        if (doc.value("model_first_shard_sha256", std::string{}) != actualModelHash) {
            out.reason = "reference model first-shard SHA-256 does not match replay input";
            return false;
        }
        if (doc.value("corpus_sha256", std::string{}) != actualCorpusHash) {
            out.reason = "reference corpus SHA-256 does not match replay input";
            return false;
        }
        if (!doc.value("deterministic", false) || !doc.value("finite", false) ||
            !doc.value("reference_result_valid", false)) {
            out.reason = "reference receipt is not marked deterministic, finite, and valid";
            return false;
        }
        const auto settings = doc.find("generation_settings");
        if (settings == doc.end() || !settings->is_object() ||
            settings->value("temperature", -1.0) != 0.0 ||
            settings->value("top_p", -1.0) != 1.0 ||
            settings->value("top_k", -1) != 1 ||
            settings->value("repeat_penalty", -1.0) != 1.0 ||
            settings->value("min_p", -1.0) != 0.0 ||
            settings->value("seed", -1) != 0) {
            out.reason = "reference generation settings are not the required deterministic settings";
            return false;
        }
        if (doc.value("prompt_tokens", 0u) != promptTokens) {
            out.reason = "reference prompt token count does not match replay";
            return false;
        }
        const auto ids = doc.find("token_ids");
        if (ids == doc.end() || !ids->is_array() || ids->empty()) {
            out.reason = "reference token_ids are missing or empty";
            return false;
        }
        for (const auto& id : *ids) {
            if (!id.is_number_integer()) {
                out.reason = "reference token_ids contain a non-integer value";
                return false;
            }
            out.expectedTokenIds.push_back(id.get<int32_t>());
        }
        if (out.expectedTokenIds != actualTokenIds) {
            out.reason = "reference token IDs do not match replay token IDs";
            return false;
        }
        out.parsed = true;
        out.pass = true;
        out.reason = "independent deterministic token parity verified";
        return true;
    } catch (const std::exception& ex) {
        out.reason = std::string("reference receipt JSON parse failed: ") + ex.what();
        return false;
    }
}

int main(int argc,char**argv){
    if(argc<4){std::cerr<<"usage: rawr-reap-replay <model.gguf> <corpus.jsonl> <receipt.json> [window-limit] [--require-mla] [--continuous] [--parity] [--reference-receipt <receipt.json>]\n";return 2;}
    // The window limit is present whenever an optional argument is supplied;
    // the certification flag is a separate argument and must not make the
    // replay silently fall back to the default 256-window run.
    const size_t limit = argc>=5 ? std::strtoull(argv[4],nullptr,10) : 256;
    if(limit==0 || limit>256){std::cerr<<"INVALID_WINDOW_LIMIT\n";return 2;}
    bool requireMla = false;
    bool continuous = false;
    bool parity = false;
    std::string referenceReceiptPath;
    for (int i = 5; i < argc; ++i) {
        const std::string flag = argv[i];
        if (flag == "--require-mla") requireMla = true;
        else if (flag == "--continuous") continuous = true;
        else if (flag == "--parity") parity = true;
        else if (flag == "--reference-receipt") {
            if (++i >= argc) { std::cerr << "MISSING_REFERENCE_RECEIPT\n"; return 2; }
            referenceReceiptPath = argv[i];
        }
        else { std::cerr << "INVALID_FLAG=" << flag << "\n"; return 2; }
    }
    if(const char* q=std::getenv("RAWR_REAP_QUIET"); q && q[0]=='1') {
#ifdef _WIN32
        FILE* nul=std::fopen("NUL","w");
        if(nul){ std::fflush(stdout); std::fflush(stderr); _dup2(_fileno(nul),_fileno(stdout)); _dup2(_fileno(nul),_fileno(stderr)); }
#endif
    }
    const auto started=std::chrono::steady_clock::now();
    Deep2::ReapActivationAccumulator acc; acc.Reset();
    Deep2::ReapRouteTracker::Instance().Install([&](size_t l,const auto& p,const auto& ids,const auto& w){acc.Observe(l,p,ids,w);});
    Deep2::Deep2Engine engine;
    if(!engine.loadModel(argv[1])){std::cerr<<"MODEL_LOAD_FAILED\n"; Deep2::ReapRouteTracker::Instance().Clear(); return 4;}
    std::ifstream in(argv[2]); if(!in){std::cerr<<"CORPUS_OPEN_FAILED\n"; return 4;}
    std::string line; size_t n=0; size_t generated=0; std::vector<ReplayResponse> responses;
    std::vector<std::string> prompts;
    while(n<limit && std::getline(in,line)) {
        auto text=jsonText(line);
        if(text.empty()) continue;
        prompts.push_back(std::move(text));
        ++n;
    }
    if (prompts.empty()) { std::cerr << "CORPUS_EMPTY\n"; return 4; }

    std::vector<int32_t> continuousTokenIds;
    std::string continuousText;
    Deep2::GenerationResult continuousResult{};
    double parityMaxAbs = -1.0;
    bool parityPass = false;
    ReferenceEvidence referenceEvidence;

    if (continuous) {
        // One generateStream call owns the full prefill/decode lifecycle.  This
        // is intentionally separate from the historical independent-window
        // probe: a receipt must say which lifecycle it actually exercised.
        const auto promptTokens = engine.tokenize(prompts.front());
        if (parity && !promptTokens.empty()) {
            const size_t parityTokens = (std::min)(promptTokens.size(), size_t(8));
            parityMaxAbs = engine.prefillParityReport(promptTokens.data(), parityTokens,
                                                      (std::min)(size_t(4), parityTokens), stdout);
            parityPass = std::isfinite(parityMaxAbs) && parityMaxAbs >= 0.0 && parityMaxAbs <= 1.0e-4;
        }
        Deep2::GenerationOptions options{};
        options.maxTokens = static_cast<uint32_t>(limit);
        options.temperature = 0.0f;
        options.topP = 1.0f;
        options.topK = 1;
        options.repeatPenalty = 1.0f;
        options.minP = 0.0f;
        options.seed = 0;
        continuousResult = engine.generateStream(
            prompts.front(), options,
            [&](int32_t tokenId, const std::string& token) {
                continuousTokenIds.push_back(tokenId);
                continuousText += token;
                return true;
            });
        generated = static_cast<size_t>(continuousResult.generatedTokens);
        responses.push_back({prompts.front(), continuousText});
        std::cout << "REPLAY_CONTINUOUS generated=" << generated
                  << " prompt_tokens=" << continuousResult.promptTokens
                  << " completed=" << (continuousResult.completed ? 1 : 0) << "\n";
    } else {
        for (size_t i = 0; i < prompts.size(); ++i) {
            auto result=engine.generateText(prompts[i],1);
            responses.push_back({prompts[i], result});
            if(!result.empty()) ++generated;
            std::cout << "REPLAY_RESPONSE[" << i << "]= " << result << "\n";
            if(((i + 1) % 8)==0) std::cerr<<"REPLAY_PROGRESS="<<(i + 1)<<"/"<<limit<<"\n";
            if(std::chrono::duration_cast<std::chrono::minutes>(std::chrono::steady_clock::now()-started).count()>=30){std::cerr<<"REPLAY_TIMEOUT\n";break;}
        }
    }
    Deep2::ReapRouteTracker::Instance().Clear(); auto m=acc.Snapshot();
    const bool mlaSeal = Deep2::MlaCertAuthority::ProductSealPass();
    if (!referenceReceiptPath.empty()) {
        if (!continuous) {
            referenceEvidence.provided = true;
            referenceEvidence.receiptPath = referenceReceiptPath;
            referenceEvidence.reason = "reference parity requires --continuous";
        } else {
            loadReferenceEvidence(referenceReceiptPath, argv[1], argv[2],
                                  continuousResult.promptTokens, continuousTokenIds,
                                  referenceEvidence);
        }
    }
    // Dense models have no MoE route observations.  That is valid calibration
    // evidence, not an incomplete run; the receipt records the distinction.
    const bool complete = continuous
        ? (generated > 0 && generated <= limit && continuousResult.completed)
        : (n==limit && generated==n);
    // A replay receipt is deliberately not promoted to full REAP certification
    // here.  Continuous decoding and the internal MLA seal are necessary, but
    // they do not establish reference parity, expert selection, GGUF rewrite,
    // reload, quality, or GPU certification.
    const bool continuousPass = continuous && complete;
    const bool parityGatePass = parity && parityPass;
    const bool referenceParityPass = referenceEvidence.pass;
    const bool certificationBlocked = requireMla && (m.empty() || !mlaSeal);
    const auto elapsedMs=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-started).count();
    std::ofstream out(argv[3],std::ios::binary); if(!out)return 4;
    const auto& gpu = engine.gpuForwardCounters();
    const bool gpuReal = engine.isRealGpuForward();
    const bool gpuDispatched = gpu.forwardLayers > 0 || gpu.layerSubmits > 0 || gpu.opSubmits > 0;
    out<<"{\"schema\":\"RAWRXD_REAP_CALIBRATION_001\",\"model\":\""<<jsonEscape(argv[1])
       <<"\",\"corpus\":\""<<jsonEscape(argv[2])
       <<"\",\"windows\":"<<(continuous ? 1 : n)
       <<",\"corpus_prompts\":"<<n<<",\"generated\":"<<generated
       <<",\"mode\":\""<<(continuous?"continuous":"independent")<<"\""
       <<",\"continuous_prefill_decode\":"<<(continuous?"true":"false")
       <<",\"continuous_completed\":"<<(continuous && continuousResult.completed?"true":"false")
       <<",\"prompt_tokens\":"<<(continuous?continuousResult.promptTokens:0)
       <<",\"decode_tokens\":"<<(continuous?continuousResult.generatedTokens:generated)
       <<",\"parity_tested\":"<<(parity?"true":"false")
       <<",\"prefill_parity_max_abs\":"<<parityMaxAbs
       <<",\"prefill_parity_pass\":"<<(parityPass?"true":"false")
       <<",\"reference_parity_tested\":"<<(referenceEvidence.provided?"true":"false")
       <<",\"reference_parity_pass\":"<<(referenceParityPass?"true":"false")
       <<",\"reference_receipt\":\""<<jsonEscape(referenceEvidence.receiptPath)<<"\""
       <<",\"reference_engine\":\""<<jsonEscape(referenceEvidence.engine)<<"\""
       <<",\"reference_reason\":\""<<jsonEscape(referenceEvidence.reason)<<"\""
       <<",\"model_first_shard_sha256\":\""<<jsonEscape(referenceEvidence.modelFirstShardSha256)<<"\""
       <<",\"corpus_sha256\":\""<<jsonEscape(referenceEvidence.corpusSha256)<<"\""
       <<",\"gpu_dispatch_observed\":"<<(gpuDispatched?"true":"false")
       <<",\"gpu_real_forward\":"<<(gpuReal?"true":"false")
       <<",\"gpu_forward_layers\":"<<gpu.forwardLayers
       <<",\"gpu_layer_submits\":"<<gpu.layerSubmits
       <<",\"gpu_op_submits\":"<<gpu.opSubmits
       <<",\"gpu_host_forward_layer_calls\":"<<gpu.hostForwardLayerCalls
       <<",\"continuous_decode_pass\":"<<(continuousPass?"true":"false")
       <<",\"internal_prefill_parity_pass\":"<<(parityGatePass?"true":"false")
       <<",\"gpu_certified\":"<<(gpuReal?"true":"false")
       <<",\"calibration_complete\":"<<((continuousPass && referenceParityPass && !m.empty())?"true":"false")
       <<",\"expert_selection_complete\":false"
       <<",\"moe_pruning_complete\":false"
       <<",\"gguf_rewrite_complete\":false"
       <<",\"reduced_model_reload_pass\":false"
       <<",\"quality_floor_pass\":false"
       <<",\"elapsed_ms\":"<<elapsedMs
       <<",\"complete\":"<<(complete?"true":"false")
       <<",\"route_metrics_available\":"<<(m.empty()?"false":"true")
       <<",\"mla_product_seal\":"<<(mlaSeal?"true":"false")
       <<",\"certification\":\"CALIBRATED_UNSEALED"
       <<"\",\"responses\":";
    writeResponses(out, responses);
    if (continuous) {
        out << ",\"continuous_token_ids\":[";
        for (size_t i = 0; i < continuousTokenIds.size(); ++i) {
            if (i) out << ',';
            out << continuousTokenIds[i];
        }
        out << "]";
    }
    out << ",\"metrics\":";
    writeMetrics(out, m);
    out << "}\n";
    std::cout<<"REPLAY_WINDOWS="<<n<<" GENERATED="<<generated<<" METRICS="<<m.size()<<" COMPLETE="<<(complete?1:0)<<"\n";
    if(!complete){std::cerr<<"REPLAY_INCOMPLETE windows="<<n<<" generated="<<generated<<" metrics="<<m.size()<<"\n";return 4;}
    if (referenceEvidence.provided && !referenceEvidence.pass) {
        std::cerr << "REFERENCE_PARITY_NOT_CERTIFIED reason=" << referenceEvidence.reason << "\n";
        return 6;
    }
    if(certificationBlocked){std::cerr<<"MLA_CERTIFICATION_BLOCKED routes="<<m.size()<<" product_seal="<<(mlaSeal?1:0)<<"\n";return 5;}
    return 0;
}
