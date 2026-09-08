// product_deep2_infer.cpp — Deep2 COMPLETE via lavapath ProductRun only
#include "product_deep2_infer.hpp"
#include "../../deep2/lavapath/ProductRun.hpp"
#include "../../deep2/SemanticSafe.hpp"
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>

namespace rawr {
namespace {

struct Session {
    Deep2::Deep2Engine engine;
    bool open = false;
    std::string alias;
};

Session& S() {
    static Session s;
    return s;
}
std::mutex& Mu() {
    static std::mutex m;
    return m;
}

const char* Alias() {
    if (const char* e = std::getenv("RAWRXD_PRODUCT_MODEL"))
        if (e && e[0]) return e;
    return "llama32";
}

} // namespace

bool ProductOpenSession(const char* modelAliasOrPath) {
    std::lock_guard<std::mutex> lock(Mu());
    Session& s = S();
    Deep2::SemanticSafeApply();
    const char* a =
        (modelAliasOrPath && modelAliasOrPath[0]) ? modelAliasOrPath : Alias();
    if (s.open && s.alias == a && s.engine.isModelLoaded()) return true;
    if (s.open) {
        s.engine.unloadModel();
        s.open = false;
    }
#ifdef _WIN32
    _putenv_s("RAWRXD_PRODUCT_MODEL", a);
#endif
    Deep2::rawr_run::RunWitness w{};
    if (!Deep2::rawr_run::OpenSession(s.engine, a, w)) {
        s.open = false;
        return false;
    }
    s.alias = a;
    s.open = true;
    return true;
}

void ProductCloseSession() {
    std::lock_guard<std::mutex> lock(Mu());
    Session& s = S();
    if (s.open) s.engine.unloadModel();
    s.open = false;
    s.alias.clear();
}

bool ProductSessionOpen() {
    std::lock_guard<std::mutex> lock(Mu());
    return S().open && S().engine.isModelLoaded();
}

void ProductRequestCancel() {
    std::lock_guard<std::mutex> lock(Mu());
    S().engine.requestCancel();
}

bool ProductDeep2InferStream(const char* prompt, uint32_t maxTokens,
                             const std::function<bool(const std::string&)>& onPiece,
                             std::string* outText, const char** outFailedStage,
                             const char** outFailedOwner, const char** outExitReason,
                             int* outFirstToken) {
    std::lock_guard<std::mutex> lock(Mu());
    Session& s = S();
    Deep2::SemanticSafeApply();
#ifdef _WIN32
    _putenv_s("RAWRXD_GREEDY", "1");
    _putenv_s("RAWRXD_DECODE_FEEDBACK", "0");
#endif
    const char* a = Alias();
    if (s.open && s.alias != a) {
        s.engine.unloadModel();
        s.open = false;
    }
    const std::string user = prompt && prompt[0] ? prompt : "complete";
    product_run::Request req{};
    req.modelAlias = a;
    req.prompt = user.c_str();
    req.maxTokens = maxTokens ? maxTokens : 64u;
    req.engine = &s.engine;
    req.keepOpen = 1;
    req.onPiece = onPiece;
    auto rc = product_run::ProductRun(req);
    s.alias = a;
    s.open = s.engine.isModelLoaded();
    if (outText) *outText = rc.text;
    if (outFailedStage) *outFailedStage = rc.failedStage;
    if (outFailedOwner) *outFailedOwner = rc.failedOwner;
    if (outExitReason) *outExitReason = rc.exitReason;
    if (outFirstToken) *outFirstToken = rc.firstToken;
    return rc.productPass != 0;
}

bool ProductDeep2Infer(const char* prompt, char* out, size_t cap) {
    if (!out || cap < 2) return false;
    out[0] = 0;
    std::string text;
    if (!ProductDeep2InferStream(prompt, 48, {}, &text) || text.empty())
        return false;
    size_t n = text.size();
    if (n >= cap) n = cap - 1;
    std::memcpy(out, text.data(), n);
    out[n] = 0;
    return true;
}

} // namespace rawr
