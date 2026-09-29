// IdeChatAuthority.cpp — RAWRXD_IDE_CHAT_AUTHORITY_001
#include "IdeChatAuthority.h"
#include "../ReceiptAuthority.h"
#include <atomic>
#include <string>
namespace rawrxd { namespace ide {
static std::atomic<int> g_promptsSubmitted{0};
static std::atomic<int> g_tokensStreamed{0};
static std::atomic<int> g_responsesFinished{0};
static std::string g_lastPrompt;
static std::mutex g_promptMutex;
void submitChatPrompt(const std::string& prompt) {
    g_promptsSubmitted.fetch_add(1);
    std::lock_guard<std::mutex> lk(g_promptMutex);
    g_lastPrompt = prompt;
}
void streamChatToken(const std::string& token) { g_tokensStreamed.fetch_add(1); }
void finishChatResponse() { g_responsesFinished.fetch_add(1); }
void writeChatReceipt(const std::string& path) {
    rawrxd::receipt::beginGate(path, "RAWRXD_IDE_CHAT_AUTHORITY_001");
    rawrxd::receipt::writeKeyValueInt(path, "PROMPTS_SUBMITTED", g_promptsSubmitted.load());
    rawrxd::receipt::writeKeyValueInt(path, "TOKENS_STREAMED", g_tokensStreamed.load());
    rawrxd::receipt::writeKeyValueInt(path, "RESPONSES_FINISHED", g_responsesFinished.load());
    std::string promptCopy;
    { std::lock_guard<std::mutex> lk(g_promptMutex); promptCopy = g_lastPrompt; }
    rawrxd::receipt::writeKeyValue(path, "LAST_PROMPT", promptCopy);
    rawrxd::receipt::endGate(path, (g_tokensStreamed.load() > 0) ? "PASS" : "FAIL");
}
}} // namespace rawrxd::ide