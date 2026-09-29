// IdeChatAuthority.h — RAWRXD_IDE_CHAT_AUTHORITY_001
#pragma once
#include <string>
#include <cstdint>
namespace rawrxd { namespace ide {
void submitChatPrompt(const std::string& prompt);
void streamChatToken(const std::string& token);
void finishChatResponse();
void writeChatReceipt(const std::string& path);
}} // namespace rawrxd::ide