// rawr_terminal_client.hpp — talk to host; auto-spawn if needed
#pragma once
#include "rawr_terminal_protocol.hpp"
#include <string>

namespace rawr::term {

bool EnsureHostRunning(const std::string& hostExePath);
bool TermClientTransact(const std::string& req, std::string& rsp);
bool TermClientStart(const std::string& name, const std::string& cmd,
                     std::string& rsp);
bool TermClientTail(const std::string& name, size_t maxBytes, std::string& data);
bool TermClientStatus(const std::string& name, std::string& rsp);
bool TermClientStop(const std::string& name, std::string& rsp);
bool TermClientSend(const std::string& name, const std::string& text,
                    std::string& rsp);
bool TermClientList(std::string& data);
bool TermClientKillAll(std::string& rsp);

} // namespace rawr::term
