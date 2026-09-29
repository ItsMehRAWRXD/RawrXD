// AgentAuthority.h — RAWRXD_AGENT_AUTHORITY_001
#pragma once
#include <string>
#include <cstdint>
namespace rawrxd { namespace agent {
enum class State { Ask, Plan, Code, Debug, Orchestrate, Certify };
void plan(const std::string& task);
void act(const std::string& action);
bool verify(const std::string& result);
void writeAgentReceipt(const std::string& path);
}} // namespace rawrxd::agent