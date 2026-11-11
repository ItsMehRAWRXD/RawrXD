#include "native_agent_bridge.hpp"
#include <cassert>
#include <iostream>
int main() {
    using namespace RawrXD::NativeBridge;
    AgentOrchestrator agent;
    agent.tools().registerTool("echo", [](const std::vector<std::string>& a, const std::atomic<bool>&)->Result {
        return {true, a.empty() ? "" : a.front(), {}};
    });
    assert(agent.submit({"first", "echo", {"real"}, {}}));
    assert(agent.submit({"second", "echo", {"execution"}, {"first"}}));
    auto result = agent.run();
    assert(result.size() == 2 && result[0].result.ok && result[1].result.ok);
    assert(result[0].result.output == "real");
    assert(result[1].result.output == "execution");
    std::atomic<bool> cancel{false};
    CEOAgent ceo([](const std::string& prompt, const std::atomic<bool>&)->Result {
        return {true, prompt, {}};
    });
    assert(ceo.plan("test", cancel).ok);
    std::cout << "NATIVE_BRIDGE_TEST_PASS\n";
}
