#include "RawrDelegationBridge.hpp"
namespace rawr::live {
void attachDelegationObserver(RawrXD::Delegation::DelegationManager& manager,Sink& sink){
    manager.onAgentStateChanged([&sink](const std::string& agentId,RawrXD::Delegation::AgentState state){
        using RawrXD::Delegation::AgentState;
        std::string phase="info";
        if(state==AgentState::Running)phase="start";
        if(state==AgentState::Completed)phase="ok";
        if(state==AgentState::Failed||state==AgentState::Cancelled||state==AgentState::TimedOut)phase="fail";
        sink.emit(Event{.worker=agentId,.kind="agent",.phase=phase,
                        .title="Delegated agent state",.detail=RawrXD::Delegation::stateName(state)});
    });
    manager.onMessage([&sink](const RawrXD::Delegation::AgentMessage& m){
        // Worker-to-worker communications are not inherently completed actions.
        sink.emit(Event{.worker=m.fromAgentId,.kind="agent",.phase="info",
                        .title="Agent message: "+m.subject,.detail=m.body});
    });
}
}
