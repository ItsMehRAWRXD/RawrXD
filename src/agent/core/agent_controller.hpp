#pragma once

#include "agent_state.hpp"
#include "agent_event.hpp"
#include <string>
#include <memory>
#include <functional>
#include <vector>

namespace rawrxd {
namespace agent {

struct TaskRequest {
    std::string goal;
    std::string context;
    std::string target_file;
    uint64_t max_steps;
    bool requires_reasoning;
    bool requires_code;

    TaskRequest() : max_steps(10), requires_reasoning(false), requires_code(false) {}
};

struct TaskResult {
    bool success;
    std::string summary;
    std::vector<std::string> files_modified;
    std::vector<std::string> actions_taken;
    uint64_t duration_ms;
    std::string error;
};

class AgentController {
public:
    AgentController();
    ~AgentController();

    bool initialize();
    bool executeTask(const TaskRequest& request);
    void handleEvent(const AgentEventData& event);
    AgentState state() const;
    bool isBusy() const;
    void cancel();
    void setEventHandler(AgentEventHandler handler);

    // Sub-agent access (for coordination)
    class PlannerAgent* planner() const { return planner_.get(); }
    class CoderAgent* coder() const { return coder_.get(); }
    class ReviewerAgent* reviewer() const { return reviewer_.get(); }
    class VerifierAgent* verifier() const { return verifier_.get(); }
    class RecoveryAgent* recovery() const { return recovery_.get(); }

private:
    AgentState state_;
    TaskRequest current_task_;
    TaskResult current_result_;
    AgentEventHandler event_handler_;

    std::unique_ptr<PlannerAgent> planner_;
    std::unique_ptr<CoderAgent> coder_;
    std::unique_ptr<ReviewerAgent> reviewer_;
    std::unique_ptr<VerifierAgent> verifier_;
    std::unique_ptr<RecoveryAgent> recovery_;

    void transitionTo(AgentState new_state);
    void emitEvent(const AgentEventData& event);
    void runExecutionLoop();
};

} // namespace agent
} // namespace rawrxd
