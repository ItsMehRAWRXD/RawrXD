#include "agent_controller.hpp"
#include "../planner/planner_agent.hpp"
#include "../coder/coder_agent.hpp"
#include "../reviewer/reviewer_agent.hpp"
#include "../verifier/verifier_agent.hpp"
#include "../recovery/recovery_agent.hpp"
#include <iostream>
#include <chrono>

namespace rawrxd {
namespace agent {

AgentController::AgentController()
    : state_(AgentState::Idle)
    , event_handler_(nullptr) {}

AgentController::~AgentController() = default;

bool AgentController::initialize() {
    planner_ = std::make_unique<PlannerAgent>();
    coder_ = std::make_unique<CoderAgent>();
    reviewer_ = std::make_unique<ReviewerAgent>();
    verifier_ = std::make_unique<VerifierAgent>();
    recovery_ = std::make_unique<RecoveryAgent>();

    if (!planner_->initialize() || !coder_->initialize() ||
        !reviewer_->initialize() || !verifier_->initialize() ||
        !recovery_->initialize()) {
        std::cerr << "[AgentController] Failed to initialize sub-agents" << std::endl;
        return false;
    }

    std::cout << "[AgentController] Initialized successfully" << std::endl;
    return true;
}

bool AgentController::executeTask(const TaskRequest& request) {
    if (isBusy()) {
        std::cerr << "[AgentController] Already executing a task" << std::endl;
        return false;
    }

    current_task_ = request;
    current_result_ = TaskResult{};
    current_result_.duration_ms = 0;

    auto start_time = std::chrono::high_resolution_clock::now();

    transitionTo(AgentState::Observing);
    emitEvent(AgentEventData(AgentEvent::UserRequest, "controller", request.goal));

    runExecutionLoop();

    auto end_time = std::chrono::high_resolution_clock::now();
    current_result_.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time).count();

    return current_result_.success;
}

void AgentController::runExecutionLoop() {
    const uint64_t max_iterations = current_task_.max_steps;
    uint64_t iteration = 0;
    bool task_complete = false;

    while (!task_complete && iteration < max_iterations && state_ != AgentState::Failed) {
        iteration++;

        // Phase 1: Plan
        transitionTo(AgentState::Planning);
        auto plan = planner_->generatePlan(current_task_);
        if (!plan.valid) {
            current_result_.error = "Planner failed to generate a valid plan";
            transitionTo(AgentState::Failed);
            break;
        }
        emitEvent(AgentEventData(AgentEvent::PlanReady, "planner", plan.description));

        // Phase 2: Execute (code generation)
        transitionTo(AgentState::Executing);
        for (const auto& step : plan.steps) {
            auto change = coder_->generate(step);
            if (!change.patch.empty()) {
                coder_->apply(change);
                current_result_.files_modified.push_back(change.file);
                current_result_.actions_taken.push_back("modified: " + change.file);
            }
        }
        emitEvent(AgentEventData(AgentEvent::CodeGenerated, "coder", "Code changes applied"));

        // Phase 3: Review
        transitionTo(AgentState::Reviewing);
        auto review = reviewer_->review(current_task_, current_result_);
        if (!review.accepted) {
            if (recovery_->canRecover(review)) {
                transitionTo(AgentState::Recovering);
                auto fix = recovery_->generateFix(review);
                coder_->apply(fix);
                emitEvent(AgentEventData(AgentEvent::ErrorDetected, "recovery", fix.description));
                continue; // Retry
            } else {
                current_result_.error = "Review rejected and recovery not possible";
                transitionTo(AgentState::Failed);
                break;
            }
        }

        // Phase 4: Verify (build + test)
        transitionTo(AgentState::Testing);
        auto verification = verifier_->verify(current_task_, current_result_);
        if (verification.build_ok && verification.tests_ok) {
            task_complete = true;
            current_result_.success = true;
            current_result_.summary = "Task completed successfully";
            emitEvent(AgentEventData(AgentEvent::TestPassed, "verifier", "All tests passed"));
        } else {
            if (recovery_->canRecoverFromVerification(verification)) {
                transitionTo(AgentState::Recovering);
                auto fix = recovery_->generateFixFromVerification(verification);
                coder_->apply(fix);
                emitEvent(AgentEventData(AgentEvent::TestFailed, "verifier", verification.log));
                continue; // Retry
            } else {
                current_result_.error = "Verification failed and recovery not possible";
                transitionTo(AgentState::Failed);
                break;
            }
        }
    }

    if (task_complete) {
        transitionTo(AgentState::Completed);
    } else if (state_ != AgentState::Failed) {
        current_result_.error = "Max iterations reached without completion";
        transitionTo(AgentState::Failed);
    }
}

void AgentController::handleEvent(const AgentEventData& event) {
    switch (event.type) {
        case AgentEvent::Cancelled:
            cancel();
            break;
        case AgentEvent::Timeout:
            if (isBusy()) {
                std::cerr << "[AgentController] Timeout during execution" << std::endl;
                transitionTo(AgentState::Failed);
            }
            break;
        default:
            emitEvent(event);
            break;
    }
}

AgentState AgentController::state() const { return state_; }
bool AgentController::isBusy() const {
    return state_ != AgentState::Idle && state_ != AgentState::Completed && state_ != AgentState::Failed;
}

void AgentController::cancel() {
    if (isBusy()) {
        std::cout << "[AgentController] Cancelling current task" << std::endl;
        transitionTo(AgentState::Idle);
        current_result_.success = false;
        current_result_.error = "Cancelled by user";
    }
}

void AgentController::setEventHandler(AgentEventHandler handler) {
    event_handler_ = handler;
}

void AgentController::transitionTo(AgentState new_state) {
    state_ = new_state;
    std::cout << "[AgentController] State: " << AgentStateToString(new_state) << std::endl;
}

void AgentController::emitEvent(const AgentEventData& event) {
    if (event_handler_) {
        event_handler_(event);
    }
}

} // namespace agent
} // namespace rawrxd
