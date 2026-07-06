#pragma once

#include <cstdint>
#include <string>

namespace RawrXD::Agentic {

struct AutonomousSubagentTask {
	uint64_t id = 0;
	std::string title;
	std::string payload;
	int priority = 0;
};

enum class AutonomousSubagentState : uint8_t {
	Idle = 0,
	Running,
	Succeeded,
	Failed
};

class AutonomousSubagent {
public:
	explicit AutonomousSubagent(std::string name)
		: m_name(std::move(name)) {}

	const std::string& name() const { return m_name; }
	AutonomousSubagentState state() const { return m_state; }
	const std::string& lastError() const { return m_lastError; }

	bool run(const AutonomousSubagentTask& task) {
		m_state = AutonomousSubagentState::Running;
		m_lastError.clear();

		if (task.title.empty()) {
			m_state = AutonomousSubagentState::Failed;
			m_lastError = "task title is empty";
			return false;
		}

		// Deterministic baseline behavior; real execution is delegated by caller.
		m_state = AutonomousSubagentState::Succeeded;
		return true;
	}

private:
	std::string m_name;
	AutonomousSubagentState m_state{AutonomousSubagentState::Idle};
	std::string m_lastError;
};

} // namespace RawrXD::Agentic
