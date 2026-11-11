#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>

namespace RawrXD::Agentic {

class AgenticFailureDetector {
public:
	struct Stats {
		uint64_t totalFailures = 0;
		uint64_t recentFailures = 0;
		uint64_t circuitTrips = 0;
	};

	static AgenticFailureDetector& instance() {
		static AgenticFailureDetector inst;
		return inst;
	}

	void configure(uint32_t maxFailuresPerWindow, std::chrono::seconds window) {
		std::lock_guard<std::mutex> lock(m_mutex);
		m_maxFailuresPerWindow = (maxFailuresPerWindow == 0) ? 1 : maxFailuresPerWindow;
		m_window = window;
	}

	void recordFailure() {
		const auto now = std::chrono::steady_clock::now();
		std::lock_guard<std::mutex> lock(m_mutex);

		if (now - m_windowStart > m_window) {
			m_windowStart = now;
			m_recentFailures = 0;
		}

		++m_recentFailures;
		++m_totalFailures;

		if (m_recentFailures >= m_maxFailuresPerWindow) {
			m_circuitOpen.store(true);
			++m_circuitTrips;
		}
	}

	bool isCircuitOpen() const {
		return m_circuitOpen.load();
	}

	void reset() {
		std::lock_guard<std::mutex> lock(m_mutex);
		m_recentFailures = 0;
		m_windowStart = std::chrono::steady_clock::now();
		m_circuitOpen.store(false);
	}

	Stats getStats() const {
		std::lock_guard<std::mutex> lock(m_mutex);
		Stats s;
		s.totalFailures = m_totalFailures;
		s.recentFailures = m_recentFailures;
		s.circuitTrips = m_circuitTrips;
		return s;
	}

private:
	AgenticFailureDetector()
		: m_windowStart(std::chrono::steady_clock::now()) {}

	mutable std::mutex m_mutex;
	std::chrono::steady_clock::time_point m_windowStart;
	std::chrono::seconds m_window{30};
	uint32_t m_maxFailuresPerWindow = 3;

	uint64_t m_totalFailures = 0;
	uint64_t m_recentFailures = 0;
	uint64_t m_circuitTrips = 0;
	std::atomic<bool> m_circuitOpen{false};
};

} // namespace RawrXD::Agentic
