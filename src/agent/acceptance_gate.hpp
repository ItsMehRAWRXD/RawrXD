// acceptance_gate.hpp -- RAWRXD_ACCEPTANCE_GATE_001
//
// Distinguishes "the command ran" from "the task succeeded".
//
// A tool invocation succeeding is not the same as the requested operation
// succeeding. This header evaluates explicit acceptance criteria against a
// captured process outcome and reports the first failing condition, so callers
// cannot silently convert a non-result into success.
//
// Header-only and dependency-free so the CLI, the GUI harness and tests share
// one definition.

#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace rawrxd {

// Captured outcome of one command. Mirrors NativeProcessResult
// (src/agent/native_process.hpp) without depending on it, so the gate is
// testable on any host.
struct ProcessOutcome {
    bool launched = false;
    int exitCode = -1;
    bool timedOut = false;
    std::string error;       // e.g. "COMMAND_TIMEOUT"
    std::string stdoutText;
    std::string stderrText;
};

struct AcceptanceCriteria {
    std::optional<int> expectedExit;          // required exit code
    std::string stdoutMustContain;            // required stdout marker
    std::string stderrMustContain;            // required stderr marker
    std::optional<std::size_t> minStdoutLen;  // minimum stdout length
    bool failOnTimeout = true;
};

struct AcceptanceResult {
    bool passed = false;
    std::string firstFailure;                 // empty when passed
};

namespace detail {

inline bool Contains(const std::string& haystack, std::string_view needle)
{
    return needle.empty() || haystack.find(needle) != std::string::npos;
}

}  // namespace detail

inline AcceptanceResult EvaluateAcceptance(const ProcessOutcome& outcome,
                                           const AcceptanceCriteria& criteria)
{
    AcceptanceResult r;

    if (!outcome.launched) {
        r.firstFailure = "not_launched";
        return r;
    }
    if (outcome.timedOut && criteria.failOnTimeout) {
        r.firstFailure = "timeout";
        return r;
    }
    if (!outcome.error.empty()) {
        r.firstFailure = "error=" + outcome.error;
        return r;
    }
    if (criteria.expectedExit && outcome.exitCode != *criteria.expectedExit) {
        r.firstFailure = "exit=" + std::to_string(outcome.exitCode) +
                         " expected=" + std::to_string(*criteria.expectedExit);
        return r;
    }
    if (!detail::Contains(outcome.stdoutText, criteria.stdoutMustContain)) {
        r.firstFailure = "missing_stdout_marker=" + criteria.stdoutMustContain;
        return r;
    }
    if (!detail::Contains(outcome.stderrText, criteria.stderrMustContain)) {
        r.firstFailure = "missing_stderr_marker=" + criteria.stderrMustContain;
        return r;
    }
    if (criteria.minStdoutLen && outcome.stdoutText.size() < *criteria.minStdoutLen) {
        r.firstFailure = "stdout_too_short=" +
                         std::to_string(outcome.stdoutText.size()) +
                         " min=" + std::to_string(*criteria.minStdoutLen);
        return r;
    }

    r.passed = true;
    return r;
}

}  // namespace rawrxd