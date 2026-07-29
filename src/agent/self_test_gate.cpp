/**
 * @file self_test_gate.cpp
 * @brief Self-test gate – Qt-free (C++20 / Win32)
 *
 * Entry point that runs all self-tests and returns pass/fail.
 * Intended for CI or pre-commit hooks.
 */

#include "self_test_gate.hpp"
#include "self_test.hpp"
<<<<<<< HEAD
#include <cstdio>

bool runSelfTestGate() {
    fprintf(stderr, "[SelfTestGate] Starting self-test gate...\n");

    SelfTest tester;
=======
#include "rollback.hpp"

bool runSelfTestGate() {
    SelfTest st;
    Rollback rb;

    // 1. Functional Tests
    if (!st.runAll()) {
        std::cerr << "[!] Self-test failed. Reverting..." << std::endl;
        rb.revertLastCommit();
        rb.openIssue("Functional regression (Self-Test Failed)", st.lastOutput());
        return false;
    }

    // 2. Performance Regression
    if (rb.detectRegression()) {
        std::cerr << "[!] Performance regression detected. Reverting..." << std::endl;
        rb.revertLastCommit();
        rb.openIssue("Performance regression", st.lastOutput());
        return false;
    }
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

    // Optional: wire a log callback for structured output
    tester.setLogCb([](void* /*ctx*/, const char* line) {
        fprintf(stdout, "%s\n", line);
    }, nullptr);

    bool pass = tester.runAll();

    fprintf(stderr, "[SelfTestGate] Result: %s\n", pass ? "PASS" : "FAIL");
    return pass;
}

