#pragma once
#include "EditTransaction.hpp"
#include "ProcessRunner.hpp"

namespace rawrxd::closure {

struct BuildTestSpec {
    ProcessSpec build;
    std::vector<ProcessSpec> tests;
};

struct BuildTestReceipt {
    bool passed{};
    ProcessResult build;
    std::vector<ProcessResult> tests;
    std::string failure;
};

class BuildTestGate {
public:
    explicit BuildTestGate(IProcessRunner& runner) : runner_(runner) {}
    BuildTestReceipt verify(const BuildTestSpec&) const;

    // Transaction only becomes authoritative if all build/test checks pass.
    BuildTestReceipt verify_and_commit(EditTransaction& tx,
                                       const BuildTestSpec& spec,
                                       std::string* commit_error = nullptr) const;
private:
    IProcessRunner& runner_;
};

} // namespace rawrxd::closure
