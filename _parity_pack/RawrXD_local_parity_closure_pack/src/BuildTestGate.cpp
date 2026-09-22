#include "rawrxd/closure/BuildTestGate.hpp"

namespace rawrxd::closure {

BuildTestReceipt BuildTestGate::verify(const BuildTestSpec& spec) const {
    BuildTestReceipt out;
    out.build = runner_.run(spec.build);
    if (!out.build.launched || out.build.timed_out || out.build.exit_code != 0) {
        out.failure = "build failed";
        return out;
    }
    for (const auto& t : spec.tests) {
        auto r = runner_.run(t);
        const bool ok = r.launched && !r.timed_out && r.exit_code == 0;
        out.tests.push_back(std::move(r));
        if (!ok) {
            out.failure = "test failed";
            return out;
        }
    }
    out.passed = true;
    return out;
}

BuildTestReceipt BuildTestGate::verify_and_commit(EditTransaction& tx,
                                                  const BuildTestSpec& spec,
                                                  std::string* commit_error) const {
    BuildTestReceipt out;
    if (!tx.apply(commit_error)) {
        out.failure = "transaction apply failed";
        return out;
    }

    // Build/tests now observe the proposed edits. A failure restores the prior tree.
    out = verify(spec);
    if (!out.passed) {
        tx.rollback();
        return out;
    }

    if (!tx.finalize(commit_error)) {
        out.passed = false;
        out.failure = "verification passed but transaction finalize failed";
        tx.rollback();
    }
    return out;
}

} // namespace rawrxd::closure
