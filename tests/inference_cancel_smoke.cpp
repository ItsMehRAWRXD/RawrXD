#include "../~dev/rawrxd/src/core/inference_cancellation.h"
#include <cassert>
#include <chrono>
#include <thread>
#include <vector>
#include <atomic>
#include <mutex>

int main() {
    using namespace rawrxd;
    {
        auto requestA = std::make_shared<InferenceCancelToken>();
        requestA->cancel(CancelReason::UserAbort);
        assert(requestA->cancelTimeNs() != 0);
        CancelCheckpoint check;
        assert(check.check(*requestA) && "Stop should be detected at first checkpoint");
        CancelCheckpoint timeoutCheck;
        assert(timeoutCheck.checkWithTimeout(*requestA));
        auto lateChild = InferenceCancelToken::createChild(requestA);
        assert(lateChild->isCancelled());
        assert(lateChild->reason() == CancelReason::ParentCancelled);
        auto requestB = std::make_shared<InferenceCancelToken>();
        assert(!requestB->isCancelled() && requestB->reason() == CancelReason::None);
    }
    {
        auto root = std::make_shared<InferenceCancelToken>();
        CancelScope scope(root, "request-A");
        auto child = InferenceCancelToken::createChild(scope.token());
        root->cancel(CancelReason::UserAbort);
        assert(scope.isCancelled() && child->isCancelled());
        assert(child->reason() == CancelReason::ParentCancelled);
    }
    // Race creation and parent cancellation repeatedly; all retained children
    // must be cancelled even when registration happens after propagation.
    for (int attempt = 0; attempt < 300; ++attempt) {
        auto parent = std::make_shared<InferenceCancelToken>();
        std::vector<std::shared_ptr<InferenceCancelToken>> children;
        std::thread create([&]() {
            for (int i = 0; i < 25; ++i)
                children.push_back(InferenceCancelToken::createChild(parent));
        });
        std::thread stop([&]() { parent->cancel(CancelReason::UserAbort); });
        create.join(); stop.join();
        for (auto& child : children) assert(child->isCancelled());
    }
    {
        auto token = std::make_shared<InferenceCancelToken>();
        token->setTimeout(15);
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
        assert(token->checkTimeout());
        assert(token->reason() == CancelReason::Timeout);
    }
    {
        auto token = std::make_shared<InferenceCancelToken>();
        CancelableForward forward(token, 20);
        int layers = 0;
        auto result = forward.runLayers(30, [&](int32_t layer) {
            assert(layer == layers++);
            if (layer == 2) token->cancel(CancelReason::UserAbort);
            return true;
        });
        assert(result.status == CancelableStatus::Cancelled);
        assert(result.value == 3 && layers == 3);
        assert(result.cancelReason == CancelReason::UserAbort);
    }
    {
        CancelableForward noToken(nullptr);
        assert(noToken.runLayers(1, [](int32_t) { return true; }).status == CancelableStatus::Error);
        assert(noToken.shouldStop());
    }
    {
        auto token = std::make_shared<InferenceCancelToken>();
        CancelableForward complete(token);
        auto result = complete.runLayers(6, [](int32_t) { return true; });
        assert(result.ok() && result.value == 6);
    }
}
