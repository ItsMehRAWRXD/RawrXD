// submission_lifecycle_test.cpp — CPU-only adversarial lifecycle controls.
//
// Exercises the real SubmissionLifecycle / NativeCleanupGuard /
// SubmissionResourceLease with multithreaded execution, no GPU.

#include "../../src/deep2/SubmissionLifecycle.hpp"
#include "../../src/deep2/NativeCleanupGuard.hpp"
#include "../../src/deep2/SubmissionResourceLease.hpp"

#include <atomic>
#include <cstdio>
#include <memory>
#include <thread>
#include <vector>

using namespace RawrXD::Deep2;

static int passed = 0;
static int failed = 0;

static void Check(bool condition, const char* name) {
    std::printf("%s %s\n", condition ? "PASS" : "FAIL", name);
    condition ? ++passed : ++failed;
}

int main() {
    using Lifecycle = SubmissionLifecycle;
    using State = Lifecycle::State;

    {
        Lifecycle owner;
        Check(!owner.Acquire(), "initial admission closed");
        Check(owner.OpenGeneration(), "first initialized generation opened");
        auto ticket = owner.Acquire();
        Check(bool(ticket), "native acquisition registered");
        Check(!owner.Acquire(), "double acquisition refused");
        Check(!owner.MarkSubmitted(ticket), "submission without begin refused");
        Check(!owner.CompleteConfirmed(ticket), "unsubmitted completion refused");
        Check(owner.BeginCleanup(), "cleanup admission closed");
        Check(!owner.Acquire(), "cleanup rejects new acquisition");
        Check(!owner.CanDestroyResources(), "acquired resources protected");
        Check(owner.BeginSubmit(ticket), "existing admitted submission may finish");
        Check(!owner.CanDestroyResources(), "submitting resources protected");
        Check(!owner.CancelUnsubmitted(ticket), "in-progress submit cancellation refused");
        Check(owner.MarkSubmitted(ticket), "successful submission registered");
        Check(!owner.CanDestroyResources(), "pending GPU resources protected");
        Check(owner.CompleteConfirmed(ticket), "confirmed submission completed");
        Check(owner.CanDestroyResources(), "completed resources reclaimable");
        Check(owner.FinishCleanup(), "cleanup completed");
        Check(!owner.Acquire(), "cleanup does not reopen admission");
        Check(owner.OpenGeneration(), "fresh initialization reopens admission");
        auto next = owner.Acquire();
        Check(next.generation != ticket.generation, "device generation advances");
        Check(!owner.BeginSubmit(ticket), "stale generation submit refused");
        Check(!owner.MarkSubmitted(ticket), "stale notification refused");
        Check(!owner.CompleteConfirmed(ticket), "stale completion refused");
        Check(owner.CancelUnsubmitted(next), "current unsubmitted ticket canceled");
    }

    {
        Lifecycle owner;
        owner.OpenGeneration();
        auto oldTicket = owner.Acquire();
        owner.CancelUnsubmitted(oldTicket);
        auto current = owner.Acquire();
        Check(oldTicket.generation == current.generation && oldTicket.acquisition != current.acquisition,
              "same-generation ABA ticket distinct");
        Check(!owner.BeginSubmit(oldTicket), "same-generation stale begin refused");
        owner.BeginSubmit(current);
        Check(!owner.MarkSubmitted(oldTicket), "same-generation stale mark refused");
        owner.MarkSubmitted(current);
        Check(!owner.CompleteConfirmed(oldTicket), "same-generation stale complete refused");
        Check(owner.CompleteConfirmed(current), "current ticket completes");
    }

    {
        Lifecycle owner;
        owner.OpenGeneration();
        auto ticket = owner.Acquire();
        owner.BeginSubmit(ticket);
        Check(owner.QuarantineSubmission(ticket), "uncertain submission quarantined");
        const auto snapshot = owner.Inspect();
        Check(snapshot.state == State::Quarantined && snapshot.terminal && snapshot.admissionBlocked,
              "quarantine closes lifecycle");
        Check(!owner.Acquire(), "quarantine rejects acquisition");
        Check(!owner.OpenGeneration(), "terminal quarantine cannot reopen");
        Check(!owner.CompleteConfirmed(ticket), "ordinary completion cannot bypass quarantine");
        Check(!owner.CanDestroyResources(), "quarantined resources protected");
    }

    {
        Lifecycle owner;
        owner.OpenGeneration();
        std::atomic<int> winners{0};
        std::atomic<int> ready{0};
        std::atomic<int> attempted{0};
        std::atomic<bool> go{false};
        std::vector<std::thread> threads;
        constexpr int count = 16;
        for (int i = 0; i < count; ++i) {
            threads.emplace_back([&] {
                ready.fetch_add(1);
                while (!go.load()) std::this_thread::yield();
                NativeCleanupGuard guard(owner);
                if (guard) winners.fetch_add(1);
                attempted.fetch_add(1);
                while (attempted.load() != count) std::this_thread::yield();
            });
        }
        while (ready.load() != count) std::this_thread::yield();
        go.store(true);
        for (auto& t : threads) t.join();
        Check(winners.load() == 1, "concurrent cleanup single owner");
        Check(!owner.Acquire(), "deferred cleanup stays blocked");
    }

    {
        Lifecycle owner;
        owner.OpenGeneration();
        auto ticket = owner.Acquire();
        SubmissionResourceLease lease;
        auto payload = std::make_shared<int>(42);
        std::weak_ptr<int> weak = payload;
        Check(lease.Attach(ticket, payload), "GPU resource lease attached");
        payload.reset();
        Check(!weak.expired(), "resource survives caller release");
        Check(lease.Seal(ticket), "submission resource set sealed");
        Check(!lease.ReleaseUnsubmitted(ticket), "sealed resources cannot cancel");
        auto stale = ticket;
        ++stale.acquisition;
        Check(!lease.ReleaseConfirmed(stale), "stale ticket cannot release resources");
        Check(!weak.expired(), "stale release retains resources");
        owner.BeginSubmit(ticket);
        owner.MarkSubmitted(ticket);
        Check(owner.CompleteConfirmed(ticket), "fixture completion transition");
        Check(lease.ReleaseConfirmed(ticket), "confirmed ticket releases resource lease");
        Check(weak.expired(), "resource reclaimed after completion");
        Check(!lease.ReleaseConfirmed(ticket), "double resource release refused");
    }

    bool stressPassed = true;
    for (unsigned iteration = 0; iteration < 2000; ++iteration) {
        Lifecycle owner;
        owner.OpenGeneration();
        Lifecycle::Ticket ticket{};
        bool cleanupWon = false;
        bool destructionAllowed = false;
        std::atomic<int> ready{0};
        std::atomic<bool> go{false};
        std::thread acquire([&] {
            ready.fetch_add(1);
            while (!go.load()) std::this_thread::yield();
            ticket = owner.Acquire();
        });
        std::thread cleanup([&] {
            ready.fetch_add(1);
            while (!go.load()) std::this_thread::yield();
            cleanupWon = owner.BeginCleanup();
            destructionAllowed = owner.CanDestroyResources();
        });
        while (ready.load() != 2) std::this_thread::yield();
        go.store(true);
        acquire.join();
        cleanup.join();
        if (!cleanupWon || (ticket && destructionAllowed)) { stressPassed = false; break; }
        if (ticket) {
            if (!owner.BeginSubmit(ticket) || !owner.MarkSubmitted(ticket) || !owner.CompleteConfirmed(ticket)) {
                stressPassed = false; break;
            }
        }
        if (!owner.CanDestroyResources() || !owner.FinishCleanup()) { stressPassed = false; break; }
    }
    Check(stressPassed, "2000 concurrent admission/cleanup races");

    std::printf("PASS_COUNT=%d FAIL_COUNT=%d\n", passed, failed);
    return failed ? 1 : 0;
}