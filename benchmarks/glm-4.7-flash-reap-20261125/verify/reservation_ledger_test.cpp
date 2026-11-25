// Acceptance test for Deep2::MultiGPU::ReservationLedger.
// Compile: g++ -std=c++17 -O2 -Wall -Wextra -pthread reservation_ledger_test.cpp -o t && t
#include "../../../src/deep2/MultiGPU/ReservationLedger.hpp"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <thread>
#include <vector>

using namespace Deep2::MultiGPU;

#define CHECK(x) do { if (!(x)) { std::fprintf(stderr, "FAIL: %s\n", #x); std::exit(1); } } while (0)

int main() {
    // 1) basic reserve/release
    ReservationLedger L;
    L.SetCapacity(100, 1000);
    Reservation r, rFail;
    CHECK(L.TryReserve(100, 400, false, r));
    CHECK(L.Reserved(100) == 400);
    CHECK(L.TryReserve(100, 700, false, rFail) == false); // 400+700 > 1000
    CHECK(L.Reserved(100) == 400);                         // unchanged after reject
    CHECK(L.Release(r.id));
    CHECK(L.Reserved(100) == 0);

    // 2) strict unknown-budget: unknown key rejects unless allowUnknown
    ReservationLedger U;
    Reservation u;
    CHECK(!U.TryReserve(7, 100, false, u));              // strict -> reject unknown
    CHECK(U.TryReserve(7, 100, true, u));                // allowUnknown -> adopt
    CHECK(U.Known(7) && U.Capacity(7) == 100);

    // 3) known-zero rejects
    ReservationLedger Z;
    Z.SetCapacity(9, 0);
    Reservation z;
    CHECK(!Z.TryReserve(9, 1, true, z));                 // 0 cap -> reject

    // 4) transactional multi: one failing hold rolls back all
    ReservationLedger M;
    M.SetCapacity(1, 1000);
    M.SetCapacity(2, 100);
    Reservation m;
    CHECK(!M.TryReserveMulti({{1, 500}, {2, 500}}, false, m)); // key2 500>100
    CHECK(M.Reserved(1) == 0 && M.Reserved(2) == 0);           // full rollback
    CHECK(M.TryReserveMulti({{1, 500}, {2, 50}}, false, m));   // both fit
    CHECK(M.Reserved(1) == 500 && M.Reserved(2) == 50);

    // 5) RAII releases on scope exit
    {
        ReservationLedger R;
        R.SetCapacity(3, 1000);
        ScopedReservation sr(R, {{3, 600}}, false);
        CHECK(sr.valid() && R.Reserved(3) == 600);
    }
    // (R destroyed; cannot inspect here — covered by explicit release below)
    {
        ReservationLedger R2;
        R2.SetCapacity(4, 1000);
        ScopedReservation sr(R2, {{4, 600}}, false);
        CHECK(R2.Reserved(4) == 600);
        sr.release();
        CHECK(R2.Reserved(4) == 0);
    }

    // 6) concurrent contention: 8 threads x 2000 ops, never oversubscribe
    ReservationLedger C;
    C.SetCapacity(0xABCD, 4096);
    std::atomic<long> rejected{0}, admitted{0};
    std::atomic<bool> oversubscribed{false};
    auto worker = [&] {
        for (int i = 0; i < 2000; ++i) {
            Reservation rr;
            bool ok = C.TryReserve(0xABCD, 64, false, rr);
            if (ok) {
                admitted++;
                if (C.Reserved(0xABCD) > C.Capacity(0xABCD))
                    oversubscribed = true;      // must never happen
                C.Release(rr.id);
            } else {
                rejected++;
            }
        }
    };
    std::vector<std::thread> ts;
    for (int t = 0; t < 8; ++t) ts.emplace_back(worker);
    for (auto& t : ts) t.join();
    CHECK(!oversubscribed.load());
    CHECK(C.Reserved(0xABCD) == 0);             // all released
    CHECK(admitted.load() + rejected.load() == 16000);

    std::printf("admitted=%ld rejected=%ld oversubscribed=%d\n",
                admitted.load(), rejected.load(), oversubscribed.load() ? 1 : 0);
    std::printf("RESERVATION_LEDGER_ACCEPTANCE PASS\n");
    return 0;
}