#include "deep2/ReapRingOwnership.hpp"
#include <cstdio>
#include <limits>
using namespace Deep2::Submit;
struct Slot { bool inFlight = false; };
int main() {
    int pass = 0, fail = 0;
    auto check = [&](bool ok, const char* name) {
        std::printf("%s %s\n", ok ? "PASS" : "FAIL", name);
        ok ? ++pass : ++fail;
    };
    Slot ring[3]{};
    unsigned cursor = 0, selected = 99;
    check(MayResetRing(ring, false), "empty reset");
    check(FindFreeRingSlot(ring, cursor, selected) && selected == 0 && cursor == 1, "initial slot");
    ring[0].inFlight = true;
    check(!MayResetRing(ring, false), "pending blocks reset");
    check(MayResetRing(ring, true), "authorized teardown");
    check(FindFreeRingSlot(ring, cursor, selected) && selected == 1 && cursor == 2, "second slot");
    ring[1].inFlight = true;
    check(FindFreeRingSlot(ring, cursor, selected) && selected == 2 && cursor == 0, "wrap");
    ring[2].inFlight = true;
    selected = 99;
    check(!FindFreeRingSlot(ring, cursor, selected), "full ring rejected");
    check(cursor == 0 && selected == 99, "failure leaves cursor and output unchanged");
    ring[1].inFlight = false;
    check(FindFreeRingSlot(ring, cursor, selected) && selected == 1 && cursor == 2, "skip outstanding slot");
    check(!MayResetRing(ring, false), "partial completion blocks reset");
    ring[0].inFlight = ring[2].inFlight = false;
    check(MayResetRing(ring, false), "all consumed permits reset");
    cursor = std::numeric_limits<unsigned>::max();
    check(FindFreeRingSlot(ring, cursor, selected) && selected < 3 && cursor < 3, "cursor overflow safe");
    Slot commandRing[4]{{true},{true},{true},{false}};
    cursor = 0;
    check(FindFreeRingSlot(commandRing, cursor, selected) && selected == 3, "four-slot command ring");
    commandRing[3].inFlight = true;
    check(!FindFreeRingSlot(commandRing, cursor, selected), "command ring full rejected");
    check(!MayResetRing(commandRing, false), "command reset rejects outstanding tickets");
    check(MayResetRing(commandRing, true), "command teardown permitted");
    std::printf("PASS_COUNT=%d FAIL_COUNT=%d\n", pass, fail);
    return fail ? 1 : 0;
}
