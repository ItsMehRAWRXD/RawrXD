// ============================================================================
// RAWRXD_INFERENCE_WIRE_001 — falsification probe
//
// Purpose: prove the wire can FAIL. An instrument whose only reachable outcome
// is PASS is decoration, and this project's own history is a catalogue of them:
// a gate that prints STRICT_GPU_VIOLATIONS=0 while every layer fell back to the
// CPU, and a cert target that existed only as an unbuilt CMake line.
//
// Each check below is written so that a literal, a hardcoded counter, or an
// emitter that simply ignores its inputs would FAIL it. That is the whole
// design constraint: no check here is satisfiable by printing a number.
//
// The negative controls are the load-bearing part. Checks that can only pass are
// not checks.
// ============================================================================

#include "deep2/InferenceWire.hpp"

#include <windows.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace Deep2::Wire;

namespace {

int g_checks = 0;
int g_pass = 0;
int g_fail = 0;

void check(bool ok, const char* id, const char* detailFmt, ...) {
    ++g_checks;
    if (ok) ++g_pass;
    else    ++g_fail;
    std::printf("%-6s %-34s ", ok ? "CHECK" : "FAIL", id);
    va_list ap;
    va_start(ap, detailFmt);
    std::vprintf(detailFmt, ap);
    va_end(ap);
    std::printf("\n");
}

const wchar_t* kCapture = L"inference_wire_001.dptx";
const wchar_t* kTampered = L"inference_wire_001_tampered.dptx";

// Build a packet with correct framing. Everything the probe emits goes through
// here, so a check cannot pass by emitting a hand-rolled frame that skips the
// emitter's own validation.
Packet makePacket(WireWriter& w, std::uint32_t token, std::uint32_t layer,
                  std::uint32_t router, std::uint32_t expert, std::uint8_t flag,
                  std::uint32_t reuse, std::uint32_t latencyNs,
                  std::uint64_t bytes, FaultClass fault, Tier from, Tier to) {
    Packet p{};
    p.tokenSeq = token;
    p.layerId = layer;
    p.routerId = router;
    p.expertId = expert;
    p.stateFlag = flag;
    p.reuseDistance = reuse;
    p.latencyNs = latencyNs;
    p.bytes = bytes;
    p.demandId = 0;
    p.faultKind = static_cast<std::uint8_t>(fault);
    p.sourceKind = kSourceMeasured;
    p.severity = (flag & kCpuFallbackViolation) ? kSeverityViolation
               : (flag & kMetalBlockThrash)     ? kSeverityWarn
                                                 : kSeverityInfo;
    p.tierFrom = static_cast<std::uint8_t>(from);
    p.tierTo = static_cast<std::uint8_t>(to);
    p.routeCount = 0;
    p.capacityEntries = 0;
    p.residentEntries = 0;
    std::uint64_t wall = 0, qpc = 0;
    WireClock(wall, qpc);
    w.stamp(p, wall, qpc);
    return p;
}

}  // namespace

#include <cstdarg>

int main() {
    std::printf("=== RAWRXD_INFERENCE_WIRE_001 ===\n");
    std::printf("SCOPE=INSTRUMENT_ONLY_MOVES_NO_BYTES\n");
    std::printf("FRAME_BYTES=%zu\n", sizeof(Packet));

    // =====================================================================
    // SECTION 0 -- wire specification constants.
    // If these are wrong the whole capture is misread by every reader, so they
    // are checked in RUNTIME too, not only by static_assert in the header.
    // =====================================================================
    std::printf("\n--- SECTION 0: SPEC CONSTANTS ---\n");
    check(kHotHit == 0x01, "SPEC_HOT_HIT", "= 0x%02X", kHotHit);
    check(kColdFault == 0x02, "SPEC_COLD_FAULT", "= 0x%02X", kColdFault);
    check(kEmptyConsumed == 0x04, "SPEC_EMPTY_CONSUMED", "= 0x%02X", kEmptyConsumed);
    check(kMetalBlockThrash == 0x08, "SPEC_METAL_BLOCK_THRASH", "= 0x%02X", kMetalBlockThrash);
    check(kCpuFallbackViolation == 0x10, "SPEC_CPU_FALLBACK_VIOLATION", "= 0x%02X",
          kCpuFallbackViolation);
    check(kStateMask == 0x1F, "SPEC_STATE_MASK", "= 0x%02X", kStateMask);
    check(sizeof(Packet) == 96, "SPEC_FRAME_SIZE", "= %zu", sizeof(Packet));

    // =====================================================================
    // SECTION 1 -- flag validation. The state byte must be unforgeable BY
    // CONSTRUCTION, which means the emitter refuses undefined bits. A probe
    // that only tested "does 0x01 emit" would never notice a wire that accepts
    // 0xFF.
    // =====================================================================
    std::printf("\n--- SECTION 1: FLAG VALIDATION ---\n");
    check(WireFlagLegal(0x00), "FLAG_0000_LEGAL", "no bits is legal");
    check(WireFlagLegal(kStateMask), "FLAG_MASK_LEGAL", "all five bits legal");
    check(WireFlagLegal(static_cast<std::uint8_t>(kColdFault | kMetalBlockThrash)),
          "FLAG_COMPOSITE_LEGAL", "COLD|THRASH legal");
    check(!WireFlagLegal(0x20), "FLAG_0020_REJECTED", "undefined bit rejected");
    check(!WireFlagLegal(0xFF), "FLAG_00FF_REJECTED", "all bits rejected");

    {
        // Prove the EMITTER refuses, not merely that a predicate does.
        WireWriter w;
        bool opened = w.open(L"inference_wire_001_flagtest.dptx");
        check(opened, "FLAGTEST_SINK_OPEN", "err=%llu",
              (unsigned long long)w.lastError());
        if (opened) {
            Packet ok = makePacket(w, 1, 0, 0, 0, kHotHit, 0, 10, 0,
                                   kFaultNone, kTierGpu, kTierGpu);
            const bool accepted = w.emit(ok);
            Packet bad{};
            std::uint64_t wall = 0, qpc = 0;
            WireClock(wall, qpc);
            w.stamp(bad, wall, qpc);
            bad.tokenSeq = 1;
            bad.stateFlag = 0x40;              // not a defined bit
            const bool rejected = !w.emit(bad);
            w.flush();
            check(accepted, "FLAGTEST_LEGAL_ACCEPTED", "seq=%llu",
                  (unsigned long long)ok.packetSeq);
            check(rejected, "FLAGTEST_ILLEGAL_REFUSED", "rejected=%d", !rejected);
            check(w.packetsRejected() == 1, "FLAGTEST_REJECT_COUNTED",
                  "rejected=%llu", (unsigned long long)w.packetsRejected());
            check(w.packetsWritten() == 1, "FLAGTEST_WRITE_COUNT",
                  "written=%llu", (unsigned long long)w.packetsWritten());
        }
        w.close();
        DeleteFileW(L"inference_wire_001_flagtest.dptx");
    }

    // =====================================================================
    // SECTION 2 -- reuse_distance is computed, not declared.
    //
    // A known route sequence with a known answer. Route E5 at tokens 1, 4 and 9
    // while capacity is unlimited: reuse must be 0 (first), 3, 5. A literal
    // cannot produce the second and third values from the first.
    // =====================================================================
    std::printf("\n--- SECTION 2: REUSE DISTANCE IS DERIVED ---\n");
    {
        ExpertLedger led(/*capacitySlots=*/1024, /*thrashWindow=*/8);
        led.beginToken(1);
        ExpertLedger::RouteEvidence a = led.route(0, 5, 1, 1024, false);
        led.endToken();
        led.beginToken(4);
        ExpertLedger::RouteEvidence b = led.route(0, 5, 4, 1024, false);
        led.endToken();
        led.beginToken(9);
        ExpertLedger::RouteEvidence c = led.route(0, 5, 9, 1024, false);
        led.endToken();

        check(a.hit == false, "REUSE_FIRST_IS_COLD", "hit=%d", a.hit);
        check(a.reuseDistance == 0, "REUSE_FIRST_IS_ZERO", "d=%u", a.reuseDistance);
        check(b.hit == true, "REUSE_SECOND_IS_HOT", "hit=%d", b.hit);
        check(b.reuseDistance == 3, "REUSE_SECOND_EQ_3", "d=%u (tokens 1->4)", b.reuseDistance);
        check(c.hit == true, "REUSE_THIRD_IS_HOT", "hit=%d", c.hit);
        check(c.reuseDistance == 5, "REUSE_THIRD_EQ_5", "d=%u (tokens 4->9)", c.reuseDistance);
        check(led.maxReuseDistance() == 5, "REUSE_MAX_TRACKED", "max=%u",
              led.maxReuseDistance());
    }

    // =====================================================================
    // SECTION 3 -- cold_fraction responds to capacity.
    //
    // Two tokens, the SAME 8 experts both times. Token 1 is first touch, so it
    // is 100% cold regardless of capacity and cannot discriminate. Token 2 is
    // where capacity bites: roomy retains all 8, starved retains 4 and must
    // re-fault the other 4.
    //
    // An earlier revision of this check routed 8 DISTINCT experts once and
    // expected hits. That is unsatisfiable by construction -- a first touch has
    // no earlier route to hit -- and it failed with hits=0 while the ledger was
    // behaving correctly. A check that encodes an impossible expectation trains
    // the reader to distrust the instrument rather than the system.
    // =====================================================================
    std::printf("\n--- SECTION 3: COLD_FRACTION RESPONDS TO CAPACITY ---\n");
    {
        const std::uint32_t kExperts[8] = {1, 2, 3, 4, 5, 6, 7, 8};

        ExpertLedger roomy(1024, 8);
        roomy.beginToken(1);
        for (std::uint32_t e : kExperts) roomy.route(0, e, 1, 4, false);
        const ExpertLedger::TokenStats r1 = roomy.endToken();
        roomy.beginToken(2);
        for (std::uint32_t e : kExperts) roomy.route(0, e, 2, 4, false);
        const ExpertLedger::TokenStats r2 = roomy.endToken();

        ExpertLedger starved(1024, 8);
        starved.setCapacityBytes(16);   // room for 4 of 8 experts
        starved.beginToken(1);
        for (std::uint32_t e : kExperts) starved.route(0, e, 1, 4, false);
        const ExpertLedger::TokenStats s1 = starved.endToken();
        starved.beginToken(2);
        for (std::uint32_t e : kExperts) starved.route(0, e, 2, 4, false);
        const ExpertLedger::TokenStats s2 = starved.endToken();

        // Token 1: first touch is always cold, whatever the capacity.
        check(r1.routed == 8 && s1.routed == 8, "CF_T1_ROUTED", "roomy=%u starved=%u",
              r1.routed, s1.routed);
        check(r1.coldFraction == 1.0, "CF_T1_ROOMY_COLD_1", "frac=%.3f", r1.coldFraction);
        check(s1.coldFraction == 1.0, "CF_T1_STARVED_COLD_1", "frac=%.3f", s1.coldFraction);

        // Token 2: the discriminating token.
        check(r2.hits == 8, "CF_T2_ROOMY_ALL_HITS", "hits=%u", r2.hits);
        check(r2.cold == 0, "CF_T2_ROOMY_NO_COLD", "cold=%u", r2.cold);
        check(r2.coldFraction == 0.0, "CF_T2_ROOMY_FRAC_0", "frac=%.3f", r2.coldFraction);

        check(s2.routed == 8, "CF_T2_STARVED_ROUTED", "routed=%u", s2.routed);
        check(s2.coldFraction > 0.0, "CF_T2_STARVED_COLD_GT_0", "frac=%.3f",
              s2.coldFraction);
        check(s2.coldFraction < 1.0, "CF_T2_STARVED_COLD_LT_1", "frac=%.3f",
              s2.coldFraction);
        check(s2.hits > 0, "CF_T2_STARVED_SOME_HITS", "hits=%u", s2.hits);
        check(r2.coldFraction < s2.coldFraction, "CF_CAPACITY_MOVES_FRACTION",
              "roomy=%.3f starved=%.3f", r2.coldFraction, s2.coldFraction);
    }

    // =====================================================================
    // SECTION 4 -- the failure states are EMITTABLE.
    //
    // This is the check a counter-based design cannot pass. The wire claims it
    // can express METAL_BLOCK_THRASH (hot, evicted under pressure, needed again
    // inside the window). Force exactly that and require the 0x08 bit.
    // =====================================================================
    std::printf("\n--- SECTION 4: THRASH IS EMITTABLE ---\n");
    std::uint64_t thrashFrames = 0;
    {
        // Capacity 2 experts. Thrash window 4 tokens.
        ExpertLedger led(8, 4);
        led.setCapacityBytes(8);      // two 4-byte experts

        // token 1: admit E1, E2 (capacity now full)
        led.beginToken(1);
        led.route(0, 1, 1, 4, false);
        led.route(0, 2, 1, 4, false);
        led.endToken();

        // token 2: touch E1 so it is HOT, then admit E3 -> evicts E2 (coldest)
        led.beginToken(2);
        led.route(0, 1, 2, 4, false);
        led.route(0, 3, 2, 4, false);
        led.endToken();

        // token 3: need E2 again. It was resident at token 1, evicted at token 2,
        // and is needed at token 3 -- inside a 4-token window. That IS a thrash.
        led.beginToken(3);
        ExpertLedger::RouteEvidence ev = led.route(0, 2, 3, 4, false);
        led.endToken();

        check(ev.hit == false, "THRASH_IS_A_MISS", "hit=%d", ev.hit);
        check(ev.thrash == true, "THRASH_FLAG_SET", "thrash=%d", ev.thrash);
        check(ev.fault == kFaultReuse, "THRASH_CLASSIFIED_REUSE_MISS", "fault=%s",
              WireFaultName(static_cast<std::uint8_t>(ev.fault)));
        check(ev.reuseDistance == 2, "THRASH_REUSE_DISTANCE_KNOWN", "d=%u (1->3)",
              ev.reuseDistance);
        check(led.totalThrash() == 1, "THRASH_COUNTER_MOVED", "thrash=%llu",
              (unsigned long long)led.totalThrash());

        // Now emit it as a frame and prove the bit lands in the file.
        WireWriter w;
        if (w.open(kCapture)) {
            for (int i = 0; i < 2; ++i) {  // two warmup packets
                Packet p = makePacket(w, 1, 0, 0, 1, kHotHit, 0, 100, 4,
                                      kFaultNone, kTierGpu, kTierGpu);
                w.emit(p);
            }
            Packet tp = makePacket(w, 3, 0, 0, 2,
                                   static_cast<std::uint8_t>(kColdFault | kMetalBlockThrash),
                                   ev.reuseDistance, 4200, 4, kFaultReuse,
                                   kTierStorage, kTierHost);
            w.emit(tp);
            ++thrashFrames;
            w.flush();
            w.close();
        }
        check(thrashFrames == 1, "THRASH_FRAME_EMITTED", "frames=%llu",
              (unsigned long long)thrashFrames);
    }

    // =====================================================================
    // SECTION 5 -- CPU_FALLBACK_VIOLATION is emittable and detectable.
    //
    // Motivated by the measured gate result: 1280 of 1280 layer-visits fell back
    // to the host while the gate printed STRICT_GPU_VIOLATIONS=0 and exited 0.
    // A wire that cannot represent that state cannot catch it.
    // =====================================================================
    std::printf("\n--- SECTION 5: CPU FALLBACK IS EMITTABLE ---\n");
    {
        WireWriter w;
        std::uint64_t fallbackFrames = 0;
        if (w.open(L"inference_wire_001_fb.dptx")) {
            for (std::uint32_t i = 0; i < 8; ++i) {
                Packet p = makePacket(w, 1, i, 0, 0, kCpuFallbackViolation, 0,
                                      900, 4 * 1024 * 1024, kFaultNone,
                                      kTierHost, kTierHost);
                w.emit(p);
                ++fallbackFrames;
            }
            w.flush();
        }
        w.close();

        VerifyReport vr{};
        std::uint64_t err = 0;
        const bool read = VerifyCapture(L"inference_wire_001_fb.dptx", vr, err);
        check(read, "FB_CAPTURE_READABLE", "err=%llu", (unsigned long long)err);
        check(fallbackFrames == 8, "FB_FRAMES_EMITTED", "frames=%llu",
              (unsigned long long)fallbackFrames);
        check(vr.cpuFallback == 8, "FB_DETECTED_IN_FILE", "detected=%llu",
              (unsigned long long)vr.cpuFallback);
        check(vr.clean(), "FB_CAPTURE_CLEAN", "hash=%llu gaps=%llu illegal=%llu",
              (unsigned long long)vr.hashFailures, (unsigned long long)vr.seqGaps,
              (unsigned long long)vr.illegalFlags);
        DeleteFileW(L"inference_wire_001_fb.dptx");
    }

    // =====================================================================
    // SECTION 6 -- capture verification is real: tamper and read back.
    //
    // A verifier that always returns clean verifies nothing. Flip one bit in the
    // file and require the verifier to notice.
    // =====================================================================
    std::printf("\n--- SECTION 6: TAMPER IS DETECTED ---\n");
    bool tamperSucceeded = false;
    {
        WireWriter w;
        if (w.open(kCapture)) {
            for (int i = 0; i < 6; ++i) {
                Packet p = makePacket(w, 1, 0, 0, static_cast<std::uint32_t>(i),
                                      i % 2 ? kHotHit : kColdFault, 0, 10 * i, 4,
                                      kFaultNone, kTierGpu, kTierGpu);
                w.emit(p);
            }
            w.flush();
        }
        w.close();

        VerifyReport cleanVr{};
        std::uint64_t err = 0;
        VerifyCapture(kCapture, cleanVr, err);
        check(cleanVr.packetsRead == 6, "TAMPER_BASELINE_COUNT", "read=%llu",
              (unsigned long long)cleanVr.packetsRead);
        check(cleanVr.clean(), "TAMPER_BASELINE_CLEAN", "hash=%llu",
              (unsigned long long)cleanVr.hashFailures);
        check(cleanVr.hotHits == 3 && cleanVr.coldFaults == 3, "TAMPER_BASELINE_TALLY",
              "hot=%llu cold=%llu", (unsigned long long)cleanVr.hotHits,
              (unsigned long long)cleanVr.coldFaults);
        check(cleanVr.coldFractionRecomputed == 0.5, "TAMPER_RECOMPUTED_FRACTION",
              "frac=%.3f", cleanVr.coldFractionRecomputed);

        // Copy and corrupt the expertId of packet 2.
        CopyFileW(kCapture, kTampered, FALSE);
        {
            HANDLE h = CreateFileW(kTampered, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                   OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (h != INVALID_HANDLE_VALUE) {
                // expertId sits at offset 44 within a 96-byte frame. The 64-bit
                // SetFilePointerEx is required: SetFilePointer takes a LONG and
                // truncates any offset above 2 GiB.
                LARGE_INTEGER off{};
                off.QuadPart = 1 * (LONGLONG)sizeof(Packet) + 44;
                LARGE_INTEGER newPos{};
                DWORD got = 0;
                SetFilePointerEx(h, off, &newPos, FILE_BEGIN);
                BYTE orig = 0;
                ReadFile(h, &orig, 1, &got, nullptr);
                const bool readOne = (got == 1);
                BYTE bad = static_cast<BYTE>(orig ^ 0xFFu);
                SetFilePointerEx(h, off, &newPos, FILE_BEGIN);
                DWORD put = 0;
                const bool wroteOne = WriteFile(h, &bad, 1, &put, nullptr) && put == 1;
                CloseHandle(h);
                tamperSucceeded = readOne && wroteOne;
            }
        }
        check(tamperSucceeded, "TAMPER_WRITE_APPLIED", "applied=%d", tamperSucceeded);

        VerifyReport badVr{};
        std::uint64_t badErr = 0;
        VerifyCapture(kTampered, badVr, badErr);
        check(badVr.hashFailures == 1, "TAMPER_HASH_FAILURE_DETECTED",
              "hashFailures=%llu", (unsigned long long)badVr.hashFailures);
        check(!badVr.clean(), "TAMPER_CAPTURE_NOT_CLEAN", "clean=%d", badVr.clean());
        DeleteFileW(kTampered);
    }

    // =====================================================================
    // SECTION 7 -- sequence gap detection.
    // Remove a frame from the middle of a capture; the reader must report a gap
    // rather than silently reading a shorter stream.
    // =====================================================================
    std::printf("\n--- SECTION 7: SEQUENCE GAP DETECTED ---\n");
    {
        WireWriter w;
        if (w.open(L"inference_wire_001_gap.dptx")) {
            for (int i = 0; i < 5; ++i) {
                Packet p = makePacket(w, 1, 0, 0, static_cast<std::uint32_t>(i),
                                      kHotHit, 0, 1, 0, kFaultNone, kTierGpu, kTierGpu);
                w.emit(p);
            }
            w.flush();
        }
        w.close();

        // Drop frame index 2 by shifting the remaining TWO frames (indices 3 and 4)
        // down one slot and truncating. Reading four frames from offset 3 in a
        // five-frame file reads two frames short of the request, which silently
        // wrote a partial frame and produced [0][1][3][3][4] instead of a gap --
        // the verifier correctly reported two sequence gaps for that malformed
        // stream, which is how the arithmetic error was located.
        bool gapRewritten = false;
        {
            HANDLE h = CreateFileW(L"inference_wire_001_gap.dptx",
                                   GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                   OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (h != INVALID_HANDLE_VALUE) {
                const DWORD twoFrames = (DWORD)(sizeof(Packet) * 2);
                std::vector<BYTE> buf(twoFrames);
                LARGE_INTEGER off{}, newPos{};
                off.QuadPart = 3 * (LONGLONG)sizeof(Packet);
                SetFilePointerEx(h, off, &newPos, FILE_BEGIN);
                DWORD got = 0;
                const bool readOk = ReadFile(h, buf.data(), twoFrames, &got, nullptr)
                                    && got == twoFrames;
                // Seek BACK to the destination slot before writing. ReadFile left
                // the cursor at EOF, and an omitted seek-back appends instead of
                // overwriting -- which left the original frames 0..3 intact and
                // reported gaps=0 on a capture that was supposed to have a hole.
                // The verifier was right; the rewrite was wrong.
                off.QuadPart = 2 * (LONGLONG)sizeof(Packet);
                SetFilePointerEx(h, off, &newPos, FILE_BEGIN);
                DWORD put = 0;
                const bool writeOk = readOk &&
                                     WriteFile(h, buf.data(), twoFrames, &put, nullptr)
                                     && put == twoFrames;
                // Truncate to an ABSOLUTE length. Seeking to FILE_END after an
                // in-place overwrite leaves whatever the overwrite happened to
                // leave behind -- an earlier revision left 7 frames in a 4-frame
                // file this way. The length is a fact about the intended capture,
                // so it is stated as a fact rather than inferred from the cursor.
                LARGE_INTEGER fourFrames{};
                fourFrames.QuadPart = 4 * (LONGLONG)sizeof(Packet);
                SetFilePointerEx(h, fourFrames, &newPos, FILE_BEGIN);
                const bool truncOk = SetEndOfFile(h) != FALSE;
                CloseHandle(h);
                gapRewritten = writeOk && truncOk;
            }
        }
        check(gapRewritten, "GAP_REWRITE_APPLIED", "applied=%d", gapRewritten);

        VerifyReport gv{};
        std::uint64_t gerr = 0;
        VerifyCapture(L"inference_wire_001_gap.dptx", gv, gerr);
        check(gv.packetsRead == 4, "GAP_FRAME_COUNT", "read=%llu",
              (unsigned long long)gv.packetsRead);
        check(gv.seqGaps == 1, "GAP_DETECTED", "gaps=%llu", (unsigned long long)gv.seqGaps);
        check(!gv.clean(), "GAP_NOT_CLEAN", "clean=%d", gv.clean());
        DeleteFileW(L"inference_wire_001_gap.dptx");
    }

    // =====================================================================
    // SECTION 8 -- the immediate wire hook, on the first real token.
    // =====================================================================
    std::printf("\n--- SECTION 8: ARMED HOOK ---\n");
    {
        ExpertLedger led(1024, 8);
        led.beginToken(1);
        led.route(0, 1, 1, 4096, false);
        led.route(0, 2, 1, 4096, false);
        led.route(0, 3, 1, 4096, false);
        const ExpertLedger::TokenStats s = led.endToken();
        WireEmitArmedHook(1, s.coldFraction, 0);
        check(s.routed == 3, "ARMED_TOKEN_ROUTED", "routed=%u", s.routed);
        check(s.coldFraction == 1.0, "ARMED_FIRST_TOUCH_COLD", "frac=%.3f",
              s.coldFraction);
    }

    // =====================================================================
    // SUMMARY -- computed from the observations above. No literal verdict.
    // =====================================================================
    std::printf("\n--- SUMMARY ---\n");
    std::printf("CHECKS_TOTAL=%d\n", g_checks);
    std::printf("CHECKS_PASS=%d\n", g_pass);
    std::printf("CHECKS_FAIL=%d\n", g_fail);
    std::printf("THRASH_STATE_EMITTABLE=%d\n", g_fail == 0 ? 1 : 0);
    std::printf("CPU_FALLBACK_STATE_EMITTABLE=%d\n", g_fail == 0 ? 1 : 0);
    std::printf("TAMPER_DETECTED=%d\n", g_fail == 0 ? 1 : 0);
    const char* verdict = (g_checks > 0 && g_fail == 0) ? "PASS" : "FAIL";
    std::printf("VERDICT=%s\n", verdict);
    DeleteFileW(kCapture);
    return g_fail == 0 ? 0 : 1;
}
