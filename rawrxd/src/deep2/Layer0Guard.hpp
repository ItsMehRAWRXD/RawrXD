// ============================================================================
// RAWRXD_LAYER0_AUTHORITY_001
//
// The layer over Layer 0.
//
// Layer 0 of a reverse investigation is the observable effect: exit code,
// exception status, faulting address, register state at the moment the engine
// stopped. This project's Layer 0 has been unavailable four separate times,
// always for the same reason: the binary that produced the effect could not be
// identified, symbolised, or reproduced.
//
// Two causes, one fix each.
//
//   CAUSE 1 -- the observation required tooling that is not installed.
//   A WER event gives an exception code but no registers; registers need cdb or
//   a dump; cdb is not installed; the dump was never produced. The information
//   was in the process the whole time and nobody was inside it.
//
//   This guard installs exception handlers IN-PROCESS. It sees the
//   EXCEPTION_RECORD and the CONTEXT directly, so it captures
//   ExceptionCode, ExceptionInformation[], RIP, RSP and RCX without a debugger,
//   without a dump, and without the CRT fast-fail table being reverse engineered
//   out of the instruction stream.
//
//   CAUSE 2 -- the effect was produced by a binary no tracked source declares.
//   That is not a discipline problem, it is a missing precondition, so it is
//   enforced here: the guard REFUSES to arm unless the running image's SHA256
//   matches an identity supplied from outside the process.
//
// Two non-negotiable properties, both of which exist to stop this layer from
// becoming the next thing that reports a confident wrong answer:
//
//   IT NEVER INVENTS A LAYER 0 RECORD. If the image cannot be identified, the
//   guard emits EXIT=2 with LAYER0=REFUSED_NO_IDENTITY and no register data. It
//   does not emit a record with empty fields, and it does not emit one "for
//   reference". An absent observation and an observation of absence must not
//   look the same.
//
//   IT PROVES IT CAN FAIL. VECTORED_CAPTURE_ARMED is set in the handler's first
//   instruction; the field is named after that fact so it can only mean what it
//   says. A guard that reports a capture without having been inside the handler
//   is reporting a hardcoded literal, which is the exact defect this project has
//   produced repeatedly.
// ============================================================================

#pragma once

#include <cstdint>
#include <string>

namespace Deep2::Layer0 {

// The captured first-stop. All fields are observations, never defaults: the
// struct is filled only inside the handler, and the writer refuses to emit a
// record that was not filled by the handler.
struct FirstStop {
    bool            captured = false;     // handler actually ran
    bool            continued = false;    // handler returned EXCEPTION_CONTINUE
    std::uint64_t   exceptionCode = 0;
    std::uint64_t   exceptionFlags = 0;
    std::uint64_t   exceptionAddress = 0;
    std::uint64_t   info[4] = {0, 0, 0, 0};
    std::uint32_t   infoCount = 0;
    std::uint64_t   rip = 0;
    std::uint64_t   rsp = 0;
    std::uint64_t   rbp = 0;
    std::uint64_t   rcx = 0;
    std::uint64_t   rdx = 0;
    std::uint64_t   rax = 0;
    std::uint32_t   threadId = 0;
    // For 0xC0000409: the fast-fail sub-code as seen two independent ways.
    // Recorded separately because a disagreement between them is itself the most
    // informative possible output -- it means the frame was already disturbed.
    bool            isFailFast = false;
    std::uint64_t   failCodeFromInfo = 0;
    std::uint64_t   failCodeFromRcx = 0;
    bool            failCodeAgrees = false;
    std::uint32_t   frameReturn[16] = {0};  // stack words, RVA-less by design
    std::uint32_t   frameCount = 0;
};

// Install the handlers. Safe to call once; subsequent calls are no-ops that
// report the prior state. Returns true if both handlers installed.
bool Arm();

// True once the in-process exception handler has actually observed an
// exception. This is NOT a configuration flag: it is set inside the handler.
// Before any exception it is false, which is what makes it a falsification
// target rather than a decoration.
bool VectoredCaptureArmed();

// The captured first stop, or a default-constructed one if nothing was caught.
const FirstStop& GetFirstStop();

// Write the record. `stageW` labels where in the run the stop happened.
// Returns false -- and writes nothing -- when no handler-populated record
// exists, so an empty file can never be mistaken for a clean run.
bool WriteRecord(const wchar_t* pathW, const wchar_t* stageW);

// Whether this guard can observe a 0xC0000409 (__fastfail / int 29h).
// MEASURED FALSE. x64 fast-fail is consumed by the kernel and terminated
// without delivery to a vectored handler or a structured handler, so no
// in-process technique recovers it. Callers must treat a fast-fail as
// unobservable here and say so rather than infer a reason from an absent record.
bool FastFailCapturableByThisGuard();

// SHA256 of an explicit buffer, uppercase hex. Self-contained; validated in the
// probe against the published FIPS-180-2 known-answer vectors, because a hash
// that silently returns a wrong-but-plausible value would corrupt every identity
// decision downstream of it.
std::wstring Sha256HexOfBytes(const void* data, std::size_t n);

// SHA256 of a file, uppercase hex. Empty on failure.
std::wstring HashFileSha256(const wchar_t* pathW);

}  // namespace Deep2::Layer0
