// StageProof.hpp — execute only on acquired, validated artifacts.
#pragma once
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace Deep2 {
namespace Proof {

enum class Stage : uint8_t {
    Identity = 0,
    Description,
    Address,
    Acquire,
    Validate,
    Execute,
    Produce,
    Release
};

struct View {
    const char* tensorId = "";
    uint16_t type = 0;
    uint64_t elementCount = 0;
    uint64_t byteCount = 0;
    const void* mapped = nullptr;
    bool acquired = false;
};

struct Artifact {
    const char* name = "";
    View view{};
    bool valid = false;
    const char* missingPrereq = nullptr; // named absent input, else null
};

inline Artifact Fail(const char* name, const char* prereq) {
    Artifact a;
    a.name = name ? name : "";
    a.valid = false;
    a.missingPrereq = prereq ? prereq : "UNKNOWN";
    return a;
}

inline Artifact Ok(const char* name, const View& v) {
    Artifact a;
    a.name = name ? name : "";
    a.view = v;
    a.valid = v.acquired && v.mapped && v.elementCount > 0;
    a.missingPrereq = a.valid ? nullptr : "VIEW_INVALID";
    return a;
}

inline bool RequireAcquired(const View& v, uint64_t expectN, uint16_t expectType,
                            const char** missOut) {
    if (!v.acquired || !v.mapped) {
        if (missOut) *missOut = "VIEW_NOT_ACQUIRED";
        return false;
    }
    if (v.elementCount != expectN) {
        if (missOut) *missOut = "VIEW_ELEMENT_COUNT";
        return false;
    }
    if (v.type != expectType) {
        if (missOut) *missOut = "VIEW_TYPE";
        return false;
    }
    if (missOut) *missOut = nullptr;
    return true;
}

inline void EmitFail(const char* stage, const Artifact& a) {
    std::fprintf(stderr,
                 "PROOF_STAGE=%s ARTIFACT=%s VALID=0 MISSING_PREREQ=%s\n",
                 stage ? stage : "", a.name ? a.name : "",
                 a.missingPrereq ? a.missingPrereq : "UNKNOWN");
    std::fflush(stderr);
}

} // namespace Proof
} // namespace Deep2
