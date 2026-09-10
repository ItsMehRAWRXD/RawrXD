#pragma once
/* TODO = missing edge — not a word/label/wish/metaphor.
 * KIND ∈ SOURCE|BUILD|RUNTIME|MEASUREMENT|DISPOSITION
 * IF no file|symbol|dep|emit|disposition → WORDS_DUST else SOURCE_DROP_WORK
 * ≤70 lines. */
#include <cstdint>
#include <cstdio>

namespace rawr::todo {

enum class Kind : uint8_t {
    Source = 0,
    Build = 1,
    Runtime = 2,
    Measurement = 3,
    Disposition = 4
};

inline const char* KindName(Kind k) noexcept {
    switch (k) {
    case Kind::Source: return "SOURCE_EDGE";
    case Kind::Build: return "BUILD_EDGE";
    case Kind::Runtime: return "RUNTIME_EDGE";
    case Kind::Measurement: return "MEASUREMENT_EDGE";
    case Kind::Disposition: return "DISPOSITION_EDGE";
    }
    return "WORDS_DUST";
}

/* Missing executable edge — fill all fields or it stays dust. */
struct Edge {
    Kind kind = Kind::Runtime;
    const char* owner = nullptr;     /* symbol / component */
    const char* file = nullptr;      /* path */
    const char* inState = nullptr;   /* input */
    const char* outState = nullptr;  /* output */
    const char* dep = nullptr;       /* producer complete condition */
    const char* emitReq = nullptr;   /* runtime evidence keys */
    const char* completion = nullptr;/* pass/fail disposition */
};

inline int Complete(const Edge& e) noexcept {
    return e.owner && e.file && e.inState && e.outState && e.dep &&
                   e.emitReq && e.completion
               ? 1
               : 0;
}

inline void Emit(FILE* f, const Edge& e) noexcept {
    if (!f) f = stderr;
    const int ok = Complete(e);
    std::fprintf(f,
                 "TODO_KIND=%s\nOWNER=%s\nFILE=%s\nIN=%s\nOUT=%s\nDEP=%s\n"
                 "EMIT_REQ=%s\nCOMPLETION=%s\nTODO_COMPLETE=%d\n"
                 "STATUS=%s\nCLAIM_INHERITANCE=0\n",
                 KindName(e.kind),
                 e.owner ? e.owner : "", e.file ? e.file : "",
                 e.inState ? e.inState : "", e.outState ? e.outState : "",
                 e.dep ? e.dep : "", e.emitReq ? e.emitReq : "",
                 e.completion ? e.completion : "", ok,
                 ok ? "SOURCE_DROP_WORK" : "WORDS_DUST");
}

} // namespace rawr::todo
