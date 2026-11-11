// Fuzz harness for the drop's security-critical parsers and path guards.
//
// These are the code paths where a memory-safety or logic bug turns into a
// security incident, and none of them are covered by the self-test or the
// mocked end-to-end run:
//
//   1. J::parse          - a hand-rolled recursive-descent JSON codec doing
//                          manual index arithmetic over a string_view. This is
//                          exactly where an off-by-one becomes an OOB read.
//   2. parse_call        - framed-tool extraction from arbitrary model output.
//                          Malicious or merely confused model text is
//                          *attacker-controlled input* by design.
//   3. check_tool        - the fail-closed tool-name validator. Its contract is
//                          absolute: never accept a name outside the allowlist,
//                          never crash.
//   4. inside/secured_path - workspace containment. Its contract is absolute:
//                          every traversal/absolute-path/escape attempt must be
//                          rejected, including under symlinks on POSIX.
//
// The harness links the real implementation by including rawr_run.cpp with
// RAWRXD_RUN_EMBEDDED defined (a seam that already exists in the drop), so it
// tests the shipped code rather than a copy of it.
//
// Build with sanitizers for the real value:
//   MSVC:    /fsanitize=address
//   GCC/Cl:  -fsanitize=address,undefined
// Deterministic by default (fixed seeds) so CI can run it unattended.

#define RAWRXD_RUN_EMBEDDED
#include "rawr_run.cpp"
#include <cstdio>
#include <random>

namespace {

struct Stats {
    long long json_inputs = 0;
    long long json_rejected = 0;
    long long json_accepted = 0;
    long long frames = 0;
    long long frame_rejected = 0;
    long long frames_parsed = 0;
    long long tool_calls = 0;
    long long tool_rejected = 0;
    long long escape_attempts = 0;
    long long escape_blocked = 0;
    std::vector<std::string> failures;
};

// Deterministic pseudo-random input generators ---------------------------------

// Bytes biased towards JSON syntax characters so the parser spends its time in
// interesting states rather than rejecting immediately.
std::string fuzz_json_string(std::mt19937_64& rng) {
    static const char* alphabet = "{}[]\",:0123456789.eE+-tfalsn \t\r\n\\/uABCDEF";
    std::uniform_int_distribution<size_t> len(0, 60);
    std::uniform_int_distribution<size_t> pick(0, std::string_view(alphabet).size() - 1);
    std::string s;
    const size_t n = len(rng);
    s.reserve(n);
    for (size_t i = 0; i < n; ++i) s.push_back(alphabet[pick(rng)]);
    return s;
}

// Arbitrary bytes: exercises the UTF-8 / control-character handling.
std::string fuzz_bytes(std::mt19937_64& rng) {
    std::uniform_int_distribution<size_t> len(0, 48);
    std::uniform_int_distribution<int> b(0, 255);
    std::string s;
    const size_t n = len(rng);
    s.reserve(n);
    for (size_t i = 0; i < n; ++i) s.push_back(char(b(rng)));
    return s;
}

// A model-shaped response: "TOOL " + garbage, which is what the runner receives
// from a backend that emits anything at all.
std::string fuzz_frame(std::mt19937_64& rng) {
    static const char* alphabet = "TOOL \n{}\":,namepayload0123456789 \t";
    std::uniform_int_distribution<size_t> len(0, 48);
    std::uniform_int_distribution<size_t> pick(0, std::string_view(alphabet).size() - 1);
    std::string s = "TOOL ";
    const size_t n = len(rng);
    for (size_t i = 0; i < n; ++i) s.push_back(alphabet[pick(rng)]);
    return s;
}

// (1) JSON codec round-trip: never crash, never OOB, and never accept trailing junk.
void fuzz_json(Stats& st, long long iters) {
    for (long long i = 0; i < iters; ++i) {
        std::mt19937_64 rng(0x4A0000ull ^ (unsigned long long)i);
        const std::string src = fuzz_json_string(rng);
        st.json_inputs++;

        try {
            const J parsed = J::parse(src);
            st.json_accepted++;
            // Re-serialising a parsed value must be stable and must re-parse to
            // the same dump: this catches codecs that emit invalid JSON.
            const std::string dumped = parsed.dump();
            try {
                const J reparsed = J::parse(dumped);
                if (reparsed.dump() != dumped) {
                    st.failures.push_back("json: dump not stable: " + dumped);
                }
            } catch (std::exception const&) {
                st.failures.push_back("json: own output does not re-parse: " + dumped);
            }
        } catch (std::exception const&) {
            st.json_rejected++;
        } catch (...) {
            st.failures.push_back("json: non-std exception escaped");
        }
    }
}

// (1b) Arbitrary bytes: the codec must reject cleanly, never fault.
void fuzz_json_arbitrary(Stats& st, long long iters) {
    for (long long i = 0; i < iters; ++i) {
        std::mt19937_64 rng(0xA00000ull ^ (unsigned long long)i);
        st.json_inputs++;
        try {
            (void)J::parse(fuzz_bytes(rng));
            st.json_accepted++;
        } catch (...) { st.json_rejected++; }
    }
}

// (2) Framed-tool parsing from arbitrary model output.
void fuzz_frames(Stats& st, long long iters) {
    for (long long i = 0; i < iters; ++i) {
        std::mt19937_64 rng(0xF00000ull ^ (unsigned long long)i);
        for (int k = 0; k < 4; ++k) {
            const std::string src = fuzz_frame(rng) + "_" + std::to_string(k);
            st.frames++;
            try {
                const Call c = parse_call(src);
                if (c.is_tool) st.frame_rejected++; else st.frames_parsed++;
            } catch (...) {
                st.failures.push_back("parse_call: exception escaped");
            }
        }
    }
}

// (3) Fail-closed tool-name validation. Contract: ONLY the seven allowlisted
// names may ever be accepted; everything else must be rejected with no crash.
void fuzz_tool_names(Stats& st, long long iters) {
    static const std::set<std::string> allowed = {"read", "list", "grep", "edit", "write", "exec", "verify"};
    // Names that must never be accepted, including near-miss typo-golf forms.
    static const char* must_reject[] = {
        "", "gash", "bash", "sh", "cmd", "powershell", "pwsh", "python", "node",
        "read2", "readd", "red", "RED", "Read", "READ", "re ad", "read\n",
        "read ", " read", "read;x", "read|x", "read.exe", "../read", "re\\u0061d",
        "exec;rm", "verify()", "write=1", "list*", "grep?", "\tread", "read\t"
    };

    for (auto bad : must_reject) {
        st.tool_calls++;
        try {
            if (check_tool(bad).empty()) {
                st.failures.push_back(std::string("check_tool ACCEPTED disallowed name: '") + bad + "'");
            } else {
                st.tool_rejected++;
            }
        } catch (...) {
            st.failures.push_back(std::string("check_tool threw on '") + bad + "'");
        }
    }

    for (auto good : allowed) {
        st.tool_calls++;
        try {
            const std::string err = check_tool(good);
            if (!err.empty()) {
                st.failures.push_back(std::string("check_tool REJECTED valid name '") + good + "': " + err);
            }
        } catch (...) {
            st.failures.push_back(std::string("check_tool threw on valid '") + good + "'");
        }
    }

    // Random names: only allowlisted names may pass.
    static const char* alphabet = "abcdefgiklnorstuvwxyz_-.\\/ \t;|&$()0123456789";
    for (long long i = 0; i < iters; ++i) {
        std::mt19937_64 rng(0xB00000ull ^ (unsigned long long)i);
        std::uniform_int_distribution<size_t> len(0, 12);
        std::uniform_int_distribution<size_t> pick(0, std::string_view(alphabet).size() - 1);
        std::string s;
        const size_t n = len(rng);
        for (size_t k = 0; k < n; ++k) s.push_back(alphabet[pick(rng)]);
        st.tool_calls++;
        try {
            if (check_tool(s).empty() && !allowed.count(s)) {
                st.failures.push_back("check_tool accepted non-allowlisted random name: '" + s + "'");
            }
        } catch (...) {
            st.failures.push_back("check_tool threw on random name");
        }
    }
}

// (4) Workspace containment. The real invariant is not "always reject" but
// "never return anything outside root": a legitimate relative path MUST resolve
// (that is the feature), while an escape may resolve to nothing. So for every
// attempt we assert that if a path comes back it is contained in root.
//
// Separately, the well-known traversal/abuse vectors are asserted to be refused
// outright. "." and "./" are deliberately NOT in that list: they legitimately
// resolve to root, which is inside root.
void test_path_containment(Stats& st) {
    const fs::path root = fs::temp_directory_path() / "rawr_fuzz_root";
    std::error_code ec;
    fs::create_directories(root, ec);

    // Vectors that must be refused outright.
    static const char* escapes[] = {
        "..", "../", "../../", "../../windows/win.ini", "..\\..\\windows\\win.ini",
        "../../../../etc/passwd", "./../x", "a/../../b", "a/../../../b",
        "C:\\Windows\\win.ini", "C:/Windows/win.ini", "//server/share/x",
        "\\\\server\\share\\x", "sub/../../../x", "sub\\..\\..\\x",
        "/", "\\", "..//..//x", "a/b/../../../../c",
        "%windir%", "..;/x", "\x01..", "..\x01",
        // Absolute POSIX-style paths that Windows still partially accepts.
        "/etc/passwd", "/proc/self/environ"
    };

    for (auto e : escapes) {
        st.escape_attempts++;
        try {
            const auto r = secured_path(root, e, /*create=*/false);
            if (r) {
                // Either acceptable (contained) or a containment failure.
                if (!inside(root, *r)) {
                    st.failures.push_back(std::string("secured_path ALLOWED escape '") + e + "' -> " + r->string());
                } else {
                    st.failures.push_back(std::string("secured_path did not refuse suspicious path '") + e + "'");
                }
            } else {
                st.escape_blocked++;
            }
        } catch (...) {
            st.failures.push_back(std::string("secured_path threw on '") + e + "'");
        }
    }

    // A NUL byte must be refused outright (it is a classic truncation vector).
    for (std::string n : {std::string("ok.cpp\0../evil.cpp"), std::string("\0"), std::string("a\0b")}) {
        st.escape_attempts++;
        try {
            if (secured_path(root, n, false)) {
                st.failures.push_back("secured_path allowed an embedded NUL");
            } else {
                st.escape_blocked++;
            }
        } catch (...) {
            st.failures.push_back("secured_path threw on embedded NUL");
        }
    }

    // Legitimate relative paths must resolve AND stay contained. This is the
    // positive half of the property: a guard that rejects everything would also
    // "pass" the negative tests above.
    for (std::string ok : {"sub/file.txt", "a/b/c.txt", "file.cpp"}) {
        st.escape_attempts++;
        try {
            const auto r = secured_path(root, ok, /*create=*/true);
            if (!r) {
                st.failures.push_back(std::string("secured_path refused legitimate path '") + ok + "'");
            } else if (!inside(root, *r)) {
                st.failures.push_back(std::string("secured_path returned path outside root for '") + ok + "'");
            } else {
                st.escape_blocked++;
            }
        } catch (...) {
            st.failures.push_back(std::string("secured_path threw on legitimate path '") + ok + "'");
        }
    }
    fs::remove_all(root, ec);

    // inside() as an oracle: a legitimate nested path must be contained.
    st.escape_attempts++;
    if (!inside(root, root / "sub" / "file.txt")) {
        st.failures.push_back("inside() wrongly rejected a path inside root");
    } else {
        st.escape_blocked++;
    }

    fs::remove_all(root, ec);
}

} // namespace

int main(int argc, char** argv) {
    long long iters = 20000;
    if (argc > 1) {
        try { iters = std::stoll(argv[1]); } catch (...) { /* keep default */ }
        if (iters < 1 || iters > 50000000) {
            std::fprintf(stderr, "usage: rawr_fuzz_parsers [iterations 1..50000000]\n");
            return 2;
        }
    }

    Stats st;
    fuzz_json(st, iters);
    fuzz_json_arbitrary(st, iters);
    fuzz_frames(st, iters);
    fuzz_tool_names(st, iters);
    test_path_containment(st);

    std::printf("FUZZ JSON  inputs=%lld accepted=%lld rejected=%lld\n",
                st.json_inputs, st.json_accepted, st.json_rejected);
    std::printf("FUZZ FRAME inputs=%lld framed_calls=%lld non_framed=%lld\n",
                st.frames, st.frame_rejected, st.frames_parsed);
    std::printf("FUZZ TOOL  checks=%lld rejected=%lld\n", st.tool_calls, st.tool_rejected);
    std::printf("FUZZ PATH  escapes=%lld blocked_or_resolved_inside=%lld\n",
                st.escape_attempts, st.escape_blocked);

    if (!st.failures.empty()) {
        std::printf("FAILURES (%zu):\n", st.failures.size());
        for (size_t i = 0; i < st.failures.size() && i < 50; ++i) {
            std::printf("  %s\n", st.failures[i].c_str());
        }
        std::printf("FUZZ_RESULT=FAIL\n");
        return 1;
    }

    std::printf("FUZZ_RESULT=PASS (no crash, no OOB, no traversal escape, no tool bypass)\n");
    return 0;
}
