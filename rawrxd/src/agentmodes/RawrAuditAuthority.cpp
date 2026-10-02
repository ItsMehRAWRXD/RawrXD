// RawrAuditAuthority.cpp — RAWRXD_RAWRAUDIT_AUTHORITY_001
#include "agentmodes/RawrAuditAuthority.h"
#include "deep2/ReceiptAuthority.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace rawrxd { namespace audit {

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Small text helpers
// ---------------------------------------------------------------------------

static std::string trim(const std::string& s) {
    size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

static bool contains(const std::string& hay, const std::string& needle) {
    return needle.empty() || hay.find(needle) != std::string::npos;
}

static std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

// Remove // comments, /* */ comments, string literals and char literals.
// Output streams survive, so `std::cout << x;` still reads as output.
static std::string stripCommentsAndStrings(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    const size_t n = in.size();
    for (size_t i = 0; i < n;) {
        if (in[i] == '/' && i + 1 < n && in[i + 1] == '/') {
            while (i < n && in[i] != '\n') { out.push_back(' '); ++i; }
        } else if (in[i] == '/' && i + 1 < n && in[i + 1] == '*') {
            out.push_back(' '); out.push_back(' ');
            i += 2;
            while (i + 1 < n && !(in[i] == '*' && in[i + 1] == '/')) {
                out.push_back(in[i] == '\n' ? '\n' : ' ');
                ++i;
            }
            if (i + 1 < n) { out.push_back(' '); out.push_back(' '); i += 2; }
        } else if (in[i] == '"' || in[i] == '\'') {
            const char q = in[i];
            out.push_back(' ');
            ++i;
            while (i < n && in[i] != q) {
                if (in[i] == '\\' && i + 1 < n) { out.push_back(' '); ++i; ++i; }
                else { out.push_back(in[i] == '\n' ? '\n' : ' '); ++i; }
            }
            if (i < n) { out.push_back(' '); ++i; }
        } else {
            out.push_back(in[i]);
            ++i;
        }
    }
    return out;
}

// True when `kw` appears as a whole token, not inside a longer identifier.
static bool hasKeyword(const std::string& code, const std::string& kw) {
    size_t pos = 0;
    while ((pos = code.find(kw, pos)) != std::string::npos) {
        const bool leftOk  = (pos == 0) || !(std::isalnum(static_cast<unsigned char>(code[pos - 1])) || code[pos - 1] == '_');
        size_t after = pos + kw.size();
        const bool rightOk = (after >= code.size()) || !(std::isalnum(static_cast<unsigned char>(code[after])) || code[after] == '_');
        if (leftOk && rightOk) return true;
        pos = after;
    }
    return false;
}

// A single '=' that is not part of ==, !=, <=, >=, +=, -=, *=, /=, |=, &=, ^=.
static bool hasBareAssignment(const std::string& code) {
    for (size_t i = 0; i < code.size(); ++i) {
        if (code[i] != '=') continue;
        if (i + 1 < code.size() && code[i + 1] == '=') { ++i; continue; }   // ==
        if (i > 0) {
            const char p = code[i - 1];
            if (p == '=' || p == '!' || p == '<' || p == '>' || p == '+' ||
                p == '-' || p == '*' || p == '/' || p == '|' || p == '&' || p == '^') continue;
        }
        return true;
    }
    return false;
}

static bool hasOutputStatement(const std::string& code) {
    return contains(code, "std::cout") || contains(code, "std::cerr") ||
           contains(code, "std::clog") || contains(code, "printf(") ||
           contains(code, "fprintf(")   || contains(code, "puts(") ||
           contains(code, "putchar(");
}

// Any evidence that the body actually computes or observes something.
static bool hasComputation(const std::string& code) {
    if (hasBareAssignment(code)) return true;
    for (const char* kw : { "if", "for", "while", "switch", "return", "sizeof", "new", "delete" }) {
        if (hasKeyword(code, kw)) return true;
    }
    if (contains(code, ".push_back") || contains(code, ".emplace_back") ||
        contains(code, ".at(")     || contains(code, "[0]")) return true;
    if (contains(code, "fs::") || contains(code, "std::filesystem")) return true;
    if (contains(code, "ifstream") || contains(code, "ofstream") ||
        contains(code, "fopen")    || contains(code, "fread") ||
        contains(code, "stat(")    || contains(code, "directory_iterator") ||
        contains(code, "GetFileAttributes") || contains(code, "FindFirstFile")) return true;
    return false;
}

bool isPrintOnlyBody(const std::string& body) {
    const std::string code = stripCommentsAndStrings(body);
    if (!hasOutputStatement(code)) return false;
    return !hasComputation(code);
}

// ---------------------------------------------------------------------------
// Line-level rules
// ---------------------------------------------------------------------------

static void addFinding(ScanResult& out, const std::string& file, int line,
                       const char* rule, Severity sev, const std::string& evidence) {
    Finding f;
    f.file = file; f.line = line; f.rule = rule; f.severity = sev;
    std::string ev = trim(evidence);
    if (ev.size() > 120) ev = ev.substr(0, 117) + "...";
    f.evidence = ev;
    out.findings.push_back(f);
    if (sev == Severity::Blocking) ++out.blockingCount; else ++out.advisoryCount;
}

void scanBuffer(const std::string& fileLabel, const std::string& text, ScanResult& out) {
    std::istringstream is(text);
    std::string line;
    int lineNo = 0;
    while (std::getline(is, line)) {
        ++lineNo;
        const std::string t    = trim(line);
        const std::string low  = lower(t);
        // Built from the trimmed line so that indices into `code` line up with
        // indices into `t` and `low`.
        const std::string code = stripCommentsAndStrings(t);

        // A verdict assigned a bare "PASS" literal can never be wrong, so it is
        // proof of a stub. Two deliberate exclusions:
        //   - `verdict = cond ? "PASS" : "FAIL"` is legitimate; a ternary RHS is
        //     not a bare literal, so it does not match.
        //   - `std::string verdict = "FAIL";` is a pessimistic default, which
        //     is good practice, so only the PASS literal is blocking.
        // The '=' is located in the stripped line so that an '=' appearing
        // inside a string such as "VERDICT=" cannot trigger the rule.
        {
            size_t v = low.find("verdict");
            while (v != std::string::npos) {
                const bool leftOk = (v == 0) ||
                    !(std::isalnum(static_cast<unsigned char>(low[v - 1])) || low[v - 1] == '_');
                if (leftOk) {
                    size_t eq = v;
                    while (eq < low.size() && code[eq] != '=') ++eq;
                    if (eq < low.size() && code[eq] == '=') {
                        const std::string rhs = trim(t.substr(eq + 1));
                        const size_t semi = rhs.find(';');
                        const std::string val = trim(semi == std::string::npos ? rhs : rhs.substr(0, semi));
                        if (val == "\"PASS\"") {
                            addFinding(out, fileLabel, lineNo, "HARDCODED_VERDICT",
                                       Severity::Blocking, t);
                            ++out.hardcodedPass;
                        }
                    }
                }
                v = low.find("verdict", v + 7);
            }
        }

        // Observation-sounding counters assigned a bare integer literal.
        //
        // RAWRXD_MEASUREMENT_HARNESS_AUTHORITY_001
        //
        // This used to be a FIXED LIST of eleven names, which is the same
        // defect as a fixed list of stubs: it undercounts silently. The list
        // caught `generatedTokenCount` and `rootsScanned` and therefore gave
        // confidence, while `filesScanned`, `waitImportHits`,
        // `networkImportHits`, `responseSymbolHits`, `pathResolvesRawr` and
        // `freshShellRawRunCompleted` -- every one of which WAS assigned a
        // literal in this tree -- passed as clean. A census whose coverage is a
        // list someone chose is worse than one that fails loudly, because it
        // reports a count that looks like a measurement of the whole.
        //
        // The list is retained as an explicit allow-nothing prefix set, and a
        // GENERIC SUFFIX rule now covers the class: any identifier whose name
        // ends in a measurement suffix and which is assigned a bare non-zero
        // integer literal is a simulated observation. New counters are covered
        // by construction rather than by remembering to add them.
        {
            static const char* kSuffixes[] = {
                "count", "counts", "hits", "scanned", "discovered", "classified",
                "exists", "resolves", "completed", "started", "verified", "valid",
                "parsed", "loaded", "issued", "found", "matched", "skipped"
            };
            static const char* kCounters[] = {
                "modelsDiscovered", "modelsClassified", "modelsWithPath",
                "modelsWithUnknownPath", "deep2CompatibleCount", "unloadableCount",
                "generatedTokenCount", "rootsScanned", "aliasesScanned",
                "ggufFilesScanned", "ollamaManifestsScanned", "tensorCount",
                "expertsUsed", "layerCount", "unloadableCount"
            };
            auto looksLikeObservation = [](const std::string& name) {
                for (const char* s : kSuffixes) {
                    if (name.size() > std::strlen(s) &&
                        name.compare(name.size() - std::strlen(s), std::strlen(s), s) == 0) {
                        return true;
                    }
                }
                return false;
            };
            for (const char* c : kCounters) {
                const size_t p = low.find(lower(c));
                if (p == std::string::npos) continue;
                const bool leftOk = (p == 0) || !(std::isalnum(static_cast<unsigned char>(low[p - 1])) || low[p - 1] == '_');
                size_t eq = p;
                while (eq < low.size() && low[eq] != '=') ++eq;
                if (!leftOk || eq >= low.size() || low[eq] != '=') continue;
                size_t after = eq + 1;
                if (after < low.size() && low[after] == '=') continue;      // ==
                const std::string rhs = trim(t.substr(after));
                const size_t semi = rhs.find(';');
                const std::string val = trim(semi == std::string::npos ? rhs : rhs.substr(0, semi));
                if (val.empty()) continue;
                if (val.find_first_not_of("0123456789") == std::string::npos) {
                    // Initialising a counter to 0 is correct, not simulated.
                    // Only a non-zero literal substitutes for a real measurement.
                    if (val == "0") continue;
                    addFinding(out, fileLabel, lineNo, "SIMULATED_COUNTER",
                               Severity::Blocking, t);
                    ++out.simulatedCounters;
                }
            }

            // Generic sweep: `<identifier> = <bare non-zero integer>;` where the
            // identifier names an observation. Scoped to member-style access
            // (`x.y = 3;` or a `g_state.y = 3;`) so ordinary local arithmetic
            // and loop counters are not swept in.
            {
                size_t i = 0;
                while (i < t.size()) {
                    // identifier
                    size_t s0 = i;
                    while (i < t.size() && (std::isalnum(static_cast<unsigned char>(t[i])) || t[i] == '_')) ++i;
                    const std::string ident = t.substr(s0, i - s0);
                    if (ident.empty() || ident == "return") { continue; }
                    // optional member access
                    size_t j = i;
                    while (j < t.size() && (t[j] == ' ' || t[j] == '.' || t[j] == '_' ||
                                             std::isalnum(static_cast<unsigned char>(t[j])))) {
                        if (t[j] == ' ' && !(j + 1 < t.size() &&
                                (std::isalnum(static_cast<unsigned char>(t[j + 1])) ||
                                 t[j + 1] == '_'))) { break; }
                        ++j;
                    }
                    const std::string rhs2 = trim(t.substr(j));
                    if (rhs2.size() < 3 || rhs2[0] != '=' || rhs2[1] == '=') { continue; }
                    const std::string val2 = trim(rhs2.substr(1));
                    const std::string bare = val2.substr(0, val2.find(';') == std::string::npos
                                                 ? val2.size() : val2.find(';'));
                    if (bare == "true" || bare == "false") {
                        // `x.flag = true;` is only a simulated observation when
                        // the name says it is one.
                        if (looksLikeObservation(ident)) {
                            addFinding(out, fileLabel, lineNo, "SIMULATED_OBSERVATION",
                                       Severity::Advisory, t);
                            ++out.simulatedCounters;
                        }
                        continue;
                    }
                    if (bare.empty() ||
                        bare.find_first_not_of("0123456789") != std::string::npos) { continue; }
                    if (bare == "0") continue;   // initialising to zero is correct
                    if (looksLikeObservation(ident)) {
                        addFinding(out, fileLabel, lineNo, "SIMULATED_OBSERVATION",
                                   Severity::Blocking, t);
                        ++out.simulatedCounters;
                    }
                }
            }
        }

        // RAWRXD_MEASUREMENT_HARNESS_AUTHORITY_001
        //
        // A function that returns success while saying it did not check is the
        // same defect as a fabricated counter, and it is invisible to any rule
        // that inspects assignments. This catches
        //     return true; // placeholder
        //     return true;  // For now, assume yes
        //     return true;  // Would need actual PATH verification
        // and the `return false; // TODO: implement` shapes, by pairing the
        // return with a concession marker anywhere in the same trimmed line or
        // the one immediately above it.
        {
            const char* markers[] = {
                "placeholder", "for now", "assume", "simplified", "omitted",
                "not implemented", "stub", "mock", "would need", "todo",
                "would extract", "would call", "would actually"
            };
            const size_t rr = low.rfind("return");
            if (rr != std::string::npos) {
                const std::string retLine = trim(low.substr(rr));
                if (retLine.rfind("return true", 0) == 0 ||
                    retLine.rfind("return false", 0) == 0 ||
                    retLine.rfind("return 0", 0) == 0) {
                    for (const char* m : markers) {
                        if (retLine.find(m) != std::string::npos) {
                            addFinding(out, fileLabel, lineNo, "ASSUMED_SUCCESS",
                                       Severity::Blocking, t);
                            break;
                        }
                    }
                }
            }
        }

        // Hardcoded data lists: push_back("literal") cannot discover anything.
        if (contains(t, ".push_back(\"")) {
            addFinding(out, fileLabel, lineNo, "LITERAL_DATA_PUSH",
                       Severity::Advisory, t);
            ++out.simulatedCounters;
        }

        // Self-declared simulation.
        if (contains(low, "// simulate") || contains(low, "/* simulate") ||
            contains(low, "would read actual")) {
            addFinding(out, fileLabel, lineNo, "SIMULATION_COMMENT",
                       Severity::Blocking, t);
        }
        if (contains(low, "// example") || contains(low, "simplified example")) {
            addFinding(out, fileLabel, lineNo, "EXAMPLE_COMMENT",
                       Severity::Advisory, t);
        }
        // Unambiguous placeholder payloads only. A bare "..." is deliberately
        // NOT a rule: it appears in legitimate truncation and in doc comments.
        if (contains(t, "\"abc123") || contains(t, "\"xxx") || contains(t, "\"TODO") ||
            (contains(low, "placeholder") && !contains(code, "placeholder"))) {
            addFinding(out, fileLabel, lineNo, "PLACEHOLDER_VALUE",
                       Severity::Blocking, t);
        }
        if (contains(low, "#exclude") || contains(t, "EXCLUDE_FROM") ||
            contains(low, "filter_missing_sources")) {
            addFinding(out, fileLabel, lineNo, "EXCLUSION_MARKER",
                       Severity::Advisory, t);
            ++out.exclusions;
        }
    }
}

// ---------------------------------------------------------------------------
// Function-body rules
// ---------------------------------------------------------------------------

// Find brace-matched function bodies and flag print-only ones.
static void scanFunctionBodies(const std::string& fileLabel, const std::string& text,
                               ScanResult& out) {
    const size_t n = text.size();
    for (size_t i = 0; i < n; ++i) {
        if (text[i] != '(') continue;
        // Walk back over the parameter list to its opening paren.
        size_t close = i;
        int depth = 0;
        while (close < n) {
            if (text[close] == '(') ++depth;
            else if (text[close] == ')') { --depth; if (depth == 0) break; }
            ++close;
        }
        if (close >= n) break;
        size_t brace = close + 1;
        while (brace < n && std::isspace(static_cast<unsigned char>(text[brace]))) ++brace;
        if (brace >= n || text[brace] != '{') continue;

        // A function definition has an identifier immediately before '('.
        if (i == 0) continue;
        const char before = text[i - 1];
        if (!(std::isalnum(static_cast<unsigned char>(before)) || before == '_' || before == '~')) continue;

        // Brace-match the body, honouring strings and comments.
        size_t j = brace, bdepth = 0;
        bool closed = false;
        while (j < n) {
            const char c = text[j];
            if (c == '"' || c == '\'') {
                const char q = c; ++j;
                while (j < n && text[j] != q) { if (text[j] == '\\') ++j; ++j; }
            } else if (c == '/' && j + 1 < n && text[j + 1] == '/') {
                while (j < n && text[j] != '\n') ++j;
            } else if (c == '/' && j + 1 < n && text[j + 1] == '*') {
                j += 2;
                while (j + 1 < n && !(text[j] == '*' && text[j + 1] == '/')) ++j;
                j += 1;
            } else if (c == '{') { ++bdepth; }
            else if (c == '}') { --bdepth; if (bdepth == 0) { closed = true; ++j; break; } }
            ++j;
        }
        if (!closed) break;

        const std::string body = text.substr(brace, j - brace);
        if (isPrintOnlyBody(body)) {
            const int ln = 1 + static_cast<int>(std::count(text.begin(), text.begin() + static_cast<long>(i), '\n'));
            addFinding(out, fileLabel, ln, "PRINT_ONLY_FUNCTION",
                       Severity::Blocking, std::string(trim(text.substr(i, close - i + 1))) + " { ... }");
        }
        i = j - 1;
    }
}

// ---------------------------------------------------------------------------
// Tree walk
// ---------------------------------------------------------------------------

static bool readFile(const fs::path& p, std::string& out) {
    std::ifstream in(p, std::ios::binary);
    if (!in) return false;
    std::ostringstream ss;
    ss << in.rdbuf();
    out = ss.str();
    return true;
}

bool auditFile(const std::string& path, ScanResult& out) {
    std::string text;
    if (!readFile(fs::path(path), text)) return false;
    const std::string rel = fs::path(path).filename().string();
    ++out.filesScanned;
    out.rootExisted = true;
    scanBuffer(rel, text, out);
    scanFunctionBodies(rel, text, out);
    return true;
}

ScanResult scanSourceTree(const ScanOptions& opts) {
    ScanResult res;
    std::error_code ec;
    if (!fs::exists(opts.root, ec)) return res;
    res.rootExisted = true;
    if (!fs::is_directory(opts.root, ec)) return res;

    // Read every candidate once; dead-code detection needs the whole set.
    struct Entry {
        fs::path     path;
        std::string  rel;
        std::string  ext;
        std::string  text;
        bool         isBuild = false;
    };
    std::vector<Entry> entries;
    for (const auto& it : fs::recursive_directory_iterator(opts.root, ec)) {
        if (ec) break;
        std::error_code fec;
        if (!it.is_regular_file(fec)) continue;
        const std::string ext   = lower(it.path().extension().string());
        const std::string fname = lower(it.path().filename().string());
        const bool isBuild  = (fname.find("cmakelists") != std::string::npos);
        const bool isSource = std::find(opts.extensions.begin(), opts.extensions.end(), ext)
                              != opts.extensions.end();
        if (!isSource && !isBuild) continue;
        if (opts.maxFiles > 0 && static_cast<int>(entries.size()) >= opts.maxFiles) break;

        Entry e;
        e.path = it.path();
        e.rel  = fs::relative(e.path, fs::path(opts.root), fec).generic_string();
        e.ext  = ext;
        e.isBuild = isBuild;
        if (!readFile(e.path, e.text)) continue;
        entries.push_back(std::move(e));
    }

    // A .cpp counts as referenced when its filename appears in the build files
    // or in any other source file. This is a heuristic and is reported as
    // ADVISORY so it can never fail a build on its own.
    std::string buildText;
    for (const auto& e : entries) if (e.isBuild) buildText += e.text;

    for (const auto& e : entries) {
        bool exempt = false;
        for (const auto& x : opts.exemptions) {
            if (!x.empty() && e.rel.find(x) != std::string::npos) { exempt = true; break; }
        }
        if (exempt) { ++res.filesExempted; continue; }

        ++res.filesScanned;
        if (e.isBuild) continue;

        scanBuffer(e.rel, e.text, res);
        scanFunctionBodies(e.rel, e.text, res);

        if (e.ext == ".cpp") {
            const std::string fname = e.path.filename().string();
            bool referenced = contains(buildText, fname);
            if (!referenced) {
                for (const auto& o : entries) {
                    if (&o == &e) continue;
                    if (contains(o.text, fname)) { referenced = true; break; }
                }
            }
            if (!referenced) {
                addFinding(res, e.rel, 1, "DEAD_CODE_UNREFERENCED", Severity::Advisory,
                           e.path.stem().string() + ".cpp is not referenced by CMake or any source file");
            }
        }
    }

    if (opts.blockingOnly) {
        res.findings.erase(std::remove_if(res.findings.begin(), res.findings.end(),
                                          [](const Finding& f) { return f.severity != Severity::Blocking; }),
                          res.findings.end());
    }
    return res;
}

// ---------------------------------------------------------------------------
// Receipt
// ---------------------------------------------------------------------------

void writeAuditReceipt(const std::string& path, const ScanResult& result,
                       const std::string& scanRoot) {
    int printOnly = 0, simComments = 0, deadCode = 0;
    for (const auto& f : result.findings) {
        if (f.rule == "PRINT_ONLY_FUNCTION")       ++printOnly;
        if (f.rule == "SIMULATION_COMMENT")        ++simComments;
        if (f.rule == "DEAD_CODE_UNREFERENCED")    ++deadCode;
    }

    receipt::beginGate(path, "RAWRXD_RAWRAUDIT_AUTHORITY_001");
    receipt::writeKeyValue(path, "SCAN_ROOT", scanRoot);
    receipt::writeKeyValueInt(path, "ROOT_EXISTED", result.rootExisted ? 1 : 0);
    receipt::writeKeyValueInt(path, "FILES_SCANNED", result.filesScanned);
    receipt::writeKeyValueInt(path, "FILES_EXEMPTED", result.filesExempted);
    receipt::writeKeyValueInt(path, "STUBS_FOUND", printOnly + simComments);
    receipt::writeKeyValueInt(path, "HARDCODED_PASS_FOUND", result.hardcodedPass);
    receipt::writeKeyValueInt(path, "SIMULATED_COUNTERS_FOUND", result.simulatedCounters);
    receipt::writeKeyValueInt(path, "EXCLUSIONS_FOUND", result.exclusions);
    receipt::writeKeyValueInt(path, "DEAD_CODE_FOUND", deadCode);
    receipt::writeKeyValueInt(path, "BLOCKING_FINDINGS", result.blockingCount);
    receipt::writeKeyValueInt(path, "ADVISORY_FINDINGS", result.advisoryCount);

    // Full evidence, capped so a pathological tree cannot produce a receipt
    // larger than the value it certifies.
    int emitted = 0;
    for (const auto& f : result.findings) {
        if (emitted >= 200) break;
        ++emitted;
        const std::string key = "FINDING_" + std::to_string(emitted);
        receipt::writeKeyValue(path, key + "_RULE", f.rule);
        receipt::writeKeyValue(path, key + "_LOCATION", f.file + ":" + std::to_string(f.line));
        receipt::writeKeyValue(path, key + "_SEVERITY", f.severity == Severity::Blocking ? "BLOCKING" : "ADVISORY");
        receipt::writeKeyValue(path, key + "_EVIDENCE", f.evidence);
    }
    receipt::writeKeyValueInt(path, "FINDINGS_EMITTED", emitted);
    receipt::writeKeyValueInt(path, "FINDINGS_TRUNCATED", emitted < static_cast<int>(result.findings.size()) ? 1 : 0);

    // Verdict is computed from the scan, never asserted. A scan that exempted
    // files gets a distinct verdict so a narrowed scan can never be mistaken
    // for a clean one.
    const char* v = !result.rootExisted ? "FAIL"
                   : (result.blockingCount > 0) ? "FAIL"
                   : (result.filesExempted > 0) ? "PASS_WITH_EXEMPTIONS"
                   : "PASS";
    receipt::endGate(path, v);
}

int runAudit(const std::string& scanRoot, const std::string& receiptPath) {
    ScanOptions opts;
    opts.root = scanRoot;
    const ScanResult res = scanSourceTree(opts);
    writeAuditReceipt(receiptPath, res, scanRoot);
    std::printf("[RawrAudit] root=%s files=%d blocking=%d advisory=%d\n",
                scanRoot.c_str(), res.filesScanned, res.blockingCount, res.advisoryCount);
    return res.blockingCount == 0 ? 0 : 2;
}

}} // namespace rawrxd::audit
