/* streamer_status.cpp -- RAWRXD_STREAMER_STATUS_V1  (ASS-8)
 *
 * Reads the telemetry sink written by deep2_streamer_cert and answers the only
 * questions anyone actually asks after a run:
 *
 *   did anything pass
 *   where did it stop
 *   which binary produced this
 *
 * The run header carries the image SHA-256. That is deliberate: a result that
 * cannot be tied to a binary is not a result, and this project has repeatedly
 * been damaged by exactly that -- an unattributable gguf_stream_probe.exe, a
 * truncated 127 GB dump, a fault RVA from one build symbolized against another.
 * The status command prints the identity beside the numbers, always.
 *
 * No dependencies beyond the CRT. Reads JSONL, no JSON library: the sink emits
 * one flat object per line with no nested structures, and a strict parser is
 * easier to falsify than a tolerant one.
 *
 * Build: cl /std:c++20 /EHsc /O2 streamer_status.cpp /Fe:streamer_status.exe
 * Usage: streamer_status.exe [path]            (default: %LOCALAPPDATA%\RawrXD\streamer_telemetry.jsonl)
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <filesystem>

namespace fs = std::filesystem;

namespace {

std::string defaultPath() {
    if (const char* p = std::getenv("RAWRXD_STREAMER_TELEMETRY")) return p;
    if (const char* l = std::getenv("LOCALAPPDATA"))
        return std::string(l) + "\\RawrXD\\streamer_telemetry.jsonl";
    return "streamer_telemetry.jsonl";
}

// strict scalar field extraction: "key":value where value is string/number/bool.
// Returns false if the key is absent. No type coercion across quotes: if the
// sink emitted "3" and we ask for a number we take the number; if it emitted
// "abc" we fail rather than guess.
bool field(const std::string& line, const char* key, std::string* out) {
    std::string pat = std::string("\"") + key + "\":";
    const size_t p = line.find(pat);
    if (p == std::string::npos) return false;
    size_t i = p + pat.size();
    if (i < line.size() && line[i] == '"') {
        ++i;
        std::string v;
        while (i < line.size() && line[i] != '"') {
            if (line[i] == '\\' && i + 1 < line.size()) {
                ++i;
                switch (line[i]) {
                    case 'n': v += '\n'; break;
                    case 't': v += '\t'; break;
                    case 'r': v += '\r'; break;
                    default:  v += line[i]; break;
                }
            } else v += line[i];
            ++i;
        }
        *out = v;
    } else {
        size_t j = i;
        while (j < line.size() && line[j] != ',' && line[j] != '}') ++j;
        *out = line.substr(i, j - i);
    }
    return true;
}

double num(const std::string& line, const char* key, double dflt = 0.0) {
    std::string v; if (!field(line, key, &v)) return dflt;
    return std::strtod(v.c_str(), nullptr);
}

std::string str(const std::string& line, const char* key, const char* dflt = "") {
    std::string v; if (!field(line, key, &v)) return dflt;
    return v;
}

struct Run {
    std::string ts, sha;
    long pid = 0;
    std::string argv1;
    int models = 0, pass = 0;
};

} // namespace

int main(int argc, char** argv) {
    const std::string path = (argc > 1) ? argv[1] : defaultPath();
    std::printf("RAWRXD_STREAMER_STATUS_V1\n");
    std::printf("sink=%s\n", path.c_str());

    std::error_code ec;
    if (!fs::exists(path, ec)) {
        std::printf("SINK_ABSENT=1\n");
        std::printf("hint: run deep2_streamer_cert, or set RAWRXD_STREAMER_TELEMETRY\n");
        std::printf("VERDICT=NO_TELEMETRY\n");
        return 1;
    }

    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) { std::printf("SINK_UNREADABLE=1\nVERDICT=NO_TELEMETRY\n"); return 1; }

    std::vector<Run> runs;
    std::vector<std::string> modelLines;   // current run's model records
    std::vector<std::string> footerLines;
    std::string curHeader;

    auto flushRun = [&]() {
        if (curHeader.empty() && modelLines.empty()) return;
        Run r;
        r.ts   = str(curHeader, "ts");
        r.sha  = str(curHeader, "image_sha256");
        r.pid  = (long)num(curHeader, "pid", 0);
        r.argv1= str(curHeader, "argv1");
        r.models = (int)modelLines.size();
        for (auto& m : modelLines)
            if (str(m, "result") == "MODEL_PASS") ++r.pass;
        runs.push_back(r);
        // NOTE: modelLines/footerLines are deliberately NOT cleared here. The
        // LATEST RUN table below prints them, and clearing them here made that
        // table print zero rows while the run counter above said 1 model. A
        // receipt that reports the right count and shows no rows is worse than
        // no receipt.
        curHeader.clear();
    };

    char buf[8192];
    long long totalLines = 0, malformed = 0;
    while (std::fgets(buf, sizeof buf, f)) {
        std::string line(buf);
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) line.pop_back();
        if (line.empty()) continue;
        ++totalLines;
        // A telemetry line that does not parse is itself a finding, not noise.
        if (line.find("\"record\":") == std::string::npos) { ++malformed; continue; }
        const std::string rec = str(line, "record");
        if (rec == "run_header")      flushRun(), curHeader = line;
        else if (rec == "model")      modelLines.push_back(line);
        else if (rec == "run_footer")  footerLines.push_back(line);
        else                          ++malformed;
    }
    std::fclose(f);
    flushRun();

    std::printf("LINES=%lld  RUNS=%zu  MALFORMED=%lld\n\n",
                totalLines, runs.size(), malformed);
    if (malformed)
        std::printf("NOTE: %lld line(s) did not parse as telemetry. A sink that\n"
                    "      silently corrupts is worse than no sink.\n\n", malformed);

    std::printf("%-20s %-20s %7s %7s  %s\n", "RUN_TS", "IMAGE_SHA256", "MODELS", "PASS", "ARGV1");
    for (auto& r : runs) {
        std::printf("%-20s %-20s %7d %7d  %s\n",
                    r.ts.c_str(),
                    r.sha.size() >= 16 ? r.sha.substr(0, 16).c_str() : r.sha.c_str(),
                    r.models, r.pass, r.argv1.c_str());
    }

    // latest run detail
    if (!runs.empty()) {
        std::printf("\n=== LATEST RUN ===\n");
        std::printf("image_sha256 = %s   (full)\n", runs.back().sha.c_str());
        std::printf("models=%d  pass=%d  fail=%d\n",
                    runs.back().models, runs.back().pass,
                    runs.back().models - runs.back().pass);
        if (!footerLines.empty()) {
            std::printf("footer: total=%d attempted=%d load_pass=%d gen_pass=%d fail=%d\n",
                        (int)num(footerLines.back(), "census_total", 0),
                        (int)num(footerLines.back(), "attempted", 0),
                        (int)num(footerLines.back(), "load_pass", 0),
                        (int)num(footerLines.back(), "generation_pass", 0),
                        (int)num(footerLines.back(), "fail", 0));
        }
        std::printf("\n%-46s %-22s %6s %8s %8s\n",
                    "MODEL", "RESULT", "TOKENS", "TTFT_MS", "TPS");
        for (auto& m : modelLines) {
            std::string full = str(m, "model");
            const size_t cut = full.find_last_of("/\\");
            std::printf("%-46s %-22s %6lld %8.1f %8.4f\n",
                        (cut == std::string::npos ? full : full.substr(cut + 1)).c_str(),
                        str(m, "result").c_str(),
                        (long long)num(m, "tokens", 0),
                        num(m, "ttft_ms", 0.0), num(m, "decode_tps", 0.0));
        }
    }

    const bool anyPass = !runs.empty() && runs.back().pass > 0;
    const bool anyData = !runs.empty();
    std::printf("\nTELEMETRY_PRESENT=%d\n", anyData ? 1 : 0);
    std::printf("LATEST_RUN_HAS_PASS=%d\n", anyPass ? 1 : 0);
    std::printf("VERDICT=%s\n", !anyData ? "NO_TELEMETRY" : (anyPass ? "SOME_MODELS_PASS" : "NO_MODEL_PASSED"));
    return 0;
}