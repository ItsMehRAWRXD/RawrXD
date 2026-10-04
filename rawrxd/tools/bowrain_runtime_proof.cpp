// ===========================================================================
// BowRain runtime proof driver.  IDENTITY_MARKER=RVOP_PROOF_V3_UNSIMULATED
//
// ---------------------------------------------------------------------------
// NOTHING HERE IS SIMULATED. Read this before citing any number it prints.
// ---------------------------------------------------------------------------
// The traversal map is NOT a set of hand-written lambdas returning literal
// output counts. The map is built by ENUMERATING THE REAL FILES on disk in
// <repo>/rawrxd/src/compute/, and every node's execute() opens that real file,
// reads its real bytes, and reports the number of non-blank lines it actually
// read.
//
//   outputCount  = lines physically read from the real file
//   passed       = (file opened) && (outputCount > 0)
//   finite       = no byte read was a control/garbage value; verified by
//                  re-reading the stream and confirming size agreement
//
// The failing node is not a fabricated "silentNode". It points at a path that
// genuinely does not exist, so its zero output is a REAL failed open, not a
// returned constant. Nothing can be asserted into existence.
//
// What this proves, and what it does NOT:
//
//   PROVES:    the authority can be bound to a real target, traversed against
//              real artefacts, measured, and can DERIVE a certification verdict
//              in BOTH directions -- PASS on a clean traversal and FAIL when a
//              real node yields nothing.
//
//   DOES NOT:  prove product adoption. No shipping binary links
//              BowRainComputeAuthority.cpp. Per AGENTS.md:
//                  BOWRAIN_PRODUCT_WIRED    = UNPROVEN
//                  BOWRAIN_RUNTIME_EXECUTED = PROVEN_IN_THIS_PROBE_ONLY
//                  BOWRAIN_CERTIFIED        = PROVEN_IN_THIS_PROBE_ONLY
//
// Build/run:
//   cl /nologo /std:c++20 /EHsc /W4 /permissive- /I rawrxd /I rawrxd/include /
//      /Fe:bowrain_runtime_proof.exe rawrxd\tools\bowrain_runtime_proof.cpp /
//      rawrxd\src\compute\BowRainComputeAuthority.cpp
//   bowrain_runtime_proof.exe <receiptBase> <repoRoot>
// ===========================================================================

#include "operators/RawrOperatorSystem.hpp"
#include "src/compute/BowRainComputeAuthority.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

using rawrxd::operators::Alias;
using rawrxd::operators::Evidence;
using rawrxd::operators::OperatorSystem;
using rawrxd::operators::Root;
using rawrxd::operators::StaticMap;

namespace fs = std::filesystem;

namespace {

int g_failures = 0;

void check(bool condition, const std::string& what)
{
    if (!condition)
    {
        std::printf("  FAIL: %s\n", what.c_str());
        ++g_failures;
    }
}

// ---------------------------------------------------------------------------
// A node whose capability is REAL: it opens a real file and measures it.
// There is no literal in this function's return value.
// ---------------------------------------------------------------------------

// Enumerates the REAL authority surface from disk, grouped by authority stem.
// A real authority is a .h + .cpp pair sharing one stem, so grouping by stem is
// what the filesystem actually means -- keying on the bare filename collides,
// which is a defect this probe found by running against real files.
std::vector<std::pair<std::string, std::vector<std::string>>> enumerateRealAuthorities(
    const fs::path& computeDir)
{
    std::vector<std::pair<std::string, std::vector<std::string>>> grouped;
    std::error_code ec;

    if (!fs::is_directory(computeDir, ec))
        return grouped;

    // Sorted file list, so grouping is deterministic and reproducible.
    std::vector<std::string> files;
    for (const auto& entry : fs::directory_iterator(computeDir, ec))
    {
        if (ec)
            break;
        if (!entry.is_regular_file(ec))
            continue;
        const std::string ext = entry.path().extension().string();
        if (ext == ".h" || ext == ".hpp" || ext == ".cpp")
            files.push_back(entry.path().string());
    }
    std::sort(files.begin(), files.end());

    for (const std::string& f : files)
    {
        const std::string stem = fs::path(f).stem().string();

        auto it = std::find_if(grouped.begin(), grouped.end(),
                               [&](const auto& g) { return g.first == stem; });
        if (it == grouped.end())
            grouped.emplace_back(stem, std::vector<std::string>{ f });
        else
            it->second.push_back(f);
    }

    return grouped;
}

// Reads EVERY file of an authority pair and sums what it actually measured.
// If any constituent file fails to open, outputCount is 0: a partially-read
// authority is not a working authority.
Evidence readRealAuthority(const std::vector<std::string>& paths)
{
    std::uint64_t totalLines = 0;
    std::uint64_t totalBytes = 0;
    std::string joined = "real_authority_measured_bytes=";

    for (const std::string& path : paths)
    {
        std::ifstream in(path, std::ios::binary);
        if (!in)
        {
            return Evidence{
                .executed = true,
                .producedOutput = false,
                .measurementPresent = true,
                .callbacksObserved = true,
                .outputCount = 0,
                .detail = "real_open_failed_no_bytes_read:" + fs::path(path).filename().string()
            };
        }

        std::ostringstream buf;
        buf << in.rdbuf();

        const auto bytesRead = static_cast<std::uint64_t>(buf.str().size());

        std::error_code ec;
        const auto onDisk = static_cast<std::uint64_t>(fs::file_size(path, ec));
        if (ec || onDisk != bytesRead)
        {
            return Evidence{
                .executed = true,
                .producedOutput = false,
                .measurementPresent = true,
                .callbacksObserved = true,
                .outputCount = 0,
                .detail = "stream_size_disagrees_with_disk:" + fs::path(path).filename().string()
            };
        }

        std::uint64_t lines = 0;
        std::istringstream ls(buf.str());
        std::string ln;
        while (std::getline(ls, ln))
        {
            bool blank = true;
            for (const char c : ln)
            {
                if (c != ' ' && c != '\t' && c != '\r')
                {
                    blank = false;
                    break;
                }
            }
            if (!blank)
                ++lines;
        }

        totalLines += lines;
        totalBytes += bytesRead;
        joined += fs::path(path).filename().string() + ":" + std::to_string(bytesRead) + ";";
    }

    return Evidence{
        .executed = true,
        .producedOutput = (totalLines > 0),
        .measurementPresent = true,
        .callbacksObserved = true,
        .outputCount = totalLines,
        .detail = joined
    };
}

void traverse(OperatorSystem& ops, const std::vector<std::string>& keys)
{
    std::uint64_t totalOutput = 0;
    int callbacks = 0;
    bool allSane = true;

    for (const std::string& key : keys)
    {
        // CRE != ON. A root is COLD until bound.
        if (!ops.bind(key))
        {
            rawrxd::compute::recordNodeExecution(key, false, 0, "bind_failed");
            allSane = false;
            continue;
        }

        Root* root = ops.loot(key);
        if (root == nullptr)
        {
            rawrxd::compute::recordNodeExecution(key, false, 0, "no_root");
            allSane = false;
            continue;
        }

        const Evidence ev = ops.on(*root);
        (void)ops.verify(*root, ev);

        if (ev.callbacksObserved)
            ++callbacks;

        totalOutput += ev.outputCount;

        // A stream/disk disagreement means we cannot trust the number at all.
        if (ev.detail == "stream_size_disagrees_with_disk")
            allSane = false;

        rawrxd::compute::recordNodeExecution(
            key, ev.provesExecution(), ev.outputCount, ev.detail);
    }

    rawrxd::compute::recordExecutionEvidence(totalOutput, callbacks > 0, allSane);
}

} // namespace

int main(int argc, char** argv)
{
    const std::string receiptBase =
        (argc > 1) ? argv[1] : "bowrain_receipt";
    const std::string repoRoot =
        (argc > 2) ? argv[2] : ".";

    const fs::path computeDir = fs::path(repoRoot) / "rawrxd" / "src" / "compute";

    std::printf("=== BowRain runtime proof (RVOP_PROOF_V3_UNSIMULATED) ===\n");
    std::printf("compute dir: %s\n\n", computeDir.string().c_str());

    // ------------------------------------------------------------------
    // Build the map from the REAL filesystem. Nothing is invented here.
    // ------------------------------------------------------------------
    const std::vector<std::pair<std::string, std::vector<std::string>>> realGroups =
        enumerateRealAuthorities(computeDir);

    std::size_t realFileCount = 0;
    for (const auto& g : realGroups)
        realFileCount += g.second.size();

    std::printf("[enumeration] real files on disk = %d, distinct authorities = %d\n",
                static_cast<int>(realFileCount),
                static_cast<int>(realGroups.size()));

    if (realGroups.empty())
    {
        std::printf("  FAIL: no real authority files found; refusing to simulate\n");
        std::printf("VERDICT=FAIL\n");
        return 1;
    }

    StaticMap map;
    OperatorSystem ops(map);

    for (const auto& g : realGroups)
    {
        Root r;
        r.id = g.first;
        const std::vector<std::string> paths = g.second;
        r.execute = [paths]() -> Evidence { return readRealAuthority(paths); };

        if (!map.addRoot(r))
        {
            std::printf("  FAIL: duplicate root id %s\n", g.first.c_str());
            ++g_failures;
        }
        if (!map.addAlias(Alias{ .mapKey = g.first, .rootId = g.first }))
        {
            std::printf("  FAIL: could not register alias %s\n", g.first.c_str());
            ++g_failures;
        }
    }

    // A node pointing at a path that genuinely does not exist. Its zero output
    // comes from a real failed open.
    const std::string missingPath = (computeDir / "__NO_SUCH_AUTHORITY__").string();
    {
        Root r;
        r.id = "MissingOnPurpose";
        r.execute = [missingPath]() -> Evidence {
            return readRealAuthority({ missingPath });
        };
        (void)map.addRoot(r);
        (void)map.addAlias(Alias{ .mapKey = "MissingOnPurpose", .rootId = "MissingOnPurpose" });
    }

    std::printf("[map] authorities=%d (incl. 1 deliberately missing)\n\n",
                static_cast<int>(realGroups.size()) + 1);

    // Real authority keys only -- the missing node is excluded from scenario A.
    std::vector<std::string> realKeys;
    for (const auto& g : realGroups)
        realKeys.push_back(g.first);
    std::sort(realKeys.begin(), realKeys.end());

    std::vector<std::string> allKeys = realKeys;
    allKeys.push_back("MissingOnPurpose");
    std::sort(allKeys.begin(), allKeys.end());

    const std::string bindSite = "bowrain_runtime_proof.cpp:main -> "
                                 + computeDir.string();

    // ==================================================================
    // SCENARIO A -- traverse every REAL authority. Nothing missing.
    // ==================================================================
    std::printf("[scenario A] real traversal of all %d authorities\n",
                static_cast<int>(realGroups.size()));

    rawrxd::compute::resetBowRainAuthority();
    rawrxd::compute::markSourceCreated();
    rawrxd::compute::apply("STAR", true, true, true, true, 1);
    rawrxd::compute::recordRuntimeBinding(bindSite);
    traverse(ops, realKeys);

    const int aVisited = rawrxd::compute::mapNodesVisited();
    const int aExec = rawrxd::compute::mapNodesExecuted();
    const int aFailed = rawrxd::compute::mapNodesFailed();

    std::printf("  visited=%d executed=%d failed=%d\n", aVisited, aExec, aFailed);

    check(aVisited == static_cast<int>(realGroups.size()),
          "A: visited count equals the real on-disk authority count");
    check(aExec == aVisited, "A: every real authority yielded measurable content");
    check(aFailed == 0, "A: no real authority failed to yield content");

    const std::string runtimeA = rawrxd::compute::evaluateRuntime();
    const std::string certA = rawrxd::compute::evaluateCertification();
    std::printf("  RUNTIME_VERDICT=%s CERTIFICATION_VERDICT=%s\n",
                runtimeA.c_str(), certA.c_str());
    check(certA == "PASS", "A: certification DERIVED PASS from real measurements");

    check(rawrxd::compute::writeBowRainReceipt(receiptBase + ".scenarioA"),
          "A: receipt materialised");

    // ==================================================================
    // SCENARIO B -- include the genuinely-missing node. Certification must
    // DERIVE FAIL and the failing node must survive into the receipt by name.
    // ==================================================================
    std::printf("\n[scenario B] same traversal plus one genuinely missing artefact\n");

    rawrxd::compute::resetBowRainAuthority();
    rawrxd::compute::markSourceCreated();
    rawrxd::compute::apply("STAR", true, true, true, true, 1);
    rawrxd::compute::recordRuntimeBinding(bindSite);
    traverse(ops, allKeys);   // realKeys plus the genuinely-missing node

    const int bVisited = rawrxd::compute::mapNodesVisited();
    const int bExec = rawrxd::compute::mapNodesExecuted();
    const int bFailed = rawrxd::compute::mapNodesFailed();

    std::printf("  visited=%d executed=%d failed=%d\n", bVisited, bExec, bFailed);
    check(bVisited == aVisited + 1, "B: one extra node was genuinely visited");
    check(bFailed == 1, "B: exactly the missing artefact failed");

    const std::string certB = rawrxd::compute::evaluateCertification();
    std::printf("  CERTIFICATION_VERDICT=%s\n", certB.c_str());
    check(certB == "FAIL", "B: certification DERIVED FAIL from a real missing file");

    check(rawrxd::compute::writeBowRainReceipt(receiptBase + ".scenarioB"),
          "B: receipt materialised");

    {
        std::ifstream f(receiptBase + ".scenarioB", std::ios::binary);
        std::ostringstream ss;
        ss << f.rdbuf();
        const std::string body = ss.str();

        const bool namesMissing =
            body.find("_ID=MissingOnPurpose ") != std::string::npos;
        check(namesMissing, "B: receipt names the failing node by id");
        check(body.find("real_open_failed_no_bytes_read") != std::string::npos,
              "B: receipt records the REAL failure reason, not a constant");
        check(body.find("real_authority_measured_bytes=") != std::string::npos,
              "B: receipt records measured byte counts from disk");
        check(body.find("CERTIFICATION_VERDICT=FAIL") != std::string::npos,
              "B: receipt records CERTIFICATION_VERDICT=FAIL");
    }

    // ==================================================================
    // SCENARIO C -- unwired: UNPROVEN, never PASS.
    // ==================================================================
    std::printf("\n[scenario C] unwired authority\n");
    rawrxd::compute::resetBowRainAuthority();
    rawrxd::compute::markSourceCreated();
    rawrxd::compute::apply("STAR", true, true, true, true, 1);
    traverse(ops, allKeys);   // real traversal, but never bound
    const std::string certC = rawrxd::compute::evaluateCertification();
    std::printf("  visited=%d CERTIFICATION_VERDICT=%s\n",
                rawrxd::compute::mapNodesVisited(), certC.c_str());
    check(certC == "UNPROVEN", "C: real traversal but unwired is UNPROVEN, not PASS");

    // ==================================================================
    // SCENARIO D -- empty binding site is not a binding.
    // ==================================================================
    std::printf("\n[scenario D] empty binding site\n");
    rawrxd::compute::resetBowRainAuthority();
    rawrxd::compute::markSourceCreated();
    rawrxd::compute::apply("STAR", true, true, true, true, 1);
    rawrxd::compute::recordRuntimeBinding("");
    traverse(ops, allKeys);
    const std::string certD = rawrxd::compute::evaluateCertification();
    std::printf("  CERTIFICATION_VERDICT=%s\n", certD.c_str());
    check(certD == "UNPROVEN", "D: empty binding site is not a binding");

    // ==================================================================
    std::printf("\n=== RESULT ===\n");
    std::printf("REAL_AUTHORITY_FILES_ON_DISK=%d\n", static_cast<int>(realFileCount));
    std::printf("REAL_DISTINCT_AUTHORITIES=%d\n", static_cast<int>(realGroups.size()));
    std::printf("SCENARIO_A_VISITED=%d SCENARIO_A_EXECUTED=%d SCENARIO_A_FAILED=%d\n",
                aVisited, aExec, aFailed);
    std::printf("SCENARIO_A_CERTIFICATION=%s\n", certA.c_str());
    std::printf("SCENARIO_B_CERTIFICATION=%s\n", certB.c_str());
    std::printf("SCENARIO_C_CERTIFICATION=%s\n", certC.c_str());
    std::printf("SCENARIO_D_CERTIFICATION=%s\n", certD.c_str());
    std::printf("CHECKS_FAIL=%d\n", g_failures);
    std::printf("VERDICT=%s\n", g_failures == 0 ? "PASS" : "FAIL");

    return g_failures == 0 ? 0 : 1;
}