// RAWRXD_WEIGHT_CONSUMPTION_CENSUS_001 -- falsification probe
//
// Proves the census (a) derives every field from recorded events, (b) refuses
// unmeasured events, (c) classifies a runtime-dependent path as CONDITIONAL
// rather than guessing, (d) reports an empty census as FAIL, and (e) cannot
// distinguish a real measurement from a claim.

#include "WeightConsumptionCensus.hpp"

#include <cstdio>
#include <string>

using namespace rawrxd::deep2::weightcensus;

static int g_fail = 0;
static int g_run  = 0;
static void check(bool c, const char* what) {
    ++g_run;
    if (!c) { ++g_fail; std::printf("FAIL: %s\n", what); }
}

static Event ev(Site s, Route r, uint64_t bytes, const char* tensor = "w") {
    Event e;
    e.site = s; e.route = r; e.bytes = bytes; e.tensor = tensor;
    return e;
}

int main() {
    auto& wc = WeightConsumptionCensus::instance();

    // ---- 1. An EMPTY census must FAIL, not PASS ---------------------------
    // A disconnected instrument reporting MEASURED would be indistinguishable
    // from a clean engine. This is the anti-false-receipt property.
    wc.reset();
    {
        Census c = wc.snapshot();
        check(c.totalEvents == 0, "empty census has no events");
        check(std::string(c.verdict()) == "FAIL_NO_MEASURED_CONSUMPTION",
              "empty census FAILs rather than reporting MEASURED");
        check(c.unobservedSites == static_cast<uint64_t>(Site::COUNT),
              "every site is UNOBSERVED when nothing ran");
    }

    // ---- 2. An event with no byte measurement must be REFUSED --------------
    {
        Census before = wc.snapshot();
        const bool ok = wc.record(ev(Site::EmbedToken, Route::Bypass, 0));
        Census after = wc.snapshot();
        check(!ok, "record() rejects a zero-byte event");
        check(after.totalEvents == before.totalEvents,
              "rejected event does not increase the event count");
        check(after.rejectedEvents == before.rejectedEvents + 1,
              "rejected event is counted as rejected");
        check(std::string(after.verdict()) == "FAIL_UNMEASURED_EVENTS_REJECTED",
              "a rejected unmeasured event forces FAIL");
    }

    // ---- 3. Ownership must be derived, never asserted -----------------------
    wc.reset();
    wc.record(ev(Site::LinearW, Route::LinearWOwned, 1024, "lmHead"));
    {
        Census c = wc.snapshot();
        const SiteReport* r = nullptr;
        for (const auto& s : c.sites) if (s.site == Site::LinearW) r = &s;
        check(r != nullptr, "LinearW site present");
        check(r && r->classification == Classification::Owned,
              "a single owned event classifies as OWNED");
        check(r && r->bytes == 1024, "byte count is carried through");
        check(c.totalBytes == 1024, "total bytes is the sum of events");
        check(std::string(c.verdict()) == "MEASURED", "a real measurement reports MEASURED");
    }

    // ---- 4. The central correction: one site, two routes => CONDITIONAL ----
    // lmHead on GPU is DELEGATED; on CPU it is OWNED. Calling either the
    // "not a bypass" answer is exactly the error this census exists to prevent.
    wc.reset();
    wc.record(ev(Site::LinearW, Route::LinearWOwned, 512, "lmHead"));    // CPU route
    wc.record(ev(Site::LinearW, Route::LinearWDelegated, 512, "lmHead")); // GPU route
    {
        Census c = wc.snapshot();
        const SiteReport* r = nullptr;
        for (const auto& s : c.sites) if (s.site == Site::LinearW) r = &s;
        check(r && r->classification == Classification::Conditional,
              "site observed under two routes classifies CONDITIONAL");
        check(c.conditionalSites == 1, "conditional site count is derived");
        check(r && r->ownedEvents == 1 && r->delegatedEvents == 1,
              "both routes counted separately");
    }

    // ---- 5. Pure bypass must classify BYPASS, not "not a bypass" ----------
    wc.reset();
    wc.record(ev(Site::RmsNormW, Route::Bypass, 2048, "attnNorm"));
    wc.record(ev(Site::EmbedToken, Route::Bypass, 4096, "tokenEmbed"));
    {
        Census c = wc.snapshot();
        const SiteReport* r = nullptr;
        for (const auto& s : c.sites) if (s.site == Site::RmsNormW) r = &s;
        check(r && r->classification == Classification::Bypass,
              "a direct-dequant site classifies LINEARW_BYPASS");
        check(c.bypassEvents == 2, "bypass event total is derived");
        check(c.unobservedSites == static_cast<uint64_t>(Site::COUNT) - 2,
              "unobserved count reflects only the sites never seen");
    }

    // ---- 6. A site is UNOBSERVED until it actually runs ---------------------
    {
        Census c = wc.snapshot();
        const SiteReport* r = nullptr;
        for (const auto& s : c.sites) if (s.site == Site::SpecQ4KGroup) r = &s;
        check(r && r->classification == Classification::Unobserved,
              "an unrun site stays UNOBSERVED and is not credited");
        check(!wc.sawSite(Site::SpecQ4KGroup), "sawSite() is false for an unrun site");
        check(wc.sawSite(Site::RmsNormW), "sawSite() is true for a run site");
    }

    // ---- 7. Out-of-range site must be rejected, not silently clamped -------
    {
        Census before = wc.snapshot();
        Event bad = ev(static_cast<Site>(9999), Route::Bypass, 16);
        check(!wc.record(bad), "record() rejects an invalid site index");
        Census after = wc.snapshot();
        check(after.totalEvents == before.totalEvents,
              "invalid site does not create an event");
    }

    // ---- 8. The receipt must actually contain the measurements -------------
    {
        Census c = wc.snapshot();
        const std::string t = c.toText();
        check(t.find("RAWRXD_WEIGHT_CONSUMPTION_CENSUS_001") != std::string::npos,
              "receipt is labelled");
        check(t.find("RmsNormW") != std::string::npos, "receipt names the site");
        check(t.find("LINEARW_BYPASS") != std::string::npos,
              "receipt states the classification");
        check(t.find("VERDICT=") != std::string::npos, "receipt carries a verdict");
    }

    // ---- 9. FALSIFICATION: clearing the census must destroy the verdict ----
    // If the census can be made to report a clean result by removing evidence
    // rather than by running the engine, it is decoration.
    // Self-contained: reset first, because earlier cases deliberately left a
    // rejected event (test 7) and the census correctly still reports it.
    {
        wc.reset();
        wc.record(ev(Site::LinearW, Route::LinearWOwned, 64, "probe"));
        std::string withData = wc.snapshot().verdict();
        wc.reset();
        std::string afterClear = wc.snapshot().verdict();
        check(withData == std::string("MEASURED"), "populated census is MEASURED");
        check(afterClear == std::string("FAIL_NO_MEASURED_CONSUMPTION"),
              "clearing the census turns the verdict to FAIL");
    }

    // ---- 10. A stray rejected event survives into the verdict --------------
    {
        wc.reset();
        wc.record(ev(Site::LinearW, Route::LinearWOwned, 64, "probe"));
        wc.record(ev(Site::LinearW, Route::Bypass, 0, "liar"));   // no measurement
        std::string v = wc.snapshot().verdict();
        check(v == std::string("FAIL_UNMEASURED_EVENTS_REJECTED"),
              "one unmeasured claim fails the census even with good data");
    }

    std::printf("CHECKS=%d FAIL=%d\n", g_run, g_fail);
    std::printf("VERDICT=%s\n", g_fail == 0 ? "PASS" : "FAIL");
    return g_fail == 0 ? 0 : 1;
}