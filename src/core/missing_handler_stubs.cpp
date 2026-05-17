// Production note:
// This translation unit intentionally avoids including generated history artifacts.
// Runtime command handlers are provided by ssot_handlers.cpp / ssot handler lanes.

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>

namespace {
std::atomic<unsigned long long> g_anchorCalls{0};
std::atomic<unsigned long long> g_providerChecks{0};
std::atomic<unsigned long long> g_providerMatchCount{0};
std::atomic<unsigned long long> g_providerMismatchCount{0};
std::atomic<unsigned long long> g_providerUnknownCount{0};
std::atomic<unsigned long long> g_probeSkippedCount{0};
std::atomic<unsigned long long> g_lastStatusCode{0};
std::atomic<bool> g_checkedOnce{false};
std::atomic<bool> g_lastMatched{false};
std::atomic<bool> g_lastKnown{false};

bool isWhitespace(char c)
{
    const unsigned char u = static_cast<unsigned char>(c);
    return std::isspace(u) != 0;
}

bool hasText(const char* s)
{
	if (!s) {
		return false;
	}
	while (*s && isWhitespace(*s)) {
		++s;
	}
	return *s != '\0';
}

void normalizeToken(const char* src, char* dst, size_t dstSize)
{
	if (!dst || dstSize == 0) {
		return;
	}
	dst[0] = '\0';
	if (!src) {
		return;
	}

	size_t out = 0;
	bool prevSep = false;
	for (const char* p = src; *p != '\0' && out + 1 < dstSize; ++p) {
		unsigned char uc = static_cast<unsigned char>(*p);
		if (std::isalnum(uc) != 0) {
			dst[out++] = static_cast<char>(std::tolower(uc));
			prevSep = false;
			continue;
		}

		if (!prevSep) {
			dst[out++] = '_';
			prevSep = true;
		}
	}

	while (out > 0 && dst[out - 1] == '_') {
		--out;
	}
	dst[out] = '\0';
}

const char* getExpectedProvider()
{
	const char* v = std::getenv("RAWRXD_SSOT_PROVIDER_EXPECTED");
	if (hasText(v)) {
		return v;
	}
	v = std::getenv("RAWR_SSOT_PROVIDER_EXPECTED");
	if (hasText(v)) {
		return v;
	}
	v = std::getenv("RAWRXD_SSOT_PROVIDER");
	if (hasText(v)) {
		return v;
	}
	return nullptr;
}

const char* getActiveProvider()
{
	const char* v = std::getenv("RAWRXD_SSOT_PROVIDER_ACTIVE");
	if (hasText(v)) {
		return v;
	}
	v = std::getenv("RAWR_SSOT_PROVIDER_ACTIVE");
	if (hasText(v)) {
		return v;
	}
	v = std::getenv("RAWRXD_RUNTIME_PROVIDER");
	if (hasText(v)) {
		return v;
	}
	return nullptr;
}

void runProviderConsistencyCheckOnce()
{
	const bool runAlways = hasText(std::getenv("RAWRXD_SSOT_PROVIDER_PROBE_ALWAYS"));
	if (!runAlways) {
		bool expected = false;
		if (!g_checkedOnce.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
			g_probeSkippedCount.fetch_add(1, std::memory_order_relaxed);
			g_lastStatusCode.store(1, std::memory_order_release); // cached/skip path
			return;
		}
	}

	g_providerChecks.fetch_add(1, std::memory_order_relaxed);

	const char* expectedProvider = getExpectedProvider();
	const char* activeProvider = getActiveProvider();
	if (!hasText(expectedProvider) || !hasText(activeProvider)) {
		g_lastKnown.store(false, std::memory_order_release);
		g_lastMatched.store(false, std::memory_order_release);
		g_providerUnknownCount.fetch_add(1, std::memory_order_relaxed);
		g_lastStatusCode.store(2, std::memory_order_release); // unknown provider
		if (hasText(std::getenv("RAWRXD_SSOT_PROVIDER_LOG_UNKNOWN"))) {
			std::fprintf(stderr,
					 "[RawrXD::Core] SSOT provider probe unknown expected=%s active=%s\n",
					 expectedProvider ? expectedProvider : "<unset>",
					 activeProvider ? activeProvider : "<unset>");
		}
		return;
	}

	char expectedNorm[96];
	char activeNorm[96];
	normalizeToken(expectedProvider, expectedNorm, sizeof(expectedNorm));
	normalizeToken(activeProvider, activeNorm, sizeof(activeNorm));

	const bool match = (std::strcmp(expectedNorm, activeNorm) == 0);
	g_lastKnown.store(true, std::memory_order_release);
	g_lastMatched.store(match, std::memory_order_release);
	if (match) {
		g_providerMatchCount.fetch_add(1, std::memory_order_relaxed);
		g_lastStatusCode.store(3, std::memory_order_release); // matched
		return;
	}

	g_providerMismatchCount.fetch_add(1, std::memory_order_relaxed);
	g_lastStatusCode.store(4, std::memory_order_release); // mismatch
	std::fprintf(stderr,
				 "[RawrXD::Core] SSOT provider mismatch expected=%s(%s) active=%s(%s)\n",
				 expectedProvider,
				 expectedNorm,
				 activeProvider,
				 activeNorm);
}
} // namespace

namespace RawrXD::Core {
void ensureMissingHandlerStubsLinked()
{
	g_anchorCalls.fetch_add(1, std::memory_order_relaxed);
	runProviderConsistencyCheckOnce();
}
}  // namespace RawrXD::Core

extern "C" unsigned __int64 rawrxd_missing_handler_stub_stats()
{
	// [63:48] mismatch, [47:32] unknown, [31:16] checks, [15:8] matched, [7:0] calls.
	const unsigned long long calls = g_anchorCalls.load(std::memory_order_relaxed) & 0xFFULL;
	const unsigned long long matched = g_providerMatchCount.load(std::memory_order_relaxed) & 0xFFULL;
	const unsigned long long checks = g_providerChecks.load(std::memory_order_relaxed) & 0xFFFFULL;
	const unsigned long long unknown = g_providerUnknownCount.load(std::memory_order_relaxed) & 0xFFFFULL;
	const unsigned long long mismatch = g_providerMismatchCount.load(std::memory_order_relaxed) & 0xFFFFULL;
	return calls | (matched << 8) | (checks << 16) | (unknown << 32) | (mismatch << 48);
}

extern "C" int rawrxd_missing_handler_stub_provider_ok()
{
	const bool known = g_lastKnown.load(std::memory_order_acquire);
	if (!known) {
		return -1;
	}
	return g_lastMatched.load(std::memory_order_acquire) ? 1 : 0;
}

extern "C" unsigned __int64 rawrxd_missing_handler_stub_extended_stats()
{
	// [63:56] last_status, [55:48] skipped, [47:32] mismatch,
	// [31:16] unknown, [15:8] matched, [7:0] calls.
	const unsigned long long status = g_lastStatusCode.load(std::memory_order_relaxed) & 0xFFULL;
	const unsigned long long skipped = g_probeSkippedCount.load(std::memory_order_relaxed) & 0xFFULL;
	const unsigned long long mismatch = g_providerMismatchCount.load(std::memory_order_relaxed) & 0xFFFFULL;
	const unsigned long long unknown = g_providerUnknownCount.load(std::memory_order_relaxed) & 0xFFFFULL;
	const unsigned long long matched = g_providerMatchCount.load(std::memory_order_relaxed) & 0xFFULL;
	const unsigned long long calls = g_anchorCalls.load(std::memory_order_relaxed) & 0xFFULL;
	return (status << 56) | (skipped << 48) | (mismatch << 32) | (unknown << 16) | (matched << 8) | calls;
}

extern "C" void rawrxd_missing_handler_stub_reset_stats()
{
	g_anchorCalls.store(0, std::memory_order_relaxed);
	g_providerChecks.store(0, std::memory_order_relaxed);
	g_providerMatchCount.store(0, std::memory_order_relaxed);
	g_providerMismatchCount.store(0, std::memory_order_relaxed);
	g_providerUnknownCount.store(0, std::memory_order_relaxed);
	g_probeSkippedCount.store(0, std::memory_order_relaxed);
	g_lastStatusCode.store(0, std::memory_order_relaxed);
	g_checkedOnce.store(false, std::memory_order_relaxed);
	g_lastMatched.store(false, std::memory_order_relaxed);
	g_lastKnown.store(false, std::memory_order_relaxed);
}
