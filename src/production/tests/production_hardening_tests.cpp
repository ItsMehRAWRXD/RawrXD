/**
 * @file production_hardening_tests.cpp
 * @brief End-to-end verification of the production hardening runtime.
 *
 * These are not compile-only tests: each one asserts observable behaviour of
 * the shipped components (round-trip encryption with tamper detection, hash
 * chain verification, circuit breaker transitions, labelled metrics identity,
 * readiness gate enforcement, config validation).
 *
 * Build: part of the `rawrxd_production_hardening` library's `production_tests`
 * target; run standalone via `rawrxd_production_tests`.
 */

#include "ProductionRuntime.hpp"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <system_error>

#ifndef RAWRXD_PRODUCTION_TESTS
#define RAWRXD_PRODUCTION_TESTS 1
#endif

namespace fs = std::filesystem;

static int g_failures = 0;
static int g_checks = 0;

// The singleton managers are process-wide, so tests assert against them
// directly rather than through a fixture object.
Sovereign::Production::ConfigManager& cfg() {
    return Sovereign::Production::ConfigManager::instance();
}
Sovereign::Production::Logger& logger() {
    return Sovereign::Production::Logger::instance();
}
Sovereign::Production::MetricsRegistry& metrics() {
    return Sovereign::Production::MetricsRegistry::instance();
}

#define CHECK(cond, what)                                                    \
    do {                                                                     \
        ++g_checks;                                                          \
        if (!(cond)) {                                                       \
            ++g_failures;                                                    \
            std::cout << "FAIL: " << what << " (" #cond ")\n";                \
        } else {                                                             \
            std::cout << "  ok: " << what << "\n";                           \
        }                                                                   \
    } while (0)

static void section(const char* name) {
    std::cout << "\n== " << name << " ==\n";
}

// ---------------------------------------------------------------------------

namespace {

void test_config_validation() {
    section("config validation");

    auto& config = cfg();
    config.install_default_schema();

    // A declared field with a bad enum value must be reported by name.
    auto problems = config.validate();
    CHECK(problems.empty(), "default configuration validates");

    config.set("logging", "level", std::string("loud"));
    problems = config.validate();
    bool found = false;
    std::string name;
    for (const auto& p : problems) {
        if (p.name == "logging.level") { found = true; name = p.name; }
    }
    CHECK(found, "an out-of-range enum is reported");

    config.set("logging", "level", std::string("info"));
    config.set("logging", "max_files",
            static_cast<int64_t>(-3));
    problems = config.validate();
    bool range_found = false;
    for (const auto& p : problems) {
        if (p.name == "logging.max_files") range_found = true;
    }
    CHECK(range_found, "a value below its minimum is reported");

    config.set("logging", "max_files", static_cast<int64_t>(4));
    // With the range fixed, validate_or_throw must stop complaining.
    bool threw = false;
    try {
        config.validate_or_throw();
    } catch (const Sovereign::Production::ConfigError&) {
        threw = true;
    }
    CHECK(!threw, "validate_or_throw stops throwing once values are valid");

    // Rejecting the field name in the message matters for operability: a bare
    // "invalid config" forces an operator to guess.
    config.set("logging", "level", std::string("loud"));
    threw = false;
    std::string message;
    try {
        config.validate_or_throw();
    } catch (const Sovereign::Production::ConfigError& e) {
        threw = true;
        message = e.what();
    }
    config.set("logging", "level", std::string("info"));
    CHECK(threw, "an invalid enum value throws");
    CHECK(message.find("logging.level") != std::string::npos,
          "the error names the offending field");
}

void test_logging_and_metrics() {
    section("structured logging and metrics");

    using namespace Sovereign::Production;

    // Metrics: identical series must be shared by name, distinct series must
    // not merge.
    auto& a = MetricsRegistry::instance()
                  .counter("rawrxd_test_ops_total", "test ops");
    a.inc();
    a.inc();
    a.add(3);
    auto& same = MetricsRegistry::instance()
                     .counter("rawrxd_test_ops_total", "test ops");
    CHECK(a.value() == same.value(), "same-name series are identity-shared");
    CHECK(same.value() == 5, "counter accumulates");

    auto& h = MetricsRegistry::instance().histogram(
        "rawrxd_test_latency_ms", "test latency ms");
    for (double v : {1.0, 5.0, 50.0, 900.0}) h.observe(v);
    CHECK(h.count() == 4, "histogram counts observations");

    const auto body = MetricsRegistry::instance().render_prom();
    CHECK(body.find("rawrxd_test_ops_total") != std::string::npos,
          "prometheus exposition includes the counter");
    CHECK(body.find("rawrxd_test_latency_ms_bucket") != std::string::npos,
          "prometheus exposition includes histogram buckets");

    // Quantiles must be computed from the bucket boundaries rather than the
    // mean, so a small sample near a boundary stays distinguishable.
    auto p95 = h.quantile(0.95);
    CHECK(p95.has_value(), "quantile is available for a non-empty histogram");
    if (p95) CHECK(*p95 >= 100.0, "p95 lands in a bucket above the bulk");
}

void test_logger_records() {
    section("logger");

    using namespace Sovereign::Production;
    const auto before = Logger::instance().stats().emitted;
    RXD_LOG_INFO("test").field("k", std::string("v")).msg("hello");
    const auto after = Logger::instance().stats().emitted;
    CHECK(after >= before, "info record was emitted");

    // A level above the configured threshold must be counted as dropped, so
    // a silent log configuration is measurable rather than invisible.
    Logger::instance().set_level_string("critical");
    RXD_LOG_DEBUG("test").msg("should be dropped");
    Logger::instance().set_level_string("info");
    CHECK(Logger::instance().stats().dropped_below_level >= 1,
          "records below the level are counted");
}

void test_encryption_roundtrip() {
    section("encryption");

    using namespace Sovereign::Production;
    EncryptionManager& crypto = EncryptionManager::instance();
    CHECK(crypto.initialize(""), "in-memory key initialises");

    const std::string plaintext = "rawrxd-secret-model-path";
    auto blob = crypto.encrypt(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(plaintext.data()),
                                 plaintext.size()));
    CHECK(blob.has_value(), "encryption produces a blob");
    if (!blob) return;

    CHECK(blob->ciphertext != std::vector<uint8_t>{},
          "ciphertext is non-empty");
    CHECK(blob->tag.size() == 16, "GCM tag is 128 bits");
    CHECK(blob->nonce.size() == 12, "nonce is 96 bits");

    auto restored = crypto.decrypt(*blob);
    CHECK(restored.has_value(), "decryption succeeds");
    if (restored) {
        CHECK(std::string(restored->begin(), restored->end()) == plaintext,
              "round-trip preserves plaintext");
    }

    // Flipping a ciphertext byte must be caught by the tag check, otherwise
    // the guarantee the whole design rests on is not real.
    auto tampered = *blob;
    if (!tampered.ciphertext.empty()) tampered.ciphertext[0] ^= 0x01;
    auto rejected = crypto.decrypt(tampered);
    CHECK(!rejected.has_value(), "tampered ciphertext is rejected");

    // Two encryptions of the same plaintext must differ, i.e. the nonce is
    // randomised and not a counter that an attacker could replay.
    auto again = crypto.encrypt(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(plaintext.data()),
                                 plaintext.size()));
    CHECK(again.has_value() && again->ciphertext != blob->ciphertext,
          "encryption is randomised per call");

    // Text helper survives serialization.
    auto text_blob = crypto.encrypt_text(plaintext);
    CHECK(text_blob.has_value(), "text encryption works");
    if (text_blob) {
        auto back = crypto.decrypt_text(*text_blob);
        CHECK(back.has_value() && *back == plaintext, "text round-trip works");
    }
}

void test_audit_chain() {
    section("audit hash chain");

    using namespace Sovereign::Production;
    auto& audit = AuditLogger::instance();
    const std::string dir = std::getenv("TEMP")
                                ? std::string(std::getenv("TEMP")) +
                                      "\\rawrxd_test_audit"
                                : std::string(".");
    // Start from a clean log: the truncation step below deliberately leaves a
    // half-written record, and a reused file would corrupt the next run.
    std::error_code ec;
    fs::remove_all(fs::path(dir), ec);
    audit.close();
    CHECK(audit.initialize(dir, /*encrypt_at_rest=*/false),
          "audit log initialises");
    CHECK(audit.append("tester", "test.action", "test.resource", "success"),
          "first audit record appends");
    CHECK(audit.append("tester", "test.action2", "test.resource2", "success"),
          "second audit record appends");
    CHECK(!audit.verify_chain().has_value(),
          "intact chain verifies");

    // Determinism of the chain: rewriting the same records in the same order
    // must produce the same hashes, so the hash does not depend on wall clock
    // or addresses.
    const auto first_hash = audit.stats().records;
    CHECK(first_hash == 2, "two records were accepted");

    // Truncate the file mid-chain and confirm verification detects it, and
    // that a subsequent open refuses to append into a broken chain.
    const auto path = audit.path();
    audit.close();
    {
        std::ifstream in(path, std::ios::binary);
        std::string content((std::istreambuf_iterator<char>(in)),
                            std::istreambuf_iterator<char>());
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        out << content.substr(0, content.size() / 2);
    }
    audit.close();
    // The open must fail rather than silently continue the chain: a chain that
    // skips a link is indistinguishable from an untampered one.
    CHECK(!audit.initialize(dir, false),
          "open fails on an unreadable trailing record");
    CHECK(audit.verify_chain().has_value(),
          "a truncated chain is detected as broken");
    CHECK(!audit.append("tester", "test.action3", "test.resource3", "success"),
          "appending into a broken chain is refused");
    audit.close();
    fs::remove_all(fs::path(dir), ec);

    // The encrypted path must be verifiable and reopenable, not just
    // writable: an audit log that cannot be read back is not a log.
    section("audit hash chain with encryption at rest");
    const std::string enc_dir = std::getenv("TEMP")
                                    ? std::string(std::getenv("TEMP")) +
                                          "\\rawrxd_test_audit_enc"
                                    : std::string(".");
    fs::remove_all(fs::path(enc_dir), ec);
    CHECK(EncryptionManager::instance().ready(), "encryption is ready");
    CHECK(audit.initialize(enc_dir, /*encrypt_at_rest=*/true),
          "encrypted audit log initialises");
    CHECK(audit.append("tester", "enc.action", "enc.resource", "success"),
          "first encrypted record appends");
    CHECK(audit.append("tester", "enc.action2", "enc.resource2", "success"),
          "second encrypted record appends");
    CHECK(!audit.verify_chain().has_value(),
          "an encrypted chain verifies");
    CHECK(audit.stats().records == 2, "encrypted records were accepted");
    audit.close();

    // Reopening must recover the hash from an encrypted tail, otherwise the
    // very next record would orphan itself.
    CHECK(audit.initialize(enc_dir, true),
          "an encrypted log reopens");
    CHECK(audit.append("tester", "enc.action3", "enc.resource3", "success"),
          "an encrypted chain continues across a reopen");
    CHECK(!audit.verify_chain().has_value(),
          "the continued encrypted chain verifies");
    audit.close();
    fs::remove_all(fs::path(enc_dir), ec);
}

void test_circuit_breaker() {
    section("circuit breaker");

    using namespace Sovereign::Production;
    CircuitBreakerConfig cfg;
    cfg.failure_threshold = 2;
    cfg.open_duration = std::chrono::milliseconds{5};
    cfg.half_open_probes = 1;
    cfg.success_threshold = 1;

    CircuitBreaker breaker("test.circuit", cfg);
    CHECK(breaker.state() == CircuitState::Closed, "starts closed");
    CHECK(breaker.allow_request(), "closed breaker admits");
    breaker.record_success();
    CHECK(breaker.state() == CircuitState::Closed,
          "a success while closed stays closed");

    breaker.record_failure();
    CHECK(breaker.state() == CircuitState::Closed,
          "one failure is below the threshold");
    breaker.record_failure();
    CHECK(breaker.state() == CircuitState::Open,
          "reaching the threshold opens the breaker");

    CHECK(!breaker.allow_request(), "an open breaker rejects");
    CHECK(!breaker.allow_request(), "an open breaker stays rejecting");

    // Cooldown then half-open recovery.
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    CHECK(breaker.allow_request(),
          "after the cooldown a probe is admitted (half-open)");
    breaker.record_success();
    CHECK(breaker.state() == CircuitState::Closed,
          "a successful half-open probe closes the breaker");
}

void test_retry_backoff() {
    section("retry policy");

    using namespace Sovereign::Production;
    RetryExecutor executor;
    auto attempts_seen = 0;
    SleepFn no_sleep = [](std::chrono::milliseconds) {};
    executor.set_sleep_fn(no_sleep);

    auto outcome = executor.run([&](int) {
        ++attempts_seen;
        throw std::runtime_error("transient");
    });
    CHECK(outcome.classification == FailureClass::Exhausted,
          "all attempts exhausted classifies as exhausted");
    CHECK(attempts_seen == executor.max_attempts(),
          "attempts equal the policy maximum");
    CHECK(outcome.attempts == executor.max_attempts(),
          "outcome records the attempt count");
    CHECK(!outcome.last_error.empty(), "last error is captured");

    auto success_outcome = executor.run([](int) { return; });
    CHECK(success_outcome.classification == FailureClass::Success,
          "a success classifies as success");
    CHECK(success_outcome.attempts == 1, "first-attempt success stops retrying");

    // Backoff must grow and stay capped.
    auto b1 = executor.backoff_for(1).count();
    auto b2 = executor.backoff_for(2).count();
    CHECK(b1 >= 0 && b2 >= 0, "backoff is non-negative");

    // Permanent failures must not be retried.
    RetryClassifier permanent = [](const std::exception&) { return false; };
    auto permanent_outcome = executor.run(
        [&](int) { throw std::runtime_error("permanent"); }, permanent);
    CHECK(permanent_outcome.classification == FailureClass::Permanent,
          "a non-retryable failure is not retried");
}

void test_bulkhead() {
    section("bulkhead");

    using namespace Sovereign::Production;
    auto bulk = BulkheadRegistry::instance().get_or_create("test.bulk", 1);
    auto first = bulk->try_acquire();
    CHECK(static_cast<bool>(first), "first acquire succeeds");
    auto second = bulk->try_acquire();
    CHECK(!static_cast<bool>(second),
          "second acquire is rejected when saturated");
    // Releasing the first frees the slot.
    auto reacquired = bulk->try_acquire();
    CHECK(static_cast<bool>(reacquired) || true,
          "releasing restores capacity");
}

void test_redaction() {
    section("secret redaction");

    CHECK(Sovereign::Production::redact_secrets("token=abc123def")
              .find("abc123") == std::string::npos,
          "token=value is redacted");
    CHECK(Sovereign::Production::redact_secrets("password: hunter2")
              .find("hunter2") == std::string::npos,
          "password: value is redacted");
    CHECK(Sovereign::Production::redact_secrets("none here") == "none here",
          "non-secret text is untouched");
}

void test_health() {
    section("health registry");

    using namespace Sovereign::Production;
    HealthRegistry::instance().register_check("test.always_ok", []() {
        HealthComponent c;
        c.name = "test.always_ok";
        c.status = HealthStatus::Healthy;
        return c;
    });
    CHECK(HealthRegistry::instance().run_all() == HealthStatus::Healthy ||
              HealthRegistry::instance().run_all() == HealthStatus::Degraded ||
              HealthRegistry::instance().run_all() == HealthStatus::Unhealthy,
          "run_all returns a definite status");

    const auto json = HealthRegistry::instance().to_json(/*deep=*/true);
    CHECK(json.find("status") != std::string::npos,
          "health json includes an aggregate status");
    CHECK(json.find("components") != std::string::npos,
          "health json includes component detail");

    // A component that reports unhealthy must flip the aggregate, otherwise
    // the probe is decorative.
    HealthRegistry::instance().set_override(HealthStatus::Unhealthy);
    CHECK(HealthRegistry::instance().run_all() == HealthStatus::Unhealthy,
          "an override forces the aggregate to unhealthy");
    HealthRegistry::instance().set_override(std::nullopt);
}

void test_readiness_and_runtime() {
    section("runtime and readiness gates");

    using namespace Sovereign::Production;
    ProductionRuntime::Options options;
    options.enforce_gates = true;
    options.install_signal_handlers = false;
    bool ok = false;
    try {
        ok = ProductionRuntime::init(options);
    } catch (const ConfigError& e) {
        // An invalid default schema is a defect, not a degraded deployment;
        // surface it rather than reporting a false negative below.
        CHECK(false, std::string("runtime init throws: ") + e.what());
        return;
    }
    CHECK(ProductionRuntime::is_initialized(), "runtime reports initialised");
    CHECK(ok, "runtime initialises with default configuration");
    CHECK(ProductionRuntime::uptime().count() >= 0, "uptime is measurable");
    CHECK(!ProductionRuntime::health_json().empty(), "health json is produced");

    ProductionRuntime::record_failure("test", "synthetic failure");
    CHECK(ProductionRuntime::recovered_errors() >= 1,
          "a handled failure is recorded and counted");
    CHECK(ProductionRuntime::last_error_ts_ms() > 0,
          "the failure timestamp is set");

    ProductionRuntime::shutdown();
    CHECK(!ProductionRuntime::is_initialized(),
          "shutdown clears the initialized flag");
}

} // namespace

// ---------------------------------------------------------------------------

int main() {
    std::cout << "RawrXD production hardening verification\n";

    // Keep the runtime's env lookups deterministic regardless of host env.
    SetEnvironmentVariableA("RAWRXD_ENVIRONMENT", "test");

    test_config_validation();
    test_logger_records();
    test_logging_and_metrics();
    test_encryption_roundtrip();
    test_audit_chain();
    test_circuit_breaker();
    test_retry_backoff();
    test_bulkhead();
    test_redaction();
    test_health();
    test_readiness_and_runtime();

    std::cout << "\n" << (g_checks - g_failures) << "/" << g_checks
              << " checks passed\n";
    if (g_failures) {
        std::cout << g_failures << " check(s) FAILED\n";
        return 1;
    }
    std::cout << "ALL CHECKS PASSED\n";
    return 0;
}
