#include "../src/deep2/Deep2QuantCert.h"
#include "../src/deep2/Deep2Determinism.h"
#include "../src/deep2/Deep2GenerationCert.h"
#include "../src/deep2/Deep2ProductionCert.h"

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <vector>

namespace {

int failures = 0;

void Check(
    bool condition,
    const char* name)
{
    std::printf(
        "[TEST] %-30s %s\n",
        name,
        condition ? "PASS" : "FAIL");

    if (!condition)
        ++failures;
}

}

int main()
{
    using namespace RawrXD::Deep2;

    /*
       Quant certification smoke test.
    */
    {
        const float a[] = {
            1.0f,
            2.0f,
            3.0f,
            4.0f
        };

        const float b[] = {
            1.0f,
            2.0f,
            3.0f,
            4.0f
        };

        const auto r =
            CertifyQuantizedOutput(
                a,
                b,
                4);

        Check(
            r.pass,
            "quant exact equality");

        Check(
            r.finite,
            "quant finite");
    }

    /*
       Determinism smoke test.
    */
    {
        DeterminismTrace a;
        DeterminismTrace b;

        const std::uint32_t tokens[] = {
            1, 42, 17, 99
        };

        a.AddTokens(tokens, 4);
        b.AddTokens(tokens, 4);

        Check(
            a.Equal(b),
            "determinism equality");

        Check(
            a.Hash() == b.Hash(),
            "determinism hash");
    }

    /*
       Generation certificate smoke test.
    */
    {
        DeterminismTrace a;
        DeterminismTrace b;

        const std::uint32_t tokens[] = {
            10, 20, 30
        };

        a.AddTokens(tokens, 3);
        b.AddTokens(tokens, 3);

        const std::vector<std::uint32_t> x = {
            10, 20, 30
        };

        const auto cert =
            CertifyGeneration(
                x,
                x,
                a,
                b,
                3);

        Check(
            cert.Pass(),
            "generation certificate");
    }

    /*
       Production certificate smoke test.
    */
    {
        ProductionCertificate cert;

        cert.gguf = true;
        cert.tokenizer = true;
        cert.embedding = true;
        cert.q4k = true;
        cert.q6k = true;
        cert.forward = true;
        cert.logits = true;
        cert.deterministic = true;
        cert.generation = true;

        Check(
            cert.Pass(),
            "production certificate");

        Check(
            cert.PassedCount() ==
                ProductionCertificate::TotalCount(),
            "production gate count");
    }

    std::printf(
        "\n[PRODUCTION_CERT] %s\n",
        failures == 0 ? "PASS" : "FAIL");

    return failures ? 1 : 0;
}
