#include "Deep2ProductionCert.h"

#include <cstdio>

namespace RawrXD::Deep2 {

namespace {

void PrintGate(
    const char* name,
    bool pass)
{
    std::printf(
        "[CERT] %-18s %s\n",
        name,
        pass ? "PASS" : "FAIL");
}

}

extern "C" void Deep2PrintProductionCertificate(
    const ProductionCertificate& cert)
{
    PrintGate("GGUF",          cert.gguf);
    PrintGate("TOKENIZER",     cert.tokenizer);
    PrintGate("EMBEDDING",     cert.embedding);
    PrintGate("Q4_K",          cert.q4k);
    PrintGate("Q6_K",          cert.q6k);
    PrintGate("FORWARD",       cert.forward);
    PrintGate("LOGITS",        cert.logits);
    PrintGate("DETERMINISM",   cert.deterministic);
    PrintGate("GENERATION",    cert.generation);

    std::printf(
        "[CERT] RESULT            %s (%zu/%zu)\n",
        cert.Pass() ? "PASS" : "FAIL",
        cert.PassedCount(),
        ProductionCertificate::TotalCount());
}

} // namespace RawrXD::Deep2
