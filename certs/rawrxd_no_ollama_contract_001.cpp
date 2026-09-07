// certs/rawrxd_no_ollama_contract_001.cpp — U10
#include "../src/deep2/SemanticSafe.hpp"
#include "../src/deep2/RawrRunSession.hpp"
#include <cstdio>
using namespace Deep2;
using namespace Deep2::rawr_run;

int main() {
    SemanticSafeApply();
    Deep2Engine e;
    RunWitness w{};
    if (!OpenSession(e, "tinyllama", w)) {
        puts("RAWRXD_NO_OLLAMA_CONTRACT_001=FAIL");
        return 1;
    }
    e.unloadModel();
    if (w.ollamaProcessUsed != 0 || w.networkUsed != 0 || !w.modelAliasResolved) {
        puts("RAWRXD_NO_OLLAMA_CONTRACT_001=FAIL");
        return 1;
    }
    printf("OLLAMA_USED=%d\nNETWORK_USED=%d\nALIAS_RESOLVED=%d\n",
           w.ollamaProcessUsed, w.networkUsed, w.modelAliasResolved);
    puts("RAWRXD_NO_OLLAMA_CONTRACT_001=PASS");
    return 0;
}
