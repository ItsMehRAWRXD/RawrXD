// =============================================================================
// rag_rule_test.cpp — A3 certification: BM25 retrieval finds planted terms.
// =============================================================================
#include <cstdio>
#include <string>

#include "rag/codebase_index.h"

int main(int argc, char** argv) {
    try {
        const std::string dir = argc > 1 ? argv[1] : "tests/fixtures";
        rawrxd::rag::CodebaseIndex index;
        index.IndexPath(dir);
        int failures = 0;
        if (index.ChunkCount() == 0) {
            std::printf("[FAIL] index empty\n");
            ++failures;
        }
        struct Case { const char* query; const char* expect; };
        const Case cases[] = {
            {"vulnerable strcpy", "sast_sample"},
            {"placeholder api_key", "secrets_sample"},
            {"lodash advisory", "package"},
        };
        for (const auto& c : cases) {
            const auto hits = index.Query(c.query, 3);
            bool found = false;
            for (const auto& h : hits) {
                if (h.file.find(c.expect) != std::string::npos) found = true;
            }
            if (!found) {
                std::printf("[FAIL] query '%s' missed %s\n", c.query, c.expect);
                ++failures;
            }
        }
        std::printf("rag_rule_test: %zu chunks, %zu terms, failures=%d\n",
                    index.ChunkCount(), index.TermCount(), failures);
        std::printf("RAG_RULE_TEST %s\n", failures == 0 ? "PASS" : "FAIL");
        return failures == 0 ? 0 : 1;
    } catch (const std::exception& e) {
        std::printf("[FAIL] exception: %s\n", e.what());
        return 1;
    }
}