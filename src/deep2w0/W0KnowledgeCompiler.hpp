// ============================================================================
// W0KnowledgeCompiler.hpp — ingest raw → normalize → graph (+ pack metadata)
// ============================================================================
// Packs (.w0k conceptually) are compiled knowledge shards — not hardcoded
// intelligence directories. Domain folders are storage organization only.
// ============================================================================
#ifndef RAWRXD_DEEP2W0_W0_KNOWLEDGE_COMPILER_HPP
#define RAWRXD_DEEP2W0_W0_KNOWLEDGE_COMPILER_HPP

#include "deep2w0/W0GraphStore.hpp"
#include "deep2w0/W0MultiIndex.hpp"
#include "deep2w0/W0UniversalIR.hpp"

#include <cctype>
#include <cstdio>
#include <string>
#include <vector>

namespace RawrXD {
namespace W0 {

struct PackMeta {
    std::string name;       // e.g. "project-fixture", "core"
    std::string magic = "W0K1";
    uint32_t version = 1;
    uint64_t weights = 0;
    uint64_t floatOps = 0;
    std::string rootHash;   // content fingerprint (simple FNV for now)
};

class KnowledgePackManager {
public:
    void registerPack(PackMeta m) { m_packs.push_back(std::move(m)); }
    const std::vector<PackMeta>& packs() const { return m_packs; }

    /// Hierarchical retrieval: domain hints → pack names (deterministic).
    std::vector<std::string> selectPacks(const QueryIR& q) const {
        std::vector<std::string> out;
        out.push_back("core");
        const std::string raw = q.raw;
        auto has = [&](const char* s) { return raw.find(s) != std::string::npos; };
        if (has("CMake") || has("cmake")) out.push_back("cmake");
        if (has(".cpp") || has("C++") || has("masm") || has("return")) out.push_back("cpp");
        out.push_back("project");
        return out;
    }

private:
    std::vector<PackMeta> m_packs;
};

class KnowledgeCompiler {
public:
    /// Ingest a single source file into graph (normalize symbols/facts).
    static void ingestSourceFile(GraphStore& g,
                                 const std::string& path,
                                 const std::string& text,
                                 KnowledgeScope scope = KnowledgeScope::Project) {
        KnowledgeNode file;
        file.kind = NodeKind::File;
        file.name = path;
        file.content = text.substr(0, 4096);
        file.provenance = {"source:" + path, 0, VerificationLevel::SourceCode};
        const uint64_t fileId = g.addNode(std::move(file), scope);

        // Naive function scrape: lines containing "(" and ")" with prior token
        scrapeFunctions(g, fileId, path, text, scope);
        scrapeLiterals(g, fileId, path, text, scope);
        scrapeStaticAsserts(g, fileId, path, text, scope);
    }

    /// Seed core ontology primitives (not domain dump).
    static void seedCoreOntology(GraphStore& g) {
        auto put = [&](const char* name, NodeKind k, const char* content) {
            KnowledgeNode n;
            n.kind = k;
            n.name = name;
            n.content = content;
            n.provenance = {"core", 0, VerificationLevel::Documentation};
            g.addNode(std::move(n), KnowledgeScope::Global);
        };
        put("ENTITY", NodeKind::Concept, "universal primitive");
        put("PROPERTY", NodeKind::Concept, "universal primitive");
        put("RELATION", NodeKind::Concept, "universal primitive");
        put("RULE", NodeKind::Concept, "universal primitive");
        put("CONSTRAINT", NodeKind::Concept, "universal primitive");
        put("EVIDENCE", NodeKind::Concept, "universal primitive");
        put("UNRESOLVED_IDENTIFIER", NodeKind::Error,
            "diagnostic class: missing declaration/include/scope");
        put("WRONG_LITERAL", NodeKind::Error,
            "diagnostic class: incorrect constant / sizeof mismatch");
    }

    static PackMeta compilePackMeta(const std::string& name, const GraphStore& g) {
        PackMeta m;
        m.name = name;
        m.weights = 0;
        m.floatOps = 0;
        uint64_t h = 14695981039346656037ull;
        for (const auto& kv : g.nodes()) {
            for (unsigned char c : kv.second.name) {
                h ^= c;
                h *= 1099511628211ull;
            }
        }
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%016llx", static_cast<unsigned long long>(h));
        m.rootHash = buf;
        return m;
    }

private:
    static void scrapeFunctions(GraphStore& g, uint64_t fileId, const std::string& path,
                                const std::string& text, KnowledgeScope scope) {
        // Extremely small C-like scraper for W0-001 fixtures.
        size_t pos = 0;
        while (pos < text.size()) {
            size_t lineEnd = text.find('\n', pos);
            if (lineEnd == std::string::npos) lineEnd = text.size();
            std::string line = text.substr(pos, lineEnd - pos);
            pos = lineEnd + 1;
            // match: int foo( or int foo (
            const auto lp = line.find('(');
            if (lp == std::string::npos) continue;
            if (line.find('{') == std::string::npos && line.find(')') == std::string::npos)
                continue;
            // take token before '('
            size_t i = lp;
            while (i > 0 && (std::isalnum(static_cast<unsigned char>(line[i - 1]))
                             || line[i - 1] == '_'))
                --i;
            std::string name = line.substr(i, lp - i);
            if (name.empty() || name == "if" || name == "for" || name == "while") continue;
            KnowledgeNode fn;
            fn.kind = NodeKind::Function;
            fn.name = name;
            fn.content = line;
            fn.provenance = {"source:" + path, 0, VerificationLevel::SourceCode};
            uint64_t id = g.addNode(std::move(fn), scope);
            g.addEdge({fileId, id, Relation::Contains, path});
            g.addEdge({id, fileId, Relation::DefinedIn, path});
        }
    }

    static void scrapeLiterals(GraphStore& g, uint64_t fileId, const std::string& path,
                               const std::string& text, KnowledgeScope scope) {
        // return <number>;
        size_t pos = 0;
        while ((pos = text.find("return ", pos)) != std::string::npos) {
            pos += 7;
            size_t end = pos;
            while (end < text.size() && (std::isdigit(static_cast<unsigned char>(text[end]))
                                         || text[end] == '-'))
                ++end;
            if (end == pos) continue;
            KnowledgeNode lit;
            lit.kind = NodeKind::Fact;
            lit.kclass = KnowledgeClass::Declarative;
            lit.name = "return_literal@" + path;
            lit.content = text.substr(pos, end - pos);
            lit.provenance = {"source:" + path, 0, VerificationLevel::SourceCode};
            uint64_t id = g.addNode(std::move(lit), scope);
            g.addEdge({fileId, id, Relation::Contains, path});
        }
    }

    static void scrapeStaticAsserts(GraphStore& g, uint64_t /*fileId*/, const std::string& path,
                                    const std::string& text, KnowledgeScope scope) {
        size_t pos = 0;
        while ((pos = text.find("static_assert", pos)) != std::string::npos) {
            size_t end = text.find(';', pos);
            if (end == std::string::npos) break;
            KnowledgeNode c;
            c.kind = NodeKind::Constraint;
            c.kclass = KnowledgeClass::Declarative;
            c.name = "static_assert@" + path;
            c.content = text.substr(pos, end - pos);
            c.provenance = {"source:" + path, 0, VerificationLevel::Certified};
            g.addNode(std::move(c), scope);
            pos = end + 1;
        }
    }
};

} // namespace W0
} // namespace RawrXD

#endif
