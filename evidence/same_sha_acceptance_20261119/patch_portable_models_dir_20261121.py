#!/usr/bin/env python3
"""Sprint 3: portable model-directory resolution in populateModelSelector.

Replaces the hardcoded R"(F:\\rawrxd\\models)" scan with a deterministic
policy:
  1) explicit RAWRXD_MODELS_DIR (invalid -> diagnose, never substitute)
  2) exe-relative models dir (walking a few ancestors)
  3) cwd-relative models dir
  4) none -> truthful empty state

Fail-closed: locates the target `if (m_availableModels.empty()) { ... }`
block by brace matching and asserts exactly one match, else aborts.
"""
import sys

PATH = r"F:\rawrxd\src\win32app\Win32IDE.cpp"

with open(PATH, "rb") as fh:
    text = fh.read().decode("utf-8")

ANCHOR = "    if (m_availableModels.empty()) {"
if text.count(ANCHOR) != 1:
    print(f"ABORT: anchor count={text.count(ANCHOR)}")
    sys.exit(2)

start = text.index(ANCHOR)
# find the opening brace and brace-match to the block end
brace_open = text.index("{", start)
depth = 0
i = brace_open
end = None
while i < len(text):
    ch = text[i]
    if ch == "{":
        depth += 1
    elif ch == "}":
        depth -= 1
        if depth == 0:
            end = i + 1
            break
    i += 1
if end is None:
    print("ABORT: unbalanced braces")
    sys.exit(2)

# detect newline style used at the block start
nl = "\r\r\n" if text[start:start+200].find("\r\r\n") >= 0 else "\r\n"

NEW = nl.join([
    "    if (m_availableModels.empty()) {",
    "        // Sprint 3: portable model-directory resolution.",
    "        // Priority: (1) explicit RAWRXD_MODELS_DIR, (2) exe-relative models",
    "        // dir (walking a few ancestors), (3) cwd-relative models dir. An",
    "        // explicitly configured but invalid directory is diagnosed rather",
    "        // than silently scanning an unrelated path. No local models is a",
    "        // truthful empty state.",
    "        std::string modelsDir;",
    "        bool explicitModelsDirInvalid = false;",
    "        const std::string configuredDir = environmentValue(\"RAWRXD_MODELS_DIR\");",
    "        std::error_code dirEc;",
    "        if (!configuredDir.empty()) {",
    "            if (std::filesystem::is_directory(std::filesystem::path(configuredDir), dirEc)) {",
    "                modelsDir = configuredDir;",
    "            } else {",
    "                explicitModelsDirInvalid = true;",
    "                std::fprintf(stderr,",
    "                    \"[MODEL_DISCOVERY_PATH] RAWRXD_MODELS_DIR is not a directory: %s\\n\",",
    "                    configuredDir.c_str());",
    "                std::fflush(stderr);",
    "            }",
    "        }",
    "        if (modelsDir.empty() && !explicitModelsDirInvalid) {",
    "            std::array<char, MAX_PATH> exePathBuf{};",
    "            const DWORD exeLen = GetModuleFileNameA(",
    "                nullptr, exePathBuf.data(), static_cast<DWORD>(exePathBuf.size()));",
    "            if (exeLen && exeLen < exePathBuf.size()) {",
    "                std::filesystem::path probeDir = std::filesystem::path(",
    "                    std::string(exePathBuf.data(), exeLen)).parent_path();",
    "                for (int depth = 0; depth < 4 && modelsDir.empty(); ++depth) {",
    "                    const std::filesystem::path candidate = probeDir / \"models\";",
    "                    if (std::filesystem::is_directory(candidate, dirEc)) {",
    "                        modelsDir = candidate.string();",
    "                        break;",
    "                    }",
    "                    if (!probeDir.has_parent_path() || !probeDir.has_filename()) break;",
    "                    probeDir = probeDir.parent_path();",
    "                }",
    "            }",
    "        }",
    "        if (modelsDir.empty() && !explicitModelsDirInvalid) {",
    "            std::error_code cwdEc;",
    "            const std::filesystem::path candidate =",
    "                std::filesystem::current_path(cwdEc) / \"models\";",
    "            if (!cwdEc && std::filesystem::is_directory(candidate, cwdEc)) {",
    "                modelsDir = candidate.string();",
    "            }",
    "        }",
    "        if (!modelsDir.empty()) {",
    "            std::fprintf(stderr, \"[MODEL_DISCOVERY_PATH] modelsDir=%s\\n\", modelsDir.c_str());",
    "            std::fflush(stderr);",
    "            std::error_code scanEc;",
    "            for (const auto& de : std::filesystem::directory_iterator(modelsDir, scanEc)) {",
    "                if (scanEc || !de.is_regular_file()) continue;",
    "                const std::string full = de.path().string();",
    "                if (full.size() < 5) continue;",
    "                std::string low = full;",
    "                for (char& c : low) c = (char)tolower((unsigned char)c);",
    "                if (low.compare(low.size() - 5, 5, \".gguf\") != 0) continue;",
    "                m_availableModels.push_back({ChatModelEntry::Source::LocalFile,",
    "                                             de.path().filename().string(), full});",
    "                std::fprintf(stderr, \"[MODEL_DISCOVERY_ADD] %s\\n\", full.c_str());",
    "                std::fflush(stderr);",
    "            }",
    "        }",
    "    }",
])

old_block = text[start:end]
new_text = text[:start] + NEW + text[end:]
with open(PATH, "wb") as fh:
    fh.write(new_text.encode("utf-8"))
print(f"replaced block ({len(old_block)} -> {len(NEW)} chars), nl={nl!r}")