#include "LocalStreamReverseParser.hpp"

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using rawrxd::streamer::ArtifactKind;
using rawrxd::streamer::ReverseParseError;
using rawrxd::streamer::ReverseParseReport;
using rawrxd::streamer::formatReverseParseReport;
using rawrxd::streamer::parseLocalArtifact;

namespace {

int g_failed = 0;

void expect(bool cond, const char* name)
{
    if (!cond) {
        std::cerr << "FAIL: " << name << "\n";
        ++g_failed;
    } else {
        std::cout << "PASS: " << name << "\n";
    }
}

void writeU32(std::ostream& out, uint32_t value)
{
    out.write(reinterpret_cast<const char*>(&value), sizeof(value));
}

void writeU64(std::ostream& out, uint64_t value)
{
    out.write(reinterpret_cast<const char*>(&value), sizeof(value));
}

void writeGgufString(std::ostream& out, const std::string& text)
{
    writeU64(out, static_cast<uint64_t>(text.size()));
    out.write(text.data(), static_cast<std::streamsize>(text.size()));
}

void writeKvString(std::ostream& out, const std::string& key, const std::string& value)
{
    writeGgufString(out, key);
    writeU32(out, 8);  // GGUF string
    writeGgufString(out, value);
}

void writeKvU32(std::ostream& out, const std::string& key, uint32_t value)
{
    writeGgufString(out, key);
    writeU32(out, 4);  // GGUF uint32
    writeU32(out, value);
}

void writeTensorInfo(std::ostream& out, const std::string& name, uint64_t rows, uint64_t cols)
{
    writeGgufString(out, name);
    writeU32(out, 2);
    writeU64(out, rows);
    writeU64(out, cols);
    writeU32(out, 0);  // F32
    writeU64(out, 0);
}

void writeMinimalGguf(std::ostream& out)
{
    writeU32(out, 0x46554747u);
    writeU32(out, 3);
    writeU64(out, 3);
    writeU64(out, 5);
    writeKvString(out, "general.architecture", "llama");
    writeKvString(out, "general.name", "testd");
    writeKvString(out, "tokenizer.ggml.model", "gpt2");
    writeKvU32(out, "llama.vocab_size", 32);
    writeKvU32(out, "llama.block_count", 1);
    writeTensorInfo(out, "token_embd.weight", 32, 8);
    writeTensorInfo(out, "blk.0.attn_q.weight", 8, 8);
    writeTensorInfo(out, "output.weight", 32, 8);
}

fs::path makeTempDir()
{
    const fs::path dir = fs::temp_directory_path() / "rawrxd_reverse_parser_test";
    fs::remove_all(dir);
    fs::create_directories(dir);
    return dir;
}

}  // namespace

int main()
{
    const fs::path dir = makeTempDir();
    const fs::path ggufPath = dir / "tiny.gguf";
    const fs::path blobPath = dir / "sha256-embedded-blob";
    const fs::path truncatedPath = dir / "truncated.gguf";
    const fs::path textPath = dir / "notes.txt";
    const fs::path extDir = dir / "demo-ext";

    {
        std::ofstream out(ggufPath, std::ios::binary);
        writeMinimalGguf(out);
    }
    {
        std::ofstream out(blobPath, std::ios::binary);
        const std::vector<char> prefix(256, static_cast<char>(0xAB));
        out.write(prefix.data(), static_cast<std::streamsize>(prefix.size()));
        writeMinimalGguf(out);
    }
    {
        std::ofstream out(truncatedPath, std::ios::binary);
        writeU32(out, 0x46554747u);
        writeU32(out, 3);
    }
    {
        std::ofstream out(textPath);
        out << "not a model\n";
    }
    fs::create_directories(extDir);

    ReverseParseReport empty;
    expect(!parseLocalArtifact(ArtifactKind::Model, "", empty), "empty path fails");
    expect(empty.error == ReverseParseError::EmptyPath, "empty path error");
    expect(!empty.missing.empty(), "empty path lists missing");

    ReverseParseReport missingFile;
    expect(!parseLocalArtifact(ArtifactKind::Model, (dir / "no-such.gguf").string(), missingFile),
           "missing file fails");
    expect(missingFile.error == ReverseParseError::NotFound, "missing file error");
    expect(!missingFile.missing.empty(), "missing file lists gap");

    ReverseParseReport gguf;
    expect(parseLocalArtifact(ArtifactKind::Model, ggufPath.string(), gguf), "pure GGUF parses");
    expect(gguf.payloadParsed, "pure GGUF payload parsed");
    expect(gguf.magicAtZero, "pure GGUF magic at 0");
    expect(gguf.ggufVersion == 3, "pure GGUF version 3");
    expect(gguf.tensorCount == 3, "pure GGUF tensor count");
    expect(gguf.architecture == "llama", "pure GGUF architecture");
    expect(gguf.modelName == "testd", "pure GGUF name");
    expect(gguf.tokenizerModel == "gpt2", "pure GGUF tokenizer");
    expect(gguf.vocabSize == 32, "pure GGUF vocab");
    expect(gguf.layerCount == 1, "pure GGUF layers");
    expect(gguf.hasEmbedTensor && gguf.hasOutputTensor && gguf.hasFirstBlock, "pure GGUF tensors classified");
    expect(gguf.missing.empty(), "pure GGUF has no missing items");

    ReverseParseReport blob;
    expect(parseLocalArtifact(ArtifactKind::Model, blobPath.string(), blob), "embedded blob parses");
    expect(blob.ggufOffset == 256, "embedded blob offset 256");
    expect(!blob.magicAtZero, "embedded blob magic not at 0");
    expect(blob.payloadParsed && blob.architecture == "llama", "embedded blob metadata");

    ReverseParseReport trunc;
    expect(!parseLocalArtifact(ArtifactKind::Model, truncatedPath.string(), trunc), "truncated GGUF fails");
    expect(trunc.error == ReverseParseError::Truncated, "truncated GGUF error");
    expect(!trunc.missing.empty(), "truncated GGUF lists missing");

    ReverseParseReport notes;
    expect(parseLocalArtifact(ArtifactKind::File, textPath.string(), notes), "plain file kind ok");
    expect(notes.error == ReverseParseError::Ok, "plain file error ok");

    ReverseParseReport junkModel;
    expect(!parseLocalArtifact(ArtifactKind::Model, textPath.string(), junkModel), "plain file as model fails");
    expect(junkModel.error == ReverseParseError::InvalidFormat, "plain file as model invalid");

    ReverseParseReport ext;
    expect(!parseLocalArtifact(ArtifactKind::Extension, extDir.string(), ext), "extension without sidecars fails");
    bool sawManifest = false;
    bool sawEntry = false;
    for (const auto& item : ext.missing) {
        if (item.id == "extension.manifest")
            sawManifest = true;
        if (item.id == "extension.entry")
            sawEntry = true;
    }
    expect(sawManifest && sawEntry, "extension lists package.json and entry");

    {
        std::ofstream(extDir / "package.json") << "{\"name\":\"demo\"}\n";
        std::ofstream(extDir / "extension.js") << "exports.activate = function() {};\n";
    }
    ReverseParseReport extOk;
    expect(parseLocalArtifact(ArtifactKind::Extension, extDir.string(), extOk), "extension with sidecars ok");
    expect(extOk.missing.empty(), "complete extension has no missing");

    const auto convenience = parseLocalArtifact("model", ggufPath.string());
    expect(convenience.kind == ArtifactKind::Model && convenience.payloadParsed, "string-kind overload");

    const std::string formatted = formatReverseParseReport(gguf);
    expect(formatted.find("[ReverseParser]") != std::string::npos, "formatted report header");
    expect(formatted.find("Missing: (none)") != std::string::npos, "formatted report missing none");
    expect(formatReverseParseReport(missingFile).find("not on disk") != std::string::npos,
           "formatted report lists missing file");

    fs::remove_all(dir);

    if (g_failed != 0) {
        std::cerr << g_failed << " check(s) failed\n";
        return 1;
    }
    std::cout << "All reverse parser checks passed\n";
    return 0;
}
