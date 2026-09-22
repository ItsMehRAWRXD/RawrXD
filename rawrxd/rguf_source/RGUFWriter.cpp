#include "RGUFWriter.hpp"
#include "RGUFPlatform.hpp"
#include <fstream>
#include <iostream>

namespace rguf {

bool Writer::pack(const std::string& ggufPath,
                  const std::string& rgufPath,
                  const WriterConfig& cfg,
                  std::string& err) {
    std::ifstream in(ggufPath, std::ios::binary);
    if (!in) { err = "cannot open input: " + ggufPath; return false; }

    std::ofstream out(rgufPath, std::ios::binary);
    if (!out) { err = "cannot open output: " + rgufPath; return false; }

    // Minimal RGUF header — no full GGUF tensor parser (safety boundary)
    Header h{};
    h.block_count = 0;
    h.blocks_off = sizeof(Header);
    out.write(reinterpret_cast<const char*>(&h), sizeof(h));
    if (!out) { err = "write header failed"; return false; }

    // Copy raw payload as single block (placeholder until full tensor-dir parser integrated)
    std::vector<uint8_t> payload((std::istreambuf_iterator<char>(in)),
                                  std::istreambuf_iterator<char>());
    if (!payload.empty()) {
        Block b{};
        b.tensor = 0;
        b.index = 0;
        b.file_off = out.tellp();
        b.plain = payload.size();
        b.stored = payload.size();
        b.crc = crc32(payload.data(), payload.size());
        if (cfg.encrypt) {
            uint8_t nonce[12];
            random_bytes(nonce, 12);
            std::memcpy(b.nonce, nonce, 12);
            std::vector<uint8_t> cipher;
            if (!aes256gcm_encrypt(cfg.key, nonce, payload.data(), payload.size(),
                                   nullptr, 0, cipher, b.tag, err)) {
                return false;
            }
            b.stored = cipher.size();
            out.write(reinterpret_cast<const char*>(cipher.data()), static_cast<std::streamsize>(cipher.size()));
        } else {
            out.write(reinterpret_cast<const char*>(payload.data()), static_cast<std::streamsize>(payload.size()));
        }
        out.seekp(0, std::ios::beg);
        h.block_count = 1;
        h.blocks_off = sizeof(Header);
        out.write(reinterpret_cast<const char*>(&h), sizeof(h));
    }
    return true;
}

} // namespace rguf
