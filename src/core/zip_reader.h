// ============================================================================
//  A self-contained ZIP reader.
//
//  The extension runtime extracts VSIX packages, and a VSIX is a ZIP. Doing
//  that by shelling out to PowerShell made the runtime depend on an external
//  tool that is not present on every machine, that fails on packages it
//  considers malformed, and that cannot be relied on in a headless or
//  service context.
//
//  This reader handles the two storage methods that occur in practice:
//
//      0  stored
//      8  deflate
//
//  The DEFLATE decoder is implemented here, so the runtime has no external
//  dependency of any kind.
// ============================================================================

#ifndef RAWRXD_ZIP_READER_H
#define RAWRXD_ZIP_READER_H

#include <string>
#include <vector>

namespace RawrXD {

struct ZipEntry {
    std::string name;
    uint32_t    compressedSize = 0;
    uint32_t    uncompressedSize = 0;
    uint16_t    method = 0;
    uint32_t    crc32 = 0;
    uint32_t    localHeaderOffset = 0;
};

// A ZIP archive read from memory.
class ZipReader {
public:
    // Parses the central directory. Returns false when the buffer is not a
    // readable archive.
    bool open(const uint8_t* data, size_t size);

    const std::vector<ZipEntry>& entries() const { return entries_; }

    // Extracts one entry. Returns false when the entry cannot be read or
    // the decompressed size does not match the archive's record.
    bool extract(const std::string& name, std::string& out) const;

    // Extracts every entry below a directory prefix, writing the files
    // under `destination` with their relative paths preserved.
    // Returns the number of files written, or -1 on failure.
    int extractAll(const std::string& destination,
                   const std::string& prefixFilter = "") const;

private:
    const uint8_t* data_ = nullptr;
    size_t size_ = 0;
    std::vector<ZipEntry> entries_;
};

// Raw DEFLATE decompression. Returns false on malformed input.
bool inflateRaw(const uint8_t* data, size_t size, std::string& out, size_t expectedSize);

} // namespace RawrXD

#endif // RAWRXD_ZIP_READER_H
