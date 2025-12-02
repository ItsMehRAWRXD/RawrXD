#pragma once
#include <vector>
#include <string>
#include <string_view>
#include <cstddef>

// Basic gap buffer based text storage.
// For large files a future Rope implementation will replace internals transparently.
class BufferModel {
public:
    BufferModel();
    explicit BufferModel(std::string_view initial);

    size_t size() const; // logical size excluding gap
    bool empty() const { return size() == 0; }

    void insert(size_t pos, std::string_view text); // inserts before pos
    void erase(size_t pos, size_t len);             // erase [pos, pos+len)

    std::string getText(size_t pos, size_t len) const; // substring
    std::string getLine(size_t line) const;            // line content without \n
    size_t lineCount() const { return m_lineOffsets.size(); }

    // Full snapshot (expensive for very large content)
    std::string snapshot() const;

    // Replaces buffer with provided content
    void set(std::string_view text);

private:
    std::vector<char> m_data; // data with a gap between m_gapStart..m_gapEnd (exclusive)
    size_t m_gapStart{};
    size_t m_gapEnd{};
    std::vector<size_t> m_lineOffsets; // starting offset of each line, last entry optional for EOF

    void ensureGapCapacity(size_t needed);
    void moveGap(size_t pos);
    void rebuildLineIndex();
    void updateLineIndexOnInsert(size_t pos, std::string_view text);
    void updateLineIndexOnErase(size_t pos, size_t len);
    size_t logicalToPhysical(size_t logical) const; // map logical index to physical index inside m_data
};
