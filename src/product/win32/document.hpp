#pragma once
#include "../context/file_window.hpp"
#include <cstdint>
#include <string>
namespace rawr::product {

struct DocTxn {
    size_t pos = 0;
    std::string text;
};

struct Document {
    std::string path = "untitled";
    std::string text;
    size_t caret = 0;
    uint64_t gen = 1;
    uint32_t line = 1;
    uint32_t col = 1;

    void bump() { gen++; }

    void recaret() {
        line = 1;
        col = 1;
        for (size_t i = 0; i < caret && i < text.size(); ++i) {
            if (text[i] == '\n') {
                line++;
                col = 1;
            } else {
                col++;
            }
        }
    }

    bool apply(const DocTxn& t) {
        if (t.pos > text.size()) return false;
        text.insert(t.pos, t.text);
        caret = t.pos + t.text.size();
        bump();
        recaret();
        return true;
    }

    void typeChar(char c) {
        DocTxn t{caret, std::string(1, c)};
        apply(t);
    }

    void setCaret(size_t p) {
        size_t n = p > text.size() ? text.size() : p;
        if (n != caret) bump();
        caret = n;
        recaret();
    }

    EditorSnap snap() const {
        EditorSnap e;
        e.path = path;
        e.language = "cpp";
        e.prefix = text.substr(0, caret);
        e.suffix = text.substr(caret);
        e.line = line;
        e.col = col;
        return e;
    }
};

} // namespace rawr::product
