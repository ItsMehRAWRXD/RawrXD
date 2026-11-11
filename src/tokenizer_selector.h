#ifndef TOKENIZER_SELECTOR_H
#define TOKENIZER_SELECTOR_H

#include <string>

class TokenizerSelector {

public:
    explicit TokenizerSelector(void* parent = nullptr);
    void initialize();
    std::string getSelectedTokenizer() const;

private:
    void* m_parent;
};

#endif
