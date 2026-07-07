#include "tokenizer_selector.h"
#include <iostream>

TokenizerSelector::TokenizerSelector(void* parent)
    : m_parent(parent)
{
}

void TokenizerSelector::initialize() {
    std::cout << "TokenizerSelector initialized" << std::endl;
}

std::string TokenizerSelector::getSelectedTokenizer() const {
    return "bpe";
}
