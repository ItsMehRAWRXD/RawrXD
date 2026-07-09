// Check if model has merges
#include "src/model/model_context.h"
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <model.gguf>\n";
        return 1;
    }
    
    auto model = rawrxd::model::ModelContextFactory::FromGGUF(argv[1]);
    if (!model) {
        std::cerr << "Failed to load model\n";
        return 1;
    }
    
    std::cout << "Vocab size: " << model->GetVocabulary().size() << "\n";
    std::cout << "Merges size: " << model->GetMerges().size() << "\n";
    
    if (!model->GetMerges().empty()) {
        std::cout << "First 5 merges:\n";
        for (size_t i = 0; i < std::min(model->GetMerges().size(), size_t(5)); ++i) {
            std::cout << "  " << model->GetMerges()[i] << "\n";
        }
    }
    
    return 0;
}
