#include "dataset_loader.hpp"
#include "../../core/logger.hpp"
#include <fstream>
#include <sstream>
#include <json/json.hpp>
#include <algorithm>
#include <random>

namespace rawrxd::training {

using json = nlohmann::json;

// ============================================================================
// JSON Dataset
// ============================================================================

JSONDataset::JSONDataset(const DatasetConfig& config) : config_(config) {}

bool JSONDataset::load(const std::string& path) {
    RAWRXD_LOG_INFO("JSONDataset", "Loading dataset from: {}", path);

    if (path.ends_with(".jsonl")) {
        return loadFromJSONL(path);
    }

    // Load JSON array
    std::ifstream file(path);
    if (!file.is_open()) {
        RAWRXD_LOG_ERROR("JSONDataset", "Failed to open file: {}", path);
        return false;
    }

    try {
        json j;
        file >> j;

        if (j.is_array()) {
            for (const auto& item : j) {
                DataSample sample;
                if (item.contains(config_.text_column)) {
                    sample.text = item[config_.text_column].get<std::string>();
                }
                if (item.contains(config_.input_column)) {
                    sample.input = item[config_.input_column].get<std::string>();
                }
                if (item.contains(config_.output_column)) {
                    sample.output = item[config_.output_column].get<std::string>();
                }
                if (item.contains(config_.instruction_column)) {
                    sample.instruction = item[config_.instruction_column].get<std::string>();
                }

                tokenize(sample);
                samples_.push_back(std::move(sample));
            }
        }

        RAWRXD_LOG_INFO("JSONDataset", "Loaded {} samples", samples_.size());
        return true;

    } catch (const std::exception& e) {
        RAWRXD_LOG_ERROR("JSONDataset", "Failed to parse JSON: {}", e.what());
        return false;
    }
}

bool JSONDataset::loadFromJSONL(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        RAWRXD_LOG_ERROR("JSONDataset", "Failed to open file: {}", path);
        return false;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty()) continue;

        try {
            json j = json::parse(line);
            DataSample sample;

            if (j.contains(config_.text_column)) {
                sample.text = j[config_.text_column].get<std::string>();
            }
            if (j.contains(config_.input_column)) {
                sample.input = j[config_.input_column].get<std::string>();
            }
            if (j.contains(config_.output_column)) {
                sample.output = j[config_.output_column].get<std::string>();
            }
            if (j.contains(config_.instruction_column)) {
                sample.instruction = j[config_.instruction_column].get<std::string>();
            }

            tokenize(sample);
            samples_.push_back(std::move(sample));

        } catch (const std::exception& e) {
            RAWRXD_LOG_WARN("JSONDataset", "Failed to parse line: {}", e.what());
        }
    }

    RAWRXD_LOG_INFO("JSONDataset", "Loaded {} samples from JSONL", samples_.size());
    return true;
}

void JSONDataset::tokenize(DataSample& sample) {
    // Simple tokenization (placeholder for actual tokenizer)
    // In production, use the model's tokenizer
    sample.num_tokens = sample.text.length() / 4;  // Rough estimate

    if (config_.truncation && sample.num_tokens > config_.max_length) {
        sample.num_tokens = config_.max_length;
    }
}

DataSample JSONDataset::get(size_t index) {
    if (index >= samples_.size()) {
        throw std::out_of_range("Index out of range");
    }
    return samples_[index];
}

std::unique_ptr<DataLoader> JSONDataset::createDataLoader(size_t batch_size, bool shuffle) {
    return std::make_unique<DataLoader>(this, batch_size, shuffle);
}

std::pair<std::unique_ptr<Dataset>, std::unique_ptr<Dataset>> JSONDataset::split(float ratio) {
    size_t split_idx = static_cast<size_t>(samples_.size() * ratio);

    auto train_dataset = std::make_unique<JSONDataset>(config_);
    auto val_dataset = std::make_unique<JSONDataset>(config_);

    train_dataset->samples_.insert(
        train_dataset->samples_.end(),
        samples_.begin(),
        samples_.begin() + split_idx
    );

    val_dataset->samples_.insert(
        val_dataset->samples_.end(),
        samples_.begin() + split_idx,
        samples_.end()
    );

    return {std::move(train_dataset), std::move(val_dataset)};
}

// ============================================================================
// Text Dataset
// ============================================================================

TextDataset::TextDataset(const DatasetConfig& config) : config_(config) {}

bool TextDataset::load(const std::string& path) {
    RAWRXD_LOG_INFO("TextDataset", "Loading text from: {}", path);

    std::ifstream file(path);
    if (!file.is_open()) {
        RAWRXD_LOG_ERROR("TextDataset", "Failed to open file: {}", path);
        return false;
    }

    std::string content((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());

    chunkText(content);

    RAWRXD_LOG_INFO("TextDataset", "Created {} chunks", chunks_.size());
    return true;
}

void TextDataset::chunkText(const std::string& text) {
    size_t pos = 0;
    while (pos < text.size()) {
        size_t end = pos + chunk_size_;
        if (end > text.size()) {
            end = text.size();
        }
        chunks_.push_back(text.substr(pos, end - pos));
        pos = end;
    }
}

DataSample TextDataset::get(size_t index) {
    if (index >= chunks_.size()) {
        throw std::out_of_range("Index out of range");
    }
    DataSample sample;
    sample.text = chunks_[index];
    sample.num_tokens = sample.text.length() / 4;
    return sample;
}

std::unique_ptr<DataLoader> TextDataset::createDataLoader(size_t batch_size, bool shuffle) {
    return std::make_unique<DataLoader>(this, batch_size, shuffle);
}

std::pair<std::unique_ptr<Dataset>, std::unique_ptr<Dataset>> TextDataset::split(float ratio) {
    size_t split_idx = static_cast<size_t>(chunks_.size() * ratio);

    auto train_dataset = std::make_unique<TextDataset>(config_);
    auto val_dataset = std::make_unique<TextDataset>(config_);

    train_dataset->chunks_.insert(
        train_dataset->chunks_.end(),
        chunks_.begin(),
        chunks_.begin() + split_idx
    );

    val_dataset->chunks_.insert(
        val_dataset->chunks_.end(),
        chunks_.begin() + split_idx,
        chunks_.end()
    );

    return {std::move(train_dataset), std::move(val_dataset)};
}

// ============================================================================
// Data Loader
// ============================================================================

DataLoader::DataLoader(Dataset* dataset, size_t batch_size, bool shuffle)
    : dataset_(dataset), batch_size_(batch_size), shuffle_(shuffle) {
    reset();
}

void DataLoader::reset() {
    current_index_ = 0;
    indices_.clear();
    for (size_t i = 0; i < dataset_->size(); ++i) {
        indices_.push_back(i);
    }
    if (shuffle_) {
        shuffleIndices();
    }
}

void DataLoader::shuffleIndices() {
    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(indices_.begin(), indices_.end(), g);
}

bool DataLoader::hasNext() const {
    return current_index_ < indices_.size();
}

Batch DataLoader::next() {
    std::vector<DataSample> samples;
    size_t end_idx = std::min(current_index_ + batch_size_, indices_.size());

    for (size_t i = current_index_; i < end_idx; ++i) {
        samples.push_back(dataset_->get(indices_[i]));
    }

    current_index_ = end_idx;
    return collate(samples);
}

Batch DataLoader::collate(const std::vector<DataSample>& samples) {
    Batch batch;
    batch.size = samples.size();

    // Find max length
    size_t max_len = 0;
    for (const auto& s : samples) {
        max_len = std::max(max_len, s.num_tokens);
    }
    batch.max_length = max_len;

    // Collate samples
    for (const auto& s : samples) {
        batch.input_ids.push_back(s.token_ids);
        batch.attention_masks.push_back(s.attention_mask);
        batch.num_tokens += s.num_tokens;
    }

    return batch;
}

size_t DataLoader::getNumBatches() const {
    return (dataset_->size() + batch_size_ - 1) / batch_size_;
}

// ============================================================================
// Factory
// ============================================================================

std::unique_ptr<Dataset> createDataset(const DatasetConfig& config) {
    if (config.format == "json" || config.format == "jsonl") {
        return std::make_unique<JSONDataset>(config);
    } else if (config.format == "txt" || config.format == "text") {
        return std::make_unique<TextDataset>(config);
    } else {
        RAWRXD_LOG_ERROR("Dataset", "Unsupported format: {}", config.format);
        return nullptr;
    }
}

} // namespace rawrxd::training
