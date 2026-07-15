#pragma once

#include "../training_config.hpp"
#include <vector>
#include <memory>
#include <functional>
#include <fstream>

namespace rawrxd::training {

// Data sample
struct DataSample {
    std::string text;
    std::string input;
    std::string output;
    std::string instruction;
    std::vector<int> token_ids;
    std::vector<float> attention_mask;
    size_t num_tokens = 0;

    void clear() {
        text.clear();
        input.clear();
        output.clear();
        instruction.clear();
        token_ids.clear();
        attention_mask.clear();
        num_tokens = 0;
    }
};

// Dataset interface
class Dataset {
public:
    virtual ~Dataset() = default;

    // Size
    virtual size_t size() const = 0;
    virtual bool empty() const { return size() == 0; }

    // Access
    virtual DataSample get(size_t index) = 0;
    virtual DataSample operator[](size_t index) { return get(index); }

    // Create data loader
    virtual std::unique_ptr<class DataLoader> createDataLoader(
        size_t batch_size, bool shuffle = true) = 0;

    // Split dataset
    virtual std::pair<std::unique_ptr<Dataset>, std::unique_ptr<Dataset>> split(float ratio) = 0;
};

// JSON/JSONL dataset
class JSONDataset : public Dataset {
public:
    JSONDataset(const DatasetConfig& config);

    bool load(const std::string& path);
    bool loadFromJSONL(const std::string& path);

    size_t size() const override { return samples_.size(); }
    DataSample get(size_t index) override;
    std::unique_ptr<DataLoader> createDataLoader(size_t batch_size, bool shuffle = true) override;
    std::pair<std::unique_ptr<Dataset>, std::unique_ptr<Dataset>> split(float ratio) override;

private:
    DatasetConfig config_;
    std::vector<DataSample> samples_;

    void tokenize(DataSample& sample);
};

// Text file dataset
class TextDataset : public Dataset {
public:
    explicit TextDataset(const DatasetConfig& config);

    bool load(const std::string& path);

    size_t size() const override { return chunks_.size(); }
    DataSample get(size_t index) override;
    std::unique_ptr<DataLoader> createDataLoader(size_t batch_size, bool shuffle = true) override;
    std::pair<std::unique_ptr<Dataset>, std::unique_ptr<Dataset>> split(float ratio) override;

private:
    DatasetConfig config_;
    std::vector<std::string> chunks_;
    size_t chunk_size_ = 2048;

    void chunkText(const std::string& text);
};

// Parquet dataset (for large datasets)
class ParquetDataset : public Dataset {
public:
    explicit ParquetDataset(const DatasetConfig& config);

    bool load(const std::string& path);

    size_t size() const override;
    DataSample get(size_t index) override;
    std::unique_ptr<DataLoader> createDataLoader(size_t batch_size, bool shuffle = true) override;
    std::pair<std::unique_ptr<Dataset>, std::unique_ptr<Dataset>> split(float ratio) override;

private:
    DatasetConfig config_;
    std::string file_path_;
    size_t num_rows_ = 0;

    DataSample readRow(size_t row);
};

// Batch
struct Batch {
    std::vector<std::vector<int>> input_ids;
    std::vector<std::vector<float>> attention_masks;
    std::vector<std::vector<int>> labels;
    size_t size = 0;
    size_t num_tokens = 0;
    size_t max_length = 0;

    void clear() {
        input_ids.clear();
        attention_masks.clear();
        labels.clear();
        size = 0;
        num_tokens = 0;
        max_length = 0;
    }
};

// Data loader
class DataLoader {
public:
    DataLoader(Dataset* dataset, size_t batch_size, bool shuffle);

    // Iterator interface
    bool hasNext() const;
    Batch next();

    // Reset
    void reset();

    // State
    size_t getCurrentIndex() const { return current_index_; }
    size_t getNumBatches() const;

private:
    Dataset* dataset_;
    size_t batch_size_;
    bool shuffle_;
    size_t current_index_ = 0;
    std::vector<size_t> indices_;

    void shuffleIndices();
    Batch collate(const std::vector<DataSample>& samples);
};

// Dataset factory
std::unique_ptr<Dataset> createDataset(const DatasetConfig& config);

} // namespace rawrxd::training
