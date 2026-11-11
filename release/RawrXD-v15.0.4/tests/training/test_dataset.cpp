/**
 * @file test_dataset.cpp
 * @brief Unit tests for dataset loading
 */

#include <gtest/gtest.h>
#include "training/data/dataset_loader.hpp"
#include "training/data/data_collator.hpp"
#include <filesystem>
#include <fstream>

using namespace rawrxd::training;

class DatasetTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create temporary test files
        temp_dir_ = std::filesystem::temp_directory_path() / "rawrxd_test";
        std::filesystem::create_directories(temp_dir_);

        // Create test JSONL file
        jsonl_path_ = temp_dir_ / "test.jsonl";
        std::ofstream jsonl(jsonl_path_);
        jsonl << R"({"instruction": "Test 1", "output": "Output 1"})" << "\n";
        jsonl << R"({"instruction": "Test 2", "output": "Output 2"})" << "\n";
        jsonl << R"({"instruction": "Test 3", "output": "Output 3"})" << "\n";
        jsonl.close();

        // Create test text file
        text_path_ = temp_dir_ / "test.txt";
        std::ofstream text(text_path_);
        text << "This is a test document.\n";
        text << "It has multiple lines.\n";
        text << "For testing purposes.\n";
        text.close();
    }

    void TearDown() override {
        std::filesystem::remove_all(temp_dir_);
    }

    std::filesystem::path temp_dir_;
    std::filesystem::path jsonl_path_;
    std::filesystem::path text_path_;
};

TEST_F(DatasetTest, JSONLDatasetLoad) {
    DatasetConfig config;
    config.path = jsonl_path_.string();
    config.format = "jsonl";
    config.text_column = "instruction";

    auto dataset = createDataset(config);
    ASSERT_NE(dataset, nullptr);

    EXPECT_TRUE(dataset->load(jsonl_path_.string()));
    EXPECT_EQ(dataset->size(), 3);

    auto sample = dataset->get(0);
    EXPECT_EQ(sample.instruction, "Test 1");
}

TEST_F(DatasetTest, TextDatasetLoad) {
    DatasetConfig config;
    config.path = text_path_.string();
    config.format = "txt";

    auto dataset = std::make_unique<TextDataset>(config);
    EXPECT_TRUE(dataset->load(text_path_.string()));
    EXPECT_GT(dataset->size(), 0);
}

TEST_F(DatasetTest, DatasetSplit) {
    DatasetConfig config;
    config.path = jsonl_path_.string();
    config.format = "jsonl";

    auto dataset = createDataset(config);
    dataset->load(jsonl_path_.string());

    auto [train, val] = dataset->split(0.7f);

    EXPECT_EQ(train->size(), 2);  // 70% of 3 = 2
    EXPECT_EQ(val->size(), 1);     // 30% of 3 = 1
}

TEST_F(DatasetTest, DataLoaderIteration) {
    DatasetConfig config;
    config.path = jsonl_path_.string();
    config.format = "jsonl";

    auto dataset = createDataset(config);
    dataset->load(jsonl_path_.string());

    auto loader = dataset->createDataLoader(2, false);

    EXPECT_TRUE(loader->hasNext());

    int batch_count = 0;
    while (loader->hasNext()) {
        auto batch = loader->next();
        EXPECT_GT(batch.size, 0);
        batch_count++;
    }

    EXPECT_EQ(batch_count, 2);  // 3 samples / batch_size 2 = 2 batches
}

TEST_F(DatasetTest, DataCollator) {
    DatasetConfig config;
    config.max_length = 512;
    config.truncation = true;
    config.padding = true;
    config.padding_side = "right";

    DataCollator collator(config);

    std::vector<DataSample> samples(2);
    samples[0].token_ids = {1, 2, 3};
    samples[0].num_tokens = 3;
    samples[1].token_ids = {4, 5};
    samples[1].num_tokens = 2;

    auto batch = collator.collate(samples);

    EXPECT_EQ(batch.size, 2);
    EXPECT_EQ(batch.input_ids.size(), 2);
}

TEST_F(DatasetTest, InstructionCollator) {
    DatasetConfig config;
    config.max_length = 512;

    InstructionCollator collator(config);
    collator.setTemplate(
        "### Instruction:\n{}\n\n### Response:\n",
        "{}"
    );

    DataSample sample;
    sample.instruction = "Test instruction";
    sample.output = "Test output";

    std::vector<DataSample> samples = {sample};
    auto batch = collator.collate(samples);

    EXPECT_EQ(batch.size, 1);
}

TEST_F(DatasetTest, DataAugmentation) {
    std::vector<int> tokens = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

    // Random mask
    auto masked = DataAugmenter::randomMask(tokens, 0.15f, 0, 100);
    EXPECT_EQ(masked.size(), tokens.size());

    // Span mask
    auto span_masked = DataAugmenter::spanMask(tokens, 0.15f, 3.0f);
    EXPECT_EQ(span_masked.size(), tokens.size());
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
