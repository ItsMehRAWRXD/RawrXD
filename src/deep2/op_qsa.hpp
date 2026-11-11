#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace Deep2::Qwen4Exp {

struct QSADescriptor {
    uint32_t index_heads = 4;
    uint32_t key_dim = 128;
    uint32_t compress_ratio = 4;
    uint32_t top_k = 2048;
    uint32_t page_size = 16;
};

bool ValidateQSADescriptor(const QSADescriptor& descriptor, std::string& failure);

// query is [rows, index_heads, key_dim]; key_cache is a compressed-key cache
// [pages, page_size, key_dim]; page_table is [requests, max_pages].
bool QSAScoreReference(const QSADescriptor& descriptor,
                       const std::vector<float>& query,
                       uint32_t rows,
                       const std::vector<float>& key_cache,
                       uint32_t pages,
                       const std::vector<int32_t>& page_table,
                       uint32_t max_pages,
                       const std::vector<int32_t>& token_to_request,
                       const std::vector<int32_t>& query_positions,
                       const std::vector<int32_t>& sequence_lengths,
                       std::vector<float>& logits,
                       std::vector<uint32_t>& visible_columns,
                       std::string& failure);

bool QSASelectReference(const QSADescriptor& descriptor,
                        const std::vector<float>& logits,
                        const std::vector<uint32_t>& visible_columns,
                        const std::vector<int32_t>& query_positions,
                        std::vector<int32_t>& selected_tokens,
                        std::string& failure);

} // namespace Deep2::Qwen4Exp
