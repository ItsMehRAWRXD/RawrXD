#include "op_qsa.hpp"

#include <algorithm>
#include <cmath>
#include <limits>
#include <utility>

namespace Deep2::Qwen4Exp {
namespace {

bool AllFinite(const std::vector<float>& values) {
    for (float value : values) if (!std::isfinite(value)) return false;
    return true;
}

} // namespace

bool ValidateQSADescriptor(const QSADescriptor& descriptor, std::string& failure) {
    if (descriptor.index_heads == 0 || descriptor.key_dim == 0 || descriptor.compress_ratio == 0 ||
        descriptor.top_k == 0 || descriptor.page_size == 0) {
        failure = "QSA dimensions are zero";
        return false;
    }
    if (descriptor.index_heads != 4 || descriptor.key_dim != 128 ||
        descriptor.compress_ratio != 4 || descriptor.top_k != 2048) {
        failure = "Qwen4Exp QSA requires index_heads=4 key_dim=128 compression=4 top_k=2048";
        return false;
    }
    if (descriptor.top_k % descriptor.compress_ratio != 0) {
        failure = "QSA top_k must be divisible by the compression ratio";
        return false;
    }
    return true;
}

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
                       std::string& failure) {
    if (!ValidateQSADescriptor(descriptor, failure)) return false;
    const size_t query_width = static_cast<size_t>(descriptor.index_heads) * descriptor.key_dim;
    const size_t columns = static_cast<size_t>(max_pages) * descriptor.page_size;
    if (rows == 0 || pages == 0 || max_pages == 0 || sequence_lengths.empty() ||
        query.size() != static_cast<size_t>(rows) * query_width ||
        key_cache.size() != static_cast<size_t>(pages) * descriptor.page_size * descriptor.key_dim ||
        page_table.size() != sequence_lengths.size() * max_pages ||
        token_to_request.size() != rows || query_positions.size() != rows) {
        failure = "QSA cache, page table, or query metadata shape mismatch";
        return false;
    }
    if (!AllFinite(query) || !AllFinite(key_cache)) {
        failure = "QSA query or compressed-key cache contains NaN/Inf";
        return false;
    }
    logits.assign(static_cast<size_t>(rows) * columns,
                  -std::numeric_limits<float>::infinity());
    visible_columns.assign(rows, 0);
    const float scale = 1.0f / std::sqrt(static_cast<float>(descriptor.key_dim));
    for (uint32_t row = 0; row < rows; ++row) {
        const int32_t request = token_to_request[row];
        if (request < 0 || static_cast<size_t>(request) >= sequence_lengths.size()) continue;
        const int32_t position = query_positions[row];
        if (position < 0) continue;
        const uint32_t visible = std::min(
            static_cast<uint32_t>((position + 1) / static_cast<int32_t>(descriptor.compress_ratio)),
            static_cast<uint32_t>(std::max(0, sequence_lengths[request]) /
                                  static_cast<int32_t>(descriptor.compress_ratio)));
        visible_columns[row] = std::min(visible, static_cast<uint32_t>(columns));
        for (uint32_t column = 0; column < visible_columns[row]; ++column) {
            const int32_t physical_page = page_table[static_cast<size_t>(request) * max_pages +
                                                     column / descriptor.page_size];
            if (physical_page < 0 || static_cast<uint32_t>(physical_page) >= pages) {
                failure = "QSA page table references an invalid physical page";
                logits.clear();
                visible_columns.clear();
                return false;
            }
            const size_t key_base = (static_cast<size_t>(physical_page) * descriptor.page_size +
                                     column % descriptor.page_size) * descriptor.key_dim;
            double score = 0.0;
            for (uint32_t head = 0; head < descriptor.index_heads; ++head) {
                double dot = 0.0;
                const size_t query_base = (static_cast<size_t>(row) * descriptor.index_heads + head) *
                                          descriptor.key_dim;
                for (uint32_t dim = 0; dim < descriptor.key_dim; ++dim)
                    dot += static_cast<double>(query[query_base + dim]) * key_cache[key_base + dim];
                score += std::max(0.0, dot);
            }
            logits[static_cast<size_t>(row) * columns + column] = static_cast<float>(score * scale);
        }
    }
    return true;
}

bool QSASelectReference(const QSADescriptor& descriptor,
                        const std::vector<float>& logits,
                        const std::vector<uint32_t>& visible_columns,
                        const std::vector<int32_t>& query_positions,
                        std::vector<int32_t>& selected_tokens,
                        std::string& failure) {
    if (!ValidateQSADescriptor(descriptor, failure)) return false;
    if (visible_columns.size() != query_positions.size() || visible_columns.empty()) {
        failure = "QSA selection metadata is empty or mismatched";
        return false;
    }
    const size_t rows = visible_columns.size();
    const size_t columns = logits.size() / rows;
    if (columns == 0 || logits.size() != rows * columns) {
        failure = "QSA score matrix has an invalid shape";
        return false;
    }
    const size_t output_width = descriptor.top_k + descriptor.compress_ratio - 1u;
    selected_tokens.assign(rows * output_width, -1);
    const uint32_t block_top_k = descriptor.top_k / descriptor.compress_ratio;
    for (size_t row = 0; row < rows; ++row) {
        std::vector<std::pair<float, uint32_t>> candidates;
        const uint32_t count = std::min(visible_columns[row], static_cast<uint32_t>(columns));
        candidates.reserve(count);
        for (uint32_t column = 0; column < count; ++column)
            candidates.emplace_back(logits[row * columns + column], column);
        std::stable_sort(candidates.begin(), candidates.end(),
                         [](const auto& lhs, const auto& rhs) {
                             if (lhs.first != rhs.first) return lhs.first > rhs.first;
                             return lhs.second < rhs.second;
                         });
        const uint32_t selected_blocks = std::min<uint32_t>(
            block_top_k, static_cast<uint32_t>(candidates.size()));
        size_t output_index = row * output_width;
        for (uint32_t block = 0; block < selected_blocks && output_index < (row + 1) * output_width; ++block) {
            const uint32_t logical_start = candidates[block].second * descriptor.compress_ratio;
            for (uint32_t offset = 0; offset < descriptor.compress_ratio &&
                 output_index < (row + 1) * output_width; ++offset) {
                const int32_t token = static_cast<int32_t>(logical_start + offset);
                if (token <= query_positions[row]) selected_tokens[output_index++] = token;
            }
        }
    }
    return true;
}

} // namespace Deep2::Qwen4Exp
