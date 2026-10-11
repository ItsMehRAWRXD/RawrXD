#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <map>
namespace deep2 {
struct TensorRecord {std::string name, dtype; uint64_t bytes=0; uint64_t dim0=0; bool shape_candidate=false, name_candidate=false;};
struct ExpertReport {
 uint64_t total_bytes=0, union_bytes=0, intersection_bytes=0, shape_bytes=0, name_bytes=0;
 size_t shape_count=0,name_count=0,union_count=0,intersection_count=0;
 std::map<std::string,uint64_t> dtype_bytes;
 std::map<std::string,size_t> dtype_counts;
 std::vector<std::string> conflicts;
 std::vector<std::string> discovered_tokens;
 std::string dominant_dtype;
 bool complete=false;
};
ExpertReport analyze(const std::vector<TensorRecord>& tensors, uint64_t declared_total_bytes, uint64_t declared_experts);
std::vector<TensorRecord> load_tsv(const std::string& path);
std::string to_json(const ExpertReport& r);
}
