#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <functional>
namespace Deep2::Directory {
struct Tensor { std::string name; std::vector<uint64_t> dims; uint32_t type=0; uint64_t offset=0, bytes=0; };
struct Model { uint32_t version=0; uint64_t file_bytes=0, data_start=0, alignment=32; std::string architecture; std::vector<Tensor> tensors; std::vector<std::string> errors; };
// Geometry must come from the production QuantTypeTable.hpp, not a second copy.
using Geometry = std::function<bool(uint32_t type, uint64_t& block_elements, uint64_t& block_bytes)>;
Model inspect(const std::string& path, const Geometry& geometry);
}
