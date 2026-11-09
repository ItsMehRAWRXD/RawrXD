#pragma once
#include <string>
#include <vector>
#include <filesystem>
#include <optional>
namespace rawr {
enum class Status { not_run, pass, fail, blocked };
struct Gate { int id; std::string name; Status status = Status::not_run; std::string evidence; };
const char* status_name(Status s);
std::optional<Status> parse_status(const std::string& s);
std::vector<Gate> default_gates();
bool safe_evidence_path(const std::filesystem::path& root, const std::filesystem::path& file);
bool write_receipt_atomic(const std::filesystem::path& out, const std::vector<Gate>& gates, std::string& error);
bool apply_results(const std::filesystem::path& in, std::vector<Gate>& gates, std::string& error);
}
