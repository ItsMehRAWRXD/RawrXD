#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <regex>
#include "../../../src/core/problems_aggregator.hpp"

static void parseLine(const std::string& line) {
  using namespace RawrXD;
  auto& agg = ProblemsAggregator::instance();
  std::regex msvcRe(R"((.+?)\((\d+)(?:,(\d+))?\)\s*:\s*(error|warning|note)\s+(\w+\d+)?\s*:\s*(.+))");
  std::smatch m;
  if (std::regex_match(line, m, msvcRe) && m.size() >= 5) {
    std::string path = m[1].str();
    int lineNo = std::stoi(m[2].str());
    int col = (m[3].matched && m[3].length()) ? std::stoi(m[3].str()) : 0;
    std::string kind = m[4].str();
    std::string code = m[5].matched ? m[5].str() : "MSVC";
    std::string msg = m[6].str();
    int severity = (kind == "error") ? 1 : (kind == "warning") ? 2 : 3;
    agg.add("Build", path, lineNo, col, severity, code, msg, code);
  }
}

int main() {
  printf("PROBLEMS_GATE harness PROMOTE=0\n");
  using namespace RawrXD;
  auto& agg = ProblemsAggregator::instance();
  agg.clear("Build");

  // Feed synthetic MSVC lines including path with spaces
  parseLine("g:\\~dev\\rawrxd\\evidence\\FOUR_PANEL_COMPLETION_001\\fixtures\\path with spaces\\broken file.cpp(8,10): error C2143: syntax error: missing ';' before '}'");
  parseLine("g:\\~dev\\rawrxd\\evidence\\FOUR_PANEL_COMPLETION_001\\fixtures\\path with spaces\\broken file.cpp(7,7): warning C4101: 'unused': unreferenced local variable");
  parseLine("g:\\~dev\\rawrxd\\evidence\\FOUR_PANEL_COMPLETION_001\\fixtures\\path with spaces\\broken file.cpp(8,10): error C2143: syntax error: missing ';' before '}'"); // dedupe

  auto all = agg.getProblems("", "Build");
  int err=0,warn=0;
  for (auto& p : all) {
    printf("DIAG sev=%d line=%d col=%d code=%s path=%s msg=%s\n",
           p.severity, p.line, p.column, p.code.c_str(), p.path.c_str(), p.message.c_str());
    if (p.severity==1) err++; else if (p.severity==2) warn++;
  }
  int fail=0;
  if (all.size()!=2) { printf("FAIL expected 2 after dedupe got %zu\n", all.size()); fail++; }
  else printf("PASS dedupe count=2\n");
  if (err!=1 || warn!=1) { printf("FAIL err/warn counts %d/%d\n", err, warn); fail++; }
  else printf("PASS warn_vs_error\n");
  bool spaces=false;
  for (auto& p: all) if (p.path.find("path with spaces")!=std::string::npos) spaces=true;
  if (spaces) printf("PASS path_with_spaces\n"); else { printf("FAIL path_with_spaces\n"); fail++; }

  // rebuild refresh: clear + re-add fixed (none)
  agg.clear("Build");
  if (agg.count()!=0 && !agg.getProblems("", "Build").empty()) {
    // count() is global; only Build cleared
  }
  if (agg.getProblems("", "Build").empty()) printf("PASS stale_removal_after_clear\n");
  else { printf("FAIL stale_removal\n"); fail++; }

  printf("PROBLEMS_PANEL=%s\n", fail?"FAIL_CLOSED":"PASS");
  printf("PROMOTE=0 TIP_CLIMB=HOLD\n");
  return fail?1:0;
}