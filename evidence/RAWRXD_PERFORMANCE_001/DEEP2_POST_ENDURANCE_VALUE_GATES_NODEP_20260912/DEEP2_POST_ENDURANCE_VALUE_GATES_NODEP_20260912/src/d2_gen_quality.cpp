#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

static std::string read_all(const std::string& p) {
    std::ifstream f(p, std::ios::binary);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static std::vector<std::string> words_lower(const std::string& s) {
    std::vector<std::string> out;
    std::string w;
    for (unsigned char ch : s) {
        if (std::isalnum(ch) || ch=='\'' || ch=='-') w.push_back((char)std::tolower(ch));
        else if (!w.empty()) { out.push_back(w); w.clear(); }
    }
    if (!w.empty()) out.push_back(w);
    return out;
}

static int max_identical_run(const std::vector<std::string>& w) {
    int best=0, cur=0;
    std::string prev;
    for (const auto& x : w) {
        if (x==prev) ++cur; else { prev=x; cur=1; }
        best = std::max(best, cur);
    }
    return best;
}

static double unique_ratio(const std::vector<std::string>& w) {
    if (w.empty()) return 0.0;
    std::set<std::string> u(w.begin(), w.end());
    return (double)u.size() / (double)w.size();
}

static double max_ngram_share(const std::vector<std::string>& w, int n) {
    if ((int)w.size() < n || n <= 0) return 0.0;
    std::unordered_map<std::string,int> c;
    int total=0, best=0;
    for (size_t i=0; i+(size_t)n<=w.size(); ++i) {
        std::string k;
        for (int j=0;j<n;++j) { if (j) k.push_back('\x1f'); k += w[i+j]; }
        int v=++c[k]; best=std::max(best,v); ++total;
    }
    return total ? (double)best/(double)total : 0.0;
}

struct TraceState {
    int rows=0;
    bool finite=true;
    bool sampler_valid=true;
    bool tok_roundtrip=true;
    bool chat_template=true;
    int selected_max_run=0;
    int argmax_max_run=0;
};

static bool field_is_zero(const std::string& line, const char* key) {
    std::string p = std::string(key) + "=0";
    return line.find(p) != std::string::npos;
}

static bool parse_i64_field(const std::string& line, const char* key, long long& out) {
    std::string p=std::string(key)+"="; size_t i=line.find(p); if(i==std::string::npos) return false;
    i += p.size(); size_t e=i; if(e<line.size() && line[e]=='-') ++e;
    while(e<line.size() && std::isdigit((unsigned char)line[e])) ++e;
    try { out=std::stoll(line.substr(i,e-i)); return true; } catch(...) { return false; }
}

static TraceState parse_trace(const std::string& p) {
    TraceState t;
    if (p.empty()) return t;
    std::ifstream f(p);
    std::string line;
    long long prev_sel=0, prev_arg=0; bool have_sel=false, have_arg=false; int run_sel=0, run_arg=0;
    while (std::getline(f,line)) {
        if (line.find("token_ordinal=")==std::string::npos) continue;
        ++t.rows;
        if (field_is_zero(line,"finite")) t.finite=false;
        if (field_is_zero(line,"sampler_valid")) t.sampler_valid=false;
        if (field_is_zero(line,"tokenizer_roundtrip")) t.tok_roundtrip=false;
        if (field_is_zero(line,"chat_template_valid")) t.chat_template=false;
        long long sel=0,arg=0;
        if(parse_i64_field(line,"selected_token_id",sel) || parse_i64_field(line,"token_id",sel)) {
            run_sel = (have_sel && sel==prev_sel) ? run_sel+1 : 1; prev_sel=sel; have_sel=true;
            t.selected_max_run=std::max(t.selected_max_run,run_sel);
        }
        if(parse_i64_field(line,"argmax_token_id",arg)) {
            run_arg = (have_arg && arg==prev_arg) ? run_arg+1 : 1; prev_arg=arg; have_arg=true;
            t.argmax_max_run=std::max(t.argmax_max_run,run_arg);
        }
    }
    return t;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: d2_gen_quality <stdout.txt> [trace.txt]\n";
        return 64;
    }
    const std::string text = read_all(argv[1]);
    const auto words = words_lower(text);
    const int run = max_identical_run(words);
    const double uniq = unique_ratio(words);
    const double tri = max_ngram_share(words,3);
    const TraceState tr = parse_trace(argc>=3 ? argv[2] : "");

    // Mechanical collapse predicates: conservative by design.
    const bool has_text = !words.empty();
    const bool repetition_collapse = (run > 4) || (words.size() >= 12 && uniq < 0.18) || (words.size() >= 18 && tri > 0.35);
    const bool trace_ok = tr.finite && tr.sampler_valid && tr.tok_roundtrip && tr.chat_template;
    const bool coherent = has_text && !repetition_collapse && (words.size() < 8 || uniq >= 0.22);
    const bool pass = coherent && trace_ok;
    std::string suspect="NONE";
    if (!tr.tok_roundtrip) suspect="TOKENIZER";
    else if (!tr.chat_template) suspect="CHAT_TEMPLATE";
    else if (!tr.finite) suspect="LOGITS_NONFINITE";
    else if (!tr.sampler_valid) suspect="SAMPLER_STATE";
    else if (repetition_collapse && tr.selected_max_run>4 && tr.argmax_max_run<=2 && tr.argmax_max_run>0) suspect="SAMPLER_SELECTION";
    else if (repetition_collapse && tr.argmax_max_run>4) suspect="UPSTREAM_LOGITS_OR_MODEL_PATH";
    else if (repetition_collapse) suspect="TEXT_LEVEL_REPETITION_NEEDS_TRACE";

    std::cout << "GEN_QUALITY_ANALYZER=1\n";
    std::cout << "WORDS=" << words.size() << "\n";
    std::cout << "MAX_IDENTICAL_WORD_RUN=" << run << "\n";
    std::cout << "UNIQUE_WORD_RATIO=" << uniq << "\n";
    std::cout << "MAX_TRIGRAM_SHARE=" << tri << "\n";
    std::cout << "TRACE_ROWS=" << tr.rows << "\n";
    std::cout << "SELECTED_TOKEN_MAX_RUN=" << tr.selected_max_run << "\n";
    std::cout << "ARGMAX_TOKEN_MAX_RUN=" << tr.argmax_max_run << "\n";
    std::cout << "LOGITS_FINITE=" << (tr.finite?1:0) << "\n";
    std::cout << "SAMPLER_STATE_VALID=" << (tr.sampler_valid?1:0) << "\n";
    std::cout << "TOKENIZER_ROUNDTRIP=" << (tr.tok_roundtrip?"PASS":"FAIL") << "\n";
    std::cout << "CHAT_TEMPLATE_VALID=" << (tr.chat_template?1:0) << "\n";
    std::cout << "REPETITION_COLLAPSE=" << (repetition_collapse?1:0) << "\n";
    std::cout << "OUTPUT_COHERENT=" << (coherent?1:0) << "\n";
    std::cout << "ROOT_CAUSE_SUSPECT=" << suspect << "\n";
    std::cout << "GEN_QUALITY=" << (pass?"PASS":"FAIL") << "\n";
    std::cout << "PROMOTE=0\n";
    return pass ? 0 : 20;
}
