// rawrstd smoke test: exercises the containers and the raw string helpers.

#include "rawrstd/algo.h"
#include "rawrstd/base.h"
#include "rawrstd/map.h"
#include "rawrstd/string.h"
#include "rawrstd/sys.h"
#include "rawrstd/vector.h"

using namespace rawrstd;

static int failures = 0;

static void check(bool cond, const char* what) {
    if (cond) {
        write_stdout("  [PASS] ", 9);
    } else {
        write_stdout("  [FAIL] ", 9);
        ++failures;
    }
    write_stdout(what, strlen_raw(what));
    write_stdout("\n", 1);
}

int main() {
    write_stdout("rawrstd smoke test\n", 19);

    // --- String ---
    String s;
    s.assign("hello");
    check(s.size() == 5, "string size");
    check(s[0] == 'h', "string index");
    s.append(" world");
    check(s.size() == 11, "string append");
    check(s == "hello world", "string equality");
    check(s.find("world") == 6, "string find");
    check(s.ends_with("world"), "string ends_with");
    check(s.starts_with("hello"), "string starts_with");

    String num;
    num.append_i64(-12345);
    check(num == "-12345", "string append_i64");
    num.clear();
    num.append_u64(18446744073709551615ull);
    check(num == "18446744073709551615", "string append_u64");
    num.clear();
    num.append_hex_u64(0xDEADBEEF);
    check(num == "DEADBEEF", "string append_hex_u64");

    // --- Vector ---
    Vector<int> v;
    for (int i = 0; i < 100; ++i) v.push_back(i * 3);
    check(v.size() == 100, "vector size");
    check(v[42] == 126, "vector index");
    v.pop_back();
    check(v.size() == 99, "vector pop_back");
    v.resize(10);
    check(v.size() == 10, "vector resize down");
    v.reserve(1000);
    check(v.capacity() >= 1000, "vector reserve");

    Vector<int> copy = v;
    check(copy.size() == v.size(), "vector copy");
    Vector<int> moved = static_cast<Vector<int>&&>(v);
    check(moved.size() == 10, "vector move");

    // --- Map ---
    StringMap<int> m;
    for (int i = 0; i < 500; ++i) {
        String key;
        key.append_u64(static_cast<uint64>(i));
        m.insert(key, i * 2);
    }
    check(m.size() == 500, "map size");
    String k57;
    k57.assign("57");
    int* found = m.find(k57);
    check(found != nullptr && *found == 114, "map lookup");
    check(m.erase(k57), "map erase");
    check(m.find(k57) == nullptr, "map erase removes");
    check(m.size() == 499, "map size after erase");

    // Re-insert after erase to check probe-chain integrity.
    m.insert(k57, 999);
    int* again = m.find(k57);
    check(again != nullptr && *again == 999, "map reinsert after erase");

    // --- Sort ---
    Vector<int> s2;
    int vals[8] = { 5, 3, 9, 1, 7, 2, 8, 4 };
    for (int i = 0; i < 8; ++i) s2.push_back(vals[i]);
    sort(s2);
    bool sorted = true;
    for (size_type i = 1; i < s2.size(); ++i) {
        if (s2[i] < s2[i - 1]) sorted = false;
    }
    check(sorted, "merge_sort");

    // --- File IO ---
    File f;
    bool opened = f.open("G:\\VSC0de\\certification\\rawrstd_test.txt", FileMode::Write);
    check(opened, "file open for write");
    if (opened) {
        f.write("rawrstd roundtrip", 17);
        f.close();
        File g;
        check(g.open("G:\\VSC0de\\certification\\rawrstd_test.txt", FileMode::Read), "file open for read");
        char buf[64];
        int64 got = g.read(buf, sizeof(buf));
        check(got == 17, "file read length");
        check(memcmp_raw(buf, "rawrstd roundtrip", 17) == 0, "file content");
        g.close();
    }

    char msg[64];
    size_type n = 0;
    msg[n++] = 'f';
    msg[n++] = 'a';
    msg[n++] = 'i';
    msg[n++] = 'l';
    msg[n++] = 's';
    msg[n++] = '=';
    n += format_i64(msg + n, failures);
    msg[n++] = '\n';
    write_stdout(msg, n);

    return failures == 0 ? 0 : 1;
}
