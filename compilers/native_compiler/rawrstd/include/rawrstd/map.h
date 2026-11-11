// rawrstd - open-addressing hash map.
//
// The compiler's symbol tables are the hottest data structure in the whole
// toolchain, so this uses a flat open-addressing layout with linear probing
// rather than a node-based tree.

#ifndef RAWRSTD_MAP_H
#define RAWRSTD_MAP_H

#include "rawrstd/base.h"
#include "rawrstd/string.h"
#include "rawrstd/vector.h"

namespace rawrstd {

// FNV-1a
inline uint64 hash_bytes(const char* data, size_type length) {
    uint64 h = 1469598103934665603ull;
    for (size_type i = 0; i < length; ++i) {
        h ^= static_cast<uint64>(static_cast<uint8>(data[i]));
        h *= 1099511628211ull;
    }
    return h;
}

inline uint64 hash_string(const String& s) {
    return hash_bytes(s.data(), s.size());
}

template <typename K, typename V, typename HashFn>
class HashMap {
public:
    struct Entry {
        K key{};
        V value{};
        uint64 hash = 0;
        bool occupied = false;
    };

    void insert(const K& key, const V& value) {
        ensure_capacity(count_ + 1);
        insert_nogrow(key, value);
    }

    V* find(const K& key) {
        if (entries_.empty()) return nullptr;
        uint64 h = HashFn{}(key);
        size_type idx = static_cast<size_type>(h) & mask_;
        for (size_type probe = 0; probe <= mask_; ++probe) {
            Entry& e = entries_[idx];
            if (!e.occupied) return nullptr;
            if (e.hash == h && equal_keys(e.key, key)) return &e.value;
            idx = (idx + 1) & mask_;
        }
        return nullptr;
    }

    const V* find(const K& key) const {
        if (entries_.empty()) return nullptr;
        uint64 h = HashFn{}(key);
        size_type idx = static_cast<size_type>(h) & mask_;
        for (size_type probe = 0; probe <= mask_; ++probe) {
            const Entry& e = entries_[idx];
            if (!e.occupied) return nullptr;
            if (e.hash == h && equal_keys(e.key, key)) return &e.value;
            idx = (idx + 1) & mask_;
        }
        return nullptr;
    }

    bool contains(const K& key) const { return find(key) != nullptr; }

    V& get_or_insert(const K& key, const V& fallback) {
        if (V* existing = find(key)) return *existing;
        insert(key, fallback);
        return *find(key);
    }

    bool erase(const K& key) {
        if (entries_.empty()) return false;
        uint64 h = HashFn{}(key);
        size_type idx = static_cast<size_type>(h) & mask_;
        for (size_type probe = 0; probe <= mask_; ++probe) {
            Entry& e = entries_[idx];
            if (!e.occupied) return false;
            if (e.hash == h && equal_keys(e.key, key)) {
                // Backward-shift deletion keeps probe chains intact.
                e.occupied = false;
                --count_;
                size_type hole = idx;
                size_type scan = (hole + 1) & mask_;
                while (entries_[scan].occupied) {
                    uint64 ih = entries_[scan].hash;
                    size_type ideal = static_cast<size_type>(ih) & mask_;
                    // The entry at `scan` may move into `hole` unless its ideal
                    // slot lies strictly inside the cyclic span (hole, scan].
                    bool can_move;
                    if (scan > hole) {
                        can_move = (ideal <= hole || ideal > scan);
                    } else {
                        can_move = (ideal <= scan || ideal > hole);
                    }
                    if (can_move) {
                        entries_[hole] = entries_[scan];
                        entries_[scan].occupied = false;
                        hole = scan;
                    }
                    scan = (scan + 1) & mask_;
                }
                return true;
            }
            idx = (idx + 1) & mask_;
        }
        return false;
    }

    void clear() {
        for (size_type i = 0; i < entries_.size(); ++i) entries_[i].occupied = false;
        count_ = 0;
    }

    size_type size() const { return count_; }
    bool empty() const { return count_ == 0; }

    // Iteration over occupied entries.
    template <typename Fn>
    void for_each(Fn fn) const {
        for (size_type i = 0; i < entries_.size(); ++i) {
            if (entries_[i].occupied) fn(entries_[i].key, entries_[i].value);
        }
    }

    Vector<Entry>& raw_entries() { return entries_; }
    const Vector<Entry>& raw_entries() const { return entries_; }

private:
    static bool equal_keys(const K& a, const K& b) { return a == b; }

    // Raw insert: assumes the table already has room for one more entry.
    void insert_nogrow(const K& key, const V& value) {
        uint64 h = HashFn{}(key);
        size_type idx = static_cast<size_type>(h) & mask_;

        for (size_type probe = 0; probe <= mask_; ++probe) {
            Entry& e = entries_[idx];
            if (!e.occupied) {
                e.key = key;
                e.value = value;
                e.hash = h;
                e.occupied = true;
                ++count_;
                return;
            }
            if (e.hash == h && equal_keys(e.key, key)) {
                e.value = value;
                return;
            }
            idx = (idx + 1) & mask_;
        }
    }

    // Grow to `new_cap` slots and rehash every live entry.
    void grow(size_type new_cap) {
        Vector<Entry> old;
        old.swap(entries_);

        entries_.resize(new_cap);
        for (size_type i = 0; i < new_cap; ++i) entries_[i].occupied = false;

        mask_ = new_cap - 1;
        count_ = 0;
        for (size_type i = 0; i < old.size(); ++i) {
            if (!old[i].occupied) continue;
            insert_nogrow(old[i].key, old[i].value);
        }
    }

    // Keep the load factor at or below 75%.
    void ensure_capacity(size_type needed) {
        if (entries_.empty()) {
            grow(16);
            return;
        }
        if (needed * 4 <= entries_.size() * 3) return;
        grow(entries_.size() * 2);
    }

    Vector<Entry> entries_;
    size_type count_ = 0;
    size_type mask_ = 0;
};

struct StringHash {
    uint64 operator()(const String& s) const { return hash_string(s); }
};

template <typename V>
using StringMap = HashMap<String, V, StringHash>;

} // namespace rawrstd

#endif // RAWRSTD_MAP_H
