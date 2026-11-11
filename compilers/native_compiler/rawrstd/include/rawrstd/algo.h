// rawrstd - sorting and small algorithm helpers.

#ifndef RAWRSTD_ALGO_H
#define RAWRSTD_ALGO_H

#include "rawrstd/base.h"
#include "rawrstd/vector.h"

namespace rawrstd {

// Insertion sort: stable, and fastest for the small ranges that dominate
// (symbol name lists, small constant arrays).
template <typename T, typename Less>
void insertion_sort(Vector<T>& v, Less less) {
    for (size_type i = 1; i < v.size(); ++i) {
        T key = static_cast<T&&>(v[i]);
        size_type j = i;
        while (j > 0 && less(key, v[j - 1])) {
            v[j] = static_cast<T&&>(v[j - 1]);
            --j;
        }
        v[j] = static_cast<T&&>(key);
    }
}

// Stable merge sort. O(n log n), no recursion depth concerns for our sizes.
template <typename T, typename Less>
void merge_sort(Vector<T>& v, Less less) {
    if (v.size() < 2) return;
    Vector<T> scratch;
    scratch.resize(v.size());

    for (size_type width = 1; width < v.size(); width *= 2) {
        for (size_type i = 0; i < v.size(); i += width * 2) {
            size_type left = i;
            size_type mid = min_of(i + width, v.size());
            size_type right = min_of(i + width * 2, v.size());

            size_type l = left, r = mid, out = left;
            while (l < mid && r < right) {
                if (less(v[r], v[l])) scratch[out++] = static_cast<T&&>(v[r++]);
                else scratch[out++] = static_cast<T&&>(v[l++]);
            }
            while (l < mid) scratch[out++] = static_cast<T&&>(v[l++]);
            while (r < right) scratch[out++] = static_cast<T&&>(v[r++]);
        }
        for (size_type i = 0; i < v.size(); ++i) v[i] = static_cast<T&&>(scratch[i]);
    }
}

template <typename T>
void sort(Vector<T>& v) {
    merge_sort(v, [](const T& a, const T& b) { return a < b; });
}

// Binary search over a sorted range; returns npos when absent.
template <typename T, typename Key, typename Less>
size_type lower_bound(const Vector<T>& v, const Key& key, Less less) {
    size_type lo = 0, hi = v.size();
    while (lo < hi) {
        size_type mid = lo + (hi - lo) / 2;
        if (less(v[mid], key)) lo = mid + 1;
        else hi = mid;
    }
    return lo;
}

} // namespace rawrstd

#endif // RAWRSTD_ALGO_H
