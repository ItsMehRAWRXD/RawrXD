#pragma once

// A host-resident key and value cache with the same ring layout as the
// device cache.
//
// The layout is [layer][window][hiddenDim] for the keys and the same for
// the values, and the logical position p lives in the physical slot
// p % window.
//
// The host copy exists so that the reference attention and the device
// attention read the same tokens from the same slots. If the two layouts
// disagreed, a parity comparison would be measuring two different token
// sets rather than two different implementations.

#include "KvWindowPlan.hpp"

#include <cstdint>
#include <vector>

namespace deep2 {

class HostKvRing {
public:
    void reset(uint32_t layers, uint32_t window, uint32_t hiddenDim) {
        m_layers = layers;
        m_window = window;
        m_hiddenDim = hiddenDim;
        const size_t elements = static_cast<size_t>(layers) * window * hiddenDim;
        m_keys.assign(elements, 0.0f);
        m_values.assign(elements, 0.0f);
    }

    bool ready() const { return m_layers != 0 && m_window != 0 && m_hiddenDim != 0; }
    uint32_t window() const { return m_window; }
    uint32_t hiddenDim() const { return m_hiddenDim; }

    // Store one position's key and value rows for a layer. Writing past the
    // window overwrites the oldest token.
    void append(uint32_t layer, uint32_t logicalPos, const float* keys, const float* values) {
        if (!ready() || layer >= m_layers || !keys || !values) return;
        float* k = keyRowMut(layer, logicalPos);
        float* v = valueRowMut(layer, logicalPos);
        if (!k || !v) return;
        for (uint32_t i = 0; i < m_hiddenDim; ++i) {
            k[i] = keys[i];
            v[i] = values[i];
        }
    }

    // The rows of a logical position, wherever the ring currently holds it.
    float* keyRowMut(uint32_t layer, uint32_t logicalPos) {
        if (!ready() || layer >= m_layers) return nullptr;
        const uint32_t physical = KvPhysicalIndex(logicalPos, m_window);
        return m_keys.data() +
               (static_cast<size_t>(layer) * m_window + physical) * m_hiddenDim;
    }

    float* valueRowMut(uint32_t layer, uint32_t logicalPos) {
        if (!ready() || layer >= m_layers) return nullptr;
        const uint32_t physical = KvPhysicalIndex(logicalPos, m_window);
        return m_values.data() +
               (static_cast<size_t>(layer) * m_window + physical) * m_hiddenDim;
    }

    const float* keyRow(uint32_t layer, uint32_t logicalPos) const {
        if (!ready() || layer >= m_layers) return nullptr;
        const uint32_t physical = KvPhysicalIndex(logicalPos, m_window);
        return m_keys.data() +
               (static_cast<size_t>(layer) * m_window + physical) * m_hiddenDim;
    }

    const float* valueRow(uint32_t layer, uint32_t logicalPos) const {
        if (!ready() || layer >= m_layers) return nullptr;
        const uint32_t physical = KvPhysicalIndex(logicalPos, m_window);
        return m_values.data() +
               (static_cast<size_t>(layer) * m_window + physical) * m_hiddenDim;
    }

private:
    uint32_t m_layers = 0;
    uint32_t m_window = 0;
    uint32_t m_hiddenDim = 0;
    std::vector<float> m_keys;
    std::vector<float> m_values;
};

}  // namespace deep2
