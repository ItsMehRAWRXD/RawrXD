#!/usr/bin/env python3
"""Shared reader for the ModelGenie differential recorder's binary format.

Layout (see DifferentialRecorder::SaveAll):
  [0]  uint32 op_id
  [4]  uint32 layer_idx
  [8]  uint64 position
  [16] uint32 ndim
  [20] int64  shape[ndim]
  ...  uint64 data_size
  ...  float  data[data_size]
"""
import glob
import os
import struct

import numpy as np


def read_record(path):
    b = open(path, "rb").read()
    op_id, layer_idx, position, ndim = struct.unpack_from("<IIQI", b, 0)
    shape = list(struct.unpack_from("<%dq" % ndim, b, 20))
    data_off = 20 + 8 * ndim + 8
    n = int((len(b) - data_off) / 4)
    return op_id, layer_idx, position, shape, np.frombuffer(
        b[data_off:], dtype=np.float32).astype(np.float64)


def find(nd, label, layer, pos):
    for p in sorted(glob.glob(os.path.join(nd, "rec_*"))):
        if label not in p or ("_p%d_" % pos) not in p:
            continue
        if ("_l%d_" % layer) not in p and ("_l%02d_" % layer) not in p:
            continue
        return p
    return None


def take(nd, label, layer, pos, expect=None):
    p = find(nd, label, layer, pos)
    if not p:
        return None
    _, _, _, shape, arr = read_record(p)
    if expect is not None and arr.size != expect:
        print("WARN %s: shape=%s size=%d expected=%d"
              % (label, shape, arr.size, expect))
    return arr


def take_shaped(nd, label, layer, pos):
    p = find(nd, label, layer, pos)
    if not p:
        return None
    _, _, _, shape, arr = read_record(p)
    return arr, shape
