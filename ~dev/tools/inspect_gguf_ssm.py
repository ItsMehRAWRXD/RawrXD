#!/usr/bin/env python3
"""Inspect Nemotron-H SSM tensor metadata independently of Deep2.

This intentionally does not decode quantized matrices.  It reports the GGUF
tensor descriptors and reads scalar F32/F16 tensors, which is enough to audit
SSM biases, A/D, dt, norms, and convolution weights without reusing the
production loader.
"""

from __future__ import annotations

import argparse
import json
import math
import struct
from pathlib import Path


TYPE_NAMES = {
    0: "F32", 1: "F16", 2: "Q4_0", 3: "Q4_1", 6: "Q5_0", 7: "Q5_1",
    8: "Q8_0", 9: "Q8_1", 10: "Q2_K", 11: "Q3_K", 12: "Q4_K",
    13: "Q5_K", 14: "Q6_K", 15: "Q8_K", 16: "IQ2_XXS", 17: "IQ2_XS",
    18: "IQ3_XXS", 19: "IQ1_S", 20: "IQ4_NL", 21: "IQ3_S", 22: "IQ2_S",
    23: "IQ4_XS", 24: "I8", 25: "I16", 26: "I32", 27: "I64",
    28: "F64", 29: "IQ1_M", 30: "BF16",
}
VALUE_SIZES = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8}


class Reader:
    def __init__(self, file, offset=0):
        self.file = file
        self.offset = offset

    def read(self, count):
        data = self.file.read(count)
        if len(data) != count:
            raise EOFError(f"truncated GGUF at 0x{self.offset:x}")
        self.offset += count
        return data

    def u32(self):
        return struct.unpack("<I", self.read(4))[0]

    def u64(self):
        return struct.unpack("<Q", self.read(8))[0]

    def string(self):
        count = self.u64()
        if count > 1024 * 1024:
            raise ValueError("GGUF string is unreasonably large")
        return self.read(count).decode("utf-8", errors="replace")


def skip_value(reader: Reader, kind: int):
    if kind in VALUE_SIZES:
        reader.read(VALUE_SIZES[kind])
    elif kind == 8:
        reader.string()
    elif kind == 9:
        item_kind = reader.u32()
        count = reader.u64()
        if count > 100_000_000:
            raise ValueError("GGUF array is unreasonably large")
        for _ in range(count):
            skip_value(reader, item_kind)
    else:
        raise ValueError(f"unsupported GGUF metadata type {kind}")


def tensor_record(reader: Reader):
    name = reader.string()
    dims = [reader.u64() for _ in range(reader.u32())]
    kind = reader.u32()
    offset = reader.u64()
    return {"name": name, "dims": dims, "type": kind, "type_name": TYPE_NAMES.get(kind, f"TYPE_{kind}"), "offset": offset}


def scalar_stats(file, data_offset: int, dims: list[int], kind: int):
    count = math.prod(dims)
    if kind == 0:
        fmt, width = "<f", 4
    elif kind == 1:
        fmt, width = "<e", 2
    else:
        return None
    file.seek(data_offset)
    values = []
    chunk = 1 << 16
    for start in range(0, count, chunk):
        take = min(chunk, count - start)
        raw = file.read(take * width)
        if len(raw) != take * width:
            raise EOFError("truncated tensor payload")
        values.extend(struct.unpack(f"<{take}{'f' if kind == 0 else 'e'}", raw))
    finite = [value for value in values if math.isfinite(value)]
    if not finite:
        return {"count": count, "finite": 0}
    return {
        "count": count,
        "finite": len(finite),
        "min": min(finite),
        "max": max(finite),
        "mean": sum(finite) / len(finite),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("model", type=Path)
    parser.add_argument("--layer", type=int, default=0)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    if args.layer < 0:
        parser.error("layer must be non-negative")

    with args.model.open("rb") as file:
        reader = Reader(file)
        if reader.read(4) != b"GGUF":
            raise ValueError("not a GGUF file")
        version = reader.u32()
        if version not in (2, 3):
            raise ValueError(f"unsupported GGUF version {version}")
        tensor_count, kv_count = reader.u64(), reader.u64()
        metadata = {}
        for _ in range(kv_count):
            key = reader.string()
            kind = reader.u32()
            if key == "general.alignment" and kind == 4:
                metadata[key] = reader.u32()
            else:
                skip_value(reader, kind)
        tensors = [tensor_record(reader) for _ in range(tensor_count)]
        alignment = int(metadata.get("general.alignment", 32))
        data_start = (reader.offset + alignment - 1) // alignment * alignment
        prefix = f"blk.{args.layer}."
        selected = [record for record in tensors if record["name"].startswith(prefix) and (
            "ssm_" in record["name"] or "ssm" in record["name"])]
        for record in selected:
            record["data_offset"] = data_start + record["offset"]
            record["elements"] = math.prod(record["dims"])
            if record["type"] in (0, 1):
                record["stats"] = scalar_stats(file, record["data_offset"], record["dims"], record["type"])
    result = {
        "model": str(args.model),
        "version": version,
        "tensor_count": tensor_count,
        "data_start": data_start,
        "layer": args.layer,
        "tensors": selected,
    }
    text = json.dumps(result, indent=2, sort_keys=True)
    if args.json:
        args.json.write_text(text + "\n", encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
