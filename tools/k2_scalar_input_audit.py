#!/usr/bin/env python3
"""Validate a Kimi captured scalar-input witness and evaluate its full expert.

The capture contains CPU-side packed weights and normalized hidden input.
No GPU output is included or inferred; a matching scalar output is NOT GPU parity.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path

from k2_scalar_expert_oracle import expert

SCHEMA = "DEEP2_KIMI_SCALAR_INPUTS_001"


def parse_manifest(manifest):
    if not manifest.name.endswith(".manifest.txt"):
        raise ValueError("expected .manifest.txt")
    fields = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        if "=" not in line:
            raise ValueError("malformed manifest line")
        key, value = line.split("=", 1)
        if not key or key in fields:
            raise ValueError("missing or duplicate manifest field")
        fields[key] = value
    required = {
        "schema": SCHEMA, "gate_ggml_type": "12",
        "up_ggml_type": "12", "down_ggml_type": "14",
        "source": "CPU_PACKED_SLICES_AND_NORMED_HIDDEN",
        "scope": "SCALAR_INPUT_ONLY_NO_GPU_OUTPUT", "certified": "0"
    }
    for key, value in required.items():
        if fields.get(key) != value:
            raise ValueError(f"manifest {key} mismatch")
    try:
        layer, expert_id, stick, hidden, intermediate = (
            int(fields[k]) for k in
            ("layer", "expert", "stick", "hidden_dim", "intermediate_dim"))
    except (ValueError, KeyError) as exc:
        raise ValueError("invalid scalar-input manifest geometry") from exc
    if layer < 0 or expert_id < 0 or stick not in (0, 1):
        raise ValueError("invalid layer/expert/stick")
    if not (256 <= hidden <= 16384 and 256 <= intermediate <= 16384
            and hidden % 256 == 0 and intermediate % 256 == 0):
        raise ValueError("invalid scalar-input dimensions")
    expected_stem = f"k2_l{layer}_e{expert_id}_s{stick}_scalar_inputs"
    if manifest.name != expected_stem + ".manifest.txt":
        raise ValueError("manifest name and identity differ")
    return {"layer": layer, "expert": expert_id, "stick": stick,
            "hidden_dim": hidden, "intermediate_dim": intermediate,
            "run_id": fields.get("run_id"), "stem": expected_stem}


def read_float_vector(path, expected):
    raw = path.read_bytes()
    values = []
    for i, line in enumerate(raw.decode("utf-8").splitlines(), 1):
        text = line.strip()
        if not text:
            raise ValueError(f"{path.name}:{i}: blank value")
        try:
            value = float(text)
        except ValueError as exc:
            raise ValueError(f"{path.name}:{i}: malformed value") from exc
        if not math.isfinite(value):
            raise ValueError(f"{path.name}:{i}: nonfinite value")
        values.append(value)
    if len(values) != expected:
        raise ValueError("hidden input length mismatch")
    return values, raw


def evaluate(manifest):
    meta = parse_manifest(manifest)
    stem = meta.pop("stem")
    base = manifest.parent / stem
    h, intermediate = meta["hidden_dim"], meta["intermediate_dim"]
    files = {
        "gate": Path(str(base) + ".gate_q4k.bin"),
        "up": Path(str(base) + ".up_q4k.bin"),
        "down": Path(str(base) + ".down_q6k.bin"),
        "hidden": Path(str(base) + ".hidden.txt"),
    }
    blobs = {name: path.read_bytes() for name, path in files.items()}
    gate_bytes = intermediate * (h // 256) * 144
    down_bytes = h * (intermediate // 256) * 210
    if (len(blobs["gate"]) != gate_bytes or
            len(blobs["up"]) != gate_bytes or
            len(blobs["down"]) != down_bytes):
        raise ValueError("packed tensor shape does not match manifest")
    hidden, _ = read_float_vector(files["hidden"], h)
    tensors = expert(blobs["gate"], blobs["up"], blobs["down"],
                     hidden, h, intermediate)
    provenance = {
        "manifest": hashlib.sha256(manifest.read_bytes()).hexdigest(),
        **{name: hashlib.sha256(raw).hexdigest()
           for name, raw in blobs.items()}
    }
    return meta, provenance, tensors


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--output-dir", type=Path, required=True)
    p.add_argument("--receipt", type=Path, required=True)
    a = p.parse_args(argv)
    try:
        if not a.output_dir.is_dir():
            raise ValueError("existing output directory required")
        if a.receipt.exists():
            raise ValueError("refusing to overwrite receipt")
        meta, hashes, outputs = evaluate(a.manifest)
        targets = {name: a.output_dir / f"scalar_{name}.txt"
                   for name in outputs}
        if any(path.exists() for path in targets.values()):
            raise ValueError("refusing to overwrite previous oracle vectors")
        # Validate all outputs before writing any.
        encoded = {}
        for name, values in outputs.items():
            if not values or not all(math.isfinite(v) for v in values):
                raise ValueError("nonfinite scalar output")
            encoded[name] = "".join(f"{v:.17g}\n" for v in values).encode("utf-8")
        written = []
        try:
            for name, path in targets.items():
                with path.open("xb") as f:
                    f.write(encoded[name])
                written.append(path)
            receipt = {
                "schema": "DEEP2_KIMI_SCALAR_INPUT_AUDIT_001/v1",
                "status": "PASS_DIAGNOSTIC", "certified": False,
                "identity": meta, "input_sha256": hashes,
                "output_sha256": {
                    name: hashlib.sha256(value).hexdigest()
                    for name, value in encoded.items()
                },
                "gpu_output_witness": "ABSENT",
                "note": "CPU input reconstruction only; no GPU per-expert parity",
            }
            with a.receipt.open("x", encoding="utf-8") as f:
                json.dump(receipt, f, indent=2, sort_keys=True)
                f.write("\n")
            return 0
        except (OSError, ValueError):
            for path in written:
                path.unlink(missing_ok=True)
            raise
    except (OSError, ValueError, UnicodeError, OverflowError) as exc:
        print("ERROR:", exc)
        # Never overwrite a prior receipt on failure.
        if not a.receipt.exists():
            with a.receipt.open("x", encoding="utf-8") as f:
                json.dump({"schema": "DEEP2_KIMI_SCALAR_INPUT_AUDIT_001/v1",
                           "status": "ERROR", "certified": False,
                           "error": str(exc)}, f, indent=2)
                f.write("\n")
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
