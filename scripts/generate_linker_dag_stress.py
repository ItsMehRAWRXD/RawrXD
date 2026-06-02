from __future__ import annotations

import argparse
import json
from pathlib import Path


def symbol_name(index: int) -> str:
    return f"obj_{index:03d}_func"


def dead_symbol_name(index: int) -> str:
    return f"obj_{index:03d}_dead"


def object_path(out_dir: Path, index: int) -> Path:
    return out_dir / f"obj_{index:03d}.asm"


def generate_source(index: int, count: int, fan_in: int, dead_symbol_every: int) -> tuple[str, list[str]]:
    name = symbol_name(index)
    deps: list[str] = []
    for delta in range(1, fan_in + 1):
        dep_index = index - delta
        if dep_index >= 0:
            deps.append(symbol_name(dep_index))

    lines: list[str] = [
        "OPTION CASEMAP:NONE",
        "",
        f"PUBLIC {name}",
    ]

    if dead_symbol_every > 0 and index % dead_symbol_every == 0:
        lines.append(f"PUBLIC {dead_symbol_name(index)}")

    for dep in deps:
        lines.append(f"EXTERN {dep}:PROC")

    lines.extend(
        [
            "",
            ".code",
            f"{name} PROC",
        ]
    )

    if deps:
        for dep in deps:
            lines.append(f"    call {dep}")
    else:
        lines.append("    nop")

    lines.extend(
        [
            "    ret",
            f"{name} ENDP",
        ]
    )

    if dead_symbol_every > 0 and index % dead_symbol_every == 0:
        dead_name = dead_symbol_name(index)
        lines.extend(
            [
                "",
                f"{dead_name} PROC",
                "    xor eax, eax",
                "    ret",
                f"{dead_name} ENDP",
            ]
        )

    lines.extend(["", "END", ""])
    return "\n".join(lines), deps


def write_entrypoint(out_dir: Path, count: int, fan_in: int) -> dict[str, object]:
    entry_deps = [symbol_name(index) for index in range(max(0, count - fan_in), count)]
    entry_path = out_dir / "entry.asm"
    lines = [
        "OPTION CASEMAP:NONE",
        "",
        "PUBLIC stress_entry",
    ]
    for dep in entry_deps:
        lines.append(f"EXTERN {dep}:PROC")
    lines.extend(["", ".code", "stress_entry PROC"])
    for dep in entry_deps:
        lines.append(f"    call {dep}")
    lines.extend(["    xor eax, eax", "    ret", "stress_entry ENDP", "", "END", ""])
    entry_path.write_text("\n".join(lines), encoding="ascii")
    return {
        "path": str(entry_path),
        "exports": ["stress_entry"],
        "dependencies": entry_deps,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a deterministic MASM DAG stress corpus.")
    parser.add_argument("--out-dir", required=True, help="Directory to write generated .asm files into.")
    parser.add_argument("--count", type=int, default=128, help="Number of object translation units to generate.")
    parser.add_argument("--fan-in", type=int, default=2, help="How many previous nodes each object references.")
    parser.add_argument(
        "--dead-symbol-every",
        type=int,
        default=5,
        help="Emit one unused PUBLIC symbol every N objects. Set 0 to disable.",
    )
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    manifest: dict[str, object] = {
        "count": args.count,
        "fanIn": args.fan_in,
        "deadSymbolEvery": args.dead_symbol_every,
        "objects": [],
    }

    for index in range(args.count):
        source, deps = generate_source(index, args.count, args.fan_in, args.dead_symbol_every)
        asm_path = object_path(out_dir, index)
        asm_path.write_text(source, encoding="ascii")
        object_record = {
            "path": str(asm_path),
            "exports": [symbol_name(index)],
            "dependencies": deps,
        }
        if args.dead_symbol_every > 0 and index % args.dead_symbol_every == 0:
            object_record["deadExport"] = dead_symbol_name(index)
        manifest["objects"].append(object_record)

    manifest["entry"] = write_entrypoint(out_dir, args.count, args.fan_in)
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())