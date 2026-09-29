#!/usr/bin/env python3
"""
Runtime Capability Code Generator
=================================
Reads capabilities.yaml and generates:
  - src/runtime/os/generated/*.hpp      (capability class declarations)
  - src/runtime/os/generated/*.cpp      (capability class implementations)
  - RuntimeCapabilityIds.hpp             (ID table)
  - RuntimeCapabilityForward.hpp         (forward declarations)
  - RuntimeCapabilityRegistration.cpp    (bootstrap registration)
  - RuntimeCapabilityCMake.cmake         (source list for CMake)

Domain-specific behavior is NOT generated — each .cpp has a stub body
that returns true for all phases. Hand-written overrides go in separate
files that subclass the generated types.
"""

import os
import sys
import re
from pathlib import Path

# Try to use PyYAML, fall back to a simple parser
try:
    import yaml
    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False

BASE = Path(r"f:\~dev\rawrxd\src\runtime\os")
GEN_DIR = BASE / "generated"
MANIFEST = BASE / "capabilities.yaml"


def parse_yaml_simple(path):
    """Simple YAML parser for our specific manifest format."""
    entries = []
    in_capabilities = False
    current = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                continue
            if stripped == "capabilities:":
                in_capabilities = True
                continue
            if not in_capabilities:
                continue
            if stripped.startswith("- {"):
                # Inline dict: - { name: Foo, ns: bar, category: baz }
                d = {}
                content = stripped[3:].rstrip("}")
                for part in content.split(","):
                    part = part.strip()
                    if ":" in part:
                        k, v = part.split(":", 1)
                        d[k.strip()] = v.strip()
                if "name" in d:
                    entries.append(d)
    return entries


def load_manifest():
    if HAVE_YAML:
        with open(MANIFEST, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data.get("capabilities", [])
    else:
        return parse_yaml_simple(MANIFEST)


def ns_path(ns):
    """Convert namespace to path component."""
    return ns.replace("::", "/")


def generate_header(cap):
    """Generate a capability class header."""
    name = cap["name"]
    ns = cap["ns"]
    cap_id = cap.get("id", "")
    category = cap.get("category", "runtime")

    short_name = name.replace("Capability", "")

    return f"""// ============================================================================
// {name}.hpp — Generated capability ({category})
// DO NOT edit the lifecycle contract — override phase methods in hand-written
// subclasses if domain-specific behavior is needed.
// ============================================================================
#pragma once
#include "../RuntimeCapability.hpp"

namespace {ns} {{

class {name} final : public rawrxd::runtime::RuntimeCapability {{
public:
    {name}() = default;
    ~{name}() override = default;

    rawrxd::runtime::CapabilityId id() const noexcept override;
    std::string_view name() const noexcept override;

    bool discover(rawrxd::runtime::CapabilityContext& ctx) override;
    bool admit(rawrxd::runtime::CapabilityContext& ctx) override;
    bool initialize(rawrxd::runtime::CapabilityContext& ctx) override;
    bool execute(rawrxd::runtime::CapabilityContext& ctx) override;
    bool observe(rawrxd::runtime::CapabilityContext& ctx) override;
    bool verify(rawrxd::runtime::CapabilityContext& ctx) override;
    bool commit(rawrxd::runtime::CapabilityContext& ctx) override;
    bool persist(rawrxd::runtime::CapabilityContext& ctx) override;
    bool recover(rawrxd::runtime::CapabilityContext& ctx) override;
    bool shutdown(rawrxd::runtime::CapabilityContext& ctx) override;
}};

}} // namespace {ns}
"""


def generate_impl(cap):
    """Generate a capability class implementation."""
    name = cap["name"]
    ns = cap["ns"]
    short_name = name.replace("Capability", "")
    id_expr = cap["id_expr"]

    phases = ["discover", "admit", "initialize", "execute",
              "observe", "verify", "commit", "persist", "recover", "shutdown"]

    state_map = {"discover": "Discovered", "admit": "Admitted", "initialize": "Initialized", "execute": "Running", "observe": "Ready", "verify": "Ready", "commit": "Ready", "persist": "Ready", "recover": "Ready", "shutdown": "Shutdown"}
    method_bodies = ""
    for phase in phases:
        st = state_map[phase]
        method_bodies += f"""
bool {name}::{phase}(rawrxd::runtime::CapabilityContext& ctx) {{
    // TODO: hand-written {phase} logic for {short_name}
    state_ = rawrxd::runtime::CapabilityState::{st};
    return true;
}}
"""

    return f"""// ============================================================================
// {name}.cpp — Generated capability implementation
// ============================================================================
#include "{name}.hpp"
#include "../RuntimeCapabilityIds.hpp"

namespace {ns} {{

rawrxd::runtime::CapabilityId {name}::id() const noexcept {{
    return {id_expr};
}}

std::string_view {name}::name() const noexcept {{
    return "{short_name}";
}}
{method_bodies}
}} // namespace {ns}
"""


def make_capid(cap):
    """Build a unique enum name for a capability using the FULL class name."""
    name = cap["name"]
    ns = cap["ns"]
    ns_prefix = ns.replace("rawrxd::", "").replace("::", "_").upper()
    # Use full class name (strip only the trailing 'Capability' suffix once)
    # but keep the full distinctive prefix to avoid collisions.
    short = name.upper()
    if short.endswith("CAPABILITY"):
        short = short[:-len("CAPABILITY")]
    return f"CAPID_{ns_prefix}_{short}"


def generate_ids_header(caps):
    """Generate RuntimeCapabilityIds.hpp with all capability IDs."""
    # Detect collisions and make them unique by appending _N
    seen = {}
    lines = []
    lines.append("// ============================================================================")
    lines.append("// RuntimeCapabilityIds.hpp — Generated capability ID table")
    lines.append("// ============================================================================")
    lines.append("#pragma once")
    lines.append("#include <cstdint>")
    lines.append("")
    lines.append("namespace rawrxd::runtime {")
    lines.append("")
    lines.append("enum CapabilityIds : uint64_t {")
    for i, cap in enumerate(caps):
        base = make_capid(cap)
        enum_name = base
        if enum_name in seen:
            # Collision — append suffix
            n = 2
            while f"{base}_{n}" in seen:
                n += 1
            enum_name = f"{base}_{n}"
        seen[enum_name] = i
        cap["_enum_name"] = enum_name  # store for impl generation
        lines.append(f"    {enum_name} = 0x{i+1:04X},")
    lines.append("};")
    lines.append("")
    lines.append("} // namespace rawrxd::runtime")
    lines.append("")
    return "\n".join(lines)


def generate_forward_header(caps):
    """Generate RuntimeCapabilityForward.hpp with all forward declarations."""
    lines = []
    lines.append("// ============================================================================")
    lines.append("// RuntimeCapabilityForward.hpp — Generated forward declarations")
    lines.append("// ============================================================================")
    lines.append("#pragma once")
    lines.append("")
    # Group by namespace
    by_ns = {}
    for cap in caps:
        ns = cap["ns"]
        by_ns.setdefault(ns, []).append(cap["name"])
    for ns, names in by_ns.items():
        lines.append(f"namespace {ns} {{")
        for name in names:
            lines.append(f"    class {name};")
        lines.append(f"}} // namespace {ns}")
        lines.append("")
    return "\n".join(lines)


def generate_registration(caps):
    """Generate RuntimeCapabilityRegistration.cpp — bootstrap registration."""
    lines = []
    lines.append("// ============================================================================")
    lines.append("// RuntimeCapabilityRegistration.cpp — Generated bootstrap registration")
    lines.append("// Registers all generated capabilities into the RuntimeKernel.")
    lines.append("// ============================================================================")
    lines.append('#include "RuntimeKernel.hpp"')
    lines.append('#include "RuntimeCapabilityIds.hpp"')
    lines.append("")
    # Include all headers
    by_ns = {}
    for cap in caps:
        ns = cap["ns"]
        by_ns.setdefault(ns, []).append(cap)
    for ns, ns_caps in by_ns.items():
        ns_dir = ns.replace("::", "/")
        for cap in ns_caps:
            lines.append(f'#include "{cap["name"]}.hpp"')
    lines.append("")
    lines.append("namespace rawrxd::runtime {")
    lines.append("")
    lines.append("void registerAllGeneratedCapabilities(RuntimeRegistry& registry) {")
    for cap in caps:
        name = cap["name"]
        ns = cap["ns"]
        lines.append(f"    registry.registerCapability(std::make_unique<{ns}::{name}>());")
    lines.append("}")
    lines.append("")
    lines.append("} // namespace rawrxd::runtime")
    lines.append("")
    return "\n".join(lines)


def generate_cmake(caps):
    """Generate RuntimeCapabilityCMake.cmake — source list for CMake."""
    lines = []
    lines.append("# ============================================================================")
    lines.append("# RuntimeCapabilityCMake.cmake — Generated source list")
    lines.append("# ============================================================================")
    lines.append("")
    lines.append("set(RAWRXD_OS_RUNTIME_GENERATED_SOURCES")
    for cap in caps:
        name = cap["name"]
        lines.append(f'    "${{CMAKE_CURRENT_SOURCE_DIR}}/generated/{name}.cpp"')
    lines.append('    "${CMAKE_CURRENT_SOURCE_DIR}}/RuntimeKernel.cpp"')
    lines.append('    "${CMAKE_CURRENT_SOURCE_DIR}}/WindowsEmitter.cpp"')
    lines.append('    "${CMAKE_CURRENT_SOURCE_DIR}}/RuntimeCapabilityRegistration.cpp"')
    lines.append(")")
    lines.append("")
    lines.append("set(RAWRXD_OS_RUNTIME_GENERATED_HEADERS")
    for cap in caps:
        name = cap["name"]
        lines.append(f'    "${{CMAKE_CURRENT_SOURCE_DIR}}/generated/{name}.hpp"')
    lines.append('    "${CMAKE_CURRENT_SOURCE_DIR}}/RuntimeCapabilityIds.hpp"')
    lines.append('    "${CMAKE_CURRENT_SOURCE_DIR}}/RuntimeCapabilityForward.hpp"')
    lines.append(")")
    lines.append("")
    return "\n".join(lines)


def main():
    caps = load_manifest()
    print(f"Loaded {len(caps)} capabilities from manifest")

    GEN_DIR.mkdir(parents=True, exist_ok=True)

    # Generate individual headers and implementations
    for i, cap in enumerate(caps):
        # The enum name is assigned during generate_ids_header; call it first.
        pass
    # Pre-assign enum names so impl generation can use them
    seen = {}
    for i, cap in enumerate(caps):
        base = make_capid(cap)
        enum_name = base
        if enum_name in seen:
            n = 2
            while f"{base}_{n}" in seen:
                n += 1
            enum_name = f"{base}_{n}"
        seen[enum_name] = i
        cap["_enum_name"] = enum_name
        cap["id_expr"] = f"rawrxd::runtime::CapabilityIds::{enum_name}"

        header = generate_header(cap)
        impl = generate_impl(cap)

        hpath = GEN_DIR / f"{cap['name']}.hpp"
        cpath = GEN_DIR / f"{cap['name']}.cpp"
        hpath.write_text(header, encoding="utf-8")
        cpath.write_text(impl, encoding="utf-8")

    # Generate ID table
    (BASE / "RuntimeCapabilityIds.hpp").write_text(
        generate_ids_header(caps), encoding="utf-8")

    # Generate forward declarations
    (BASE / "RuntimeCapabilityForward.hpp").write_text(
        generate_forward_header(caps), encoding="utf-8")

    # Generate registration
    (BASE / "RuntimeCapabilityRegistration.cpp").write_text(
        generate_registration(caps), encoding="utf-8")

    # Generate CMake
    (BASE / "RuntimeCapabilityCMake.cmake").write_text(
        generate_cmake(caps), encoding="utf-8")

    print(f"Generated {len(caps)*2} files in {GEN_DIR}")
    print(f"Generated RuntimeCapabilityIds.hpp ({len(caps)} IDs)")
    print(f"Generated RuntimeCapabilityForward.hpp")
    print(f"Generated RuntimeCapabilityRegistration.cpp")
    print(f"Generated RuntimeCapabilityCMake.cmake")

    # Summary by namespace
    by_ns = {}
    for cap in caps:
        ns = cap["ns"]
        by_ns.setdefault(ns, 0)
        by_ns[ns] += 1
    print("\nCapabilities by namespace:")
    for ns, count in sorted(by_ns.items()):
        print(f"  {ns}: {count}")


if __name__ == "__main__":
    main()