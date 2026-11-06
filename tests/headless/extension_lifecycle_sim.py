#!/usr/bin/env python3
"""Deterministic, dependency-free extension lifecycle simulator.

This is a TEST DOUBLE, not the RawrXD native extension runtime.
A PASS here certifies only the simulator contract, never Win32IDE/QuickJS.
"""
from dataclasses import dataclass
import json
from pathlib import PurePosixPath
import re
import zipfile

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

class ExtensionError(ValueError):
    pass

@dataclass
class Extension:
    identifier: str
    version: str
    active: bool = False

class SimulatedExtensionHost:
    def __init__(self):
        self.extensions = {}
        self.commands = {}
        self.events = []

    def install_manifest(self, manifest):
        if not isinstance(manifest, dict):
            raise ExtensionError("manifest must be object")
        publisher, name, version = (manifest.get(k) for k in ("publisher", "name", "version"))
        if not all(isinstance(v, str) and v for v in (publisher, name, version)):
            raise ExtensionError("publisher, name and version required")
        identifier = publisher + "." + name
        if not _ID.fullmatch(identifier) or not re.fullmatch(r"\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?", version):
            raise ExtensionError("invalid id/version")
        if identifier in self.extensions:
            raise ExtensionError("duplicate extension")
        self.extensions[identifier] = Extension(identifier, version)
        return identifier

    def install_vsix(self, archive):
        # Test-double validation only: this does not extract or execute VSIX code.
        with zipfile.ZipFile(archive) as z:
            entries = z.infolist()
            if len(entries) > 512:
                raise ExtensionError("too many archive entries")
            normalized = set()
            total_size = 0
            for item in entries:
                name = item.filename.replace("\\\\", "/")
                path = PurePosixPath(name)
                is_directory = name.endswith("/")
                checked_name = name[:-1] if is_directory else name
                # Treat Windows drive letters, UNC paths, and empty segments as unsafe
                # even when tests execute on a POSIX runner.
                if (not name or name.startswith("/") or name.startswith("//")
                        or ":" in name or any(part in ("", ".", "..") for part in checked_name.split("/"))):
                    raise ExtensionError("unsafe archive path")
                if checked_name.casefold() in normalized:
                    raise ExtensionError("duplicate archive entry")
                normalized.add(checked_name.casefold())
                if (item.external_attr >> 16) & 0o170000 == 0o120000:
                    raise ExtensionError("symlink archive entry")
                if item.file_size > 8 * 1024 * 1024:
                    raise ExtensionError("oversized archive entry")
                total_size += item.file_size
                if total_size > 32 * 1024 * 1024:
                    raise ExtensionError("oversized archive")
            if "extension/package.json" not in normalized:
                raise ExtensionError("missing extension manifest")
            manifest_info = next(i for i in entries if i.filename.casefold() == "extension/package.json")
            if manifest_info.file_size > 256 * 1024:
                raise ExtensionError("oversized manifest")
            try:
                manifest = json.loads(z.read(manifest_info).decode("utf-8"))
            except (UnicodeError, ValueError) as exc:
                raise ExtensionError("invalid manifest JSON") from exc
            return self.install_manifest(manifest)

    def activate(self, identifier):
        ext = self.extensions.get(identifier)
        if ext is None:
            raise ExtensionError("unknown extension")
        ext.active = True

    def deactivate(self, identifier):
        ext = self.extensions.get(identifier)
        if ext is None:
            raise ExtensionError("unknown extension")
        ext.active = False
        self.commands = {k: v for k, v in self.commands.items() if v[0] != identifier}

    def register_command(self, identifier, name, callback):
        if identifier not in self.extensions or not self.extensions[identifier].active:
            raise ExtensionError("extension not active")
        if name in self.commands:
            raise ExtensionError("duplicate command")
        self.commands[name] = (identifier, callback)

    def execute_command(self, name, *args):
        if name not in self.commands:
            raise ExtensionError("unknown command")
        return self.commands[name][1](*args)

    def fire_event(self, event, payload):
        self.events.append((event, payload))

    def uninstall(self, identifier):
        self.deactivate(identifier)
        del self.extensions[identifier]
