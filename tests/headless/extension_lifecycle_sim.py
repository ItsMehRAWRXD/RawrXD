#!/usr/bin/env python3
"""Deterministic, dependency-free extension lifecycle simulator.

This is a TEST DOUBLE, not the RawrXD native extension runtime.
A PASS here certifies only the simulator contract, never Win32IDE/QuickJS.
"""
from dataclasses import dataclass
import json
from pathlib import Path
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
        with zipfile.ZipFile(archive) as z:
            names = z.namelist()
            if len(names) > 512 or len(set(names)) != len(names):
                raise ExtensionError("unsafe archive entries")
            for item in z.infolist():
                p = Path(item.filename.replace("\\", "/"))
                if p.is_absolute() or ".." in p.parts or item.file_size > 8 * 1024 * 1024:
                    raise ExtensionError("unsafe archive path/size")
            if "extension/package.json" not in names:
                raise ExtensionError("missing extension manifest")
            return self.install_manifest(json.loads(z.read("extension/package.json")))

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
