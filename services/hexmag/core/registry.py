from __future__ import annotations

import importlib
import sys
from pathlib import Path
from typing import List

from core.contracts import Bot


def _bots_dir() -> Path:
    """Locate the bots/ package relative to this file (never the CWD)."""
    # core/registry.py -> hexmag/ -> bots/
    bots_dir = Path(__file__).resolve().parent.parent / "bots"
    if not bots_dir.is_dir():
        raise FileNotFoundError(f"bots package not found at {bots_dir}")
    return bots_dir


def load_bots() -> List[Bot]:
    """Dynamically load Bot implementations located under the bots/ package."""
    bots: List[Bot] = []
    bots_dir = _bots_dir()
    package_parent = bots_dir.parent
    if str(package_parent) not in sys.path:
        sys.path.insert(0, str(package_parent))

    for module_path in sorted(bots_dir.glob("*.py")):
        name = module_path.stem
        if name.startswith("_"):
            continue
        try:
            module = importlib.import_module(f"bots.{name}")
        except Exception as exc:  # a broken bot is loud, not silent
            print(f"Warning: failed to import bots.{name}: {exc}")
            continue

        for attr_name in dir(module):
            obj = getattr(module, attr_name)
            try:
                if isinstance(obj, type) and issubclass(obj, Bot) and obj is not Bot:
                    bots.append(obj())
                    break
            except Exception:
                continue
    return bots
