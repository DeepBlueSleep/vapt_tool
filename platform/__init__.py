from __future__ import annotations

import importlib.util
import sysconfig
from pathlib import Path
from types import ModuleType


def _load_stdlib_platform() -> ModuleType | None:
    path = Path(sysconfig.get_path("stdlib")) / "platform.py"
    spec = importlib.util.spec_from_file_location("_stdlib_platform", path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_STDLIB_PLATFORM = _load_stdlib_platform()


def __getattr__(name: str) -> object:
    if _STDLIB_PLATFORM is not None and hasattr(_STDLIB_PLATFORM, name):
        return getattr(_STDLIB_PLATFORM, name)
    raise AttributeError(name)


__all__ = ["api", "auth", "dashboards", "database", "evidence", "exports", "reporting", "web"]
