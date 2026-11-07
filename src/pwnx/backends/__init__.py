"""Replaceable implementation backends for technique and adapter authors."""

from __future__ import annotations

from importlib import import_module
from types import ModuleType

__all__ = [
    "diagnostics", "integrations", "memory", "rop", "toolchain", "transports",
]


def __getattr__(name: str) -> ModuleType:
    if name not in __all__:
        raise AttributeError(name)
    module = import_module(f"{__name__}.{name}")
    globals()[name] = module
    return module
