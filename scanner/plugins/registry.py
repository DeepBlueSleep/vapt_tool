from __future__ import annotations

from collections.abc import Iterable

from scanner.plugins.base import ScannerPlugin


class PluginRegistry:
    def __init__(self) -> None:
        self._plugins: dict[str, ScannerPlugin] = {}

    def register(self, plugin: ScannerPlugin) -> None:
        self._plugins[plugin.metadata.name] = plugin

    def plugins(self, *, include_active: bool = False) -> Iterable[ScannerPlugin]:
        for plugin in self._plugins.values():
            if plugin.metadata.active and not include_active:
                continue
            yield plugin
