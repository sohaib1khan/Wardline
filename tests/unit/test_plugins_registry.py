"""Plugin registry discovery tests."""

from __future__ import annotations

from wardline.plugins.base import PluginRegistry, discover_plugins, get_registry
from wardline.plugins.dummy import DummyPlugin


def test_discover_finds_dummy() -> None:
    registry = PluginRegistry()
    discover_plugins(registry)
    assert "dummy" in registry
    plugin = registry.get("dummy")
    assert isinstance(plugin, DummyPlugin)
    assert plugin.hidden is True


def test_list_hides_hidden_by_default() -> None:
    registry = get_registry(refresh=True)
    visible = registry.names(include_hidden=False)
    all_names = registry.names(include_hidden=True)
    assert "dummy" not in visible
    assert "dummy" in all_names
