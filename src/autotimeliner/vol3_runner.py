"""
vol3_runner.py
~~~~~~~~~~~~~~
Low-level wrapper around the Volatility 3 library API.

Key design decisions
--------------------
* Volatility3 is initialised **once** (module-level singleton) so that
  ``import_files`` is never called twice and the plugin registry is stable.
* Plugin classes are resolved through ``framework.list_plugins()`` (the
  official registry) rather than direct ``from volatility3.plugins.X import Y``
  statements.  Direct imports are unreliable when a plugin's own dependencies
  are missing (e.g. yara, PyCryptodome) because the module never ends up in
  sys.modules even after import_files succeeds globally.
* ``run_plugin()`` returns rows as a plain list of dicts — no subprocess, no
  shell expansion.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Callable, Optional, Type

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level initialisation (runs once per interpreter session)
# ---------------------------------------------------------------------------

_vol3_ready: bool = False
_plugin_list: dict[str, Type] = {}


def _ensure_vol3() -> None:
    """Raise a friendly ImportError if volatility3 is not installed."""
    try:
        import volatility3  # noqa: F401
    except ImportError as exc:
        raise ImportError(
            "volatility3 is not installed. "
            "Install it with:  pip install volatility3"
        ) from exc


def initialize_vol3() -> None:
    """Import and register all Volatility3 plugins (idempotent).

    Must be called before ``get_plugin_class()`` or ``run_plugin()``.
    Subsequent calls are no-ops.
    """
    global _vol3_ready, _plugin_list
    if _vol3_ready:
        return

    _ensure_vol3()

    import volatility3
    import volatility3.plugins
    import volatility3.framework as framework
    from volatility3.framework import constants

    framework.require_interface_version(2, 0, 0)

    # Extend the plugin search path (idempotent-safe: only add new entries)
    extra = list(constants.PLUGINS_PATH)
    existing = set(volatility3.plugins.__path__)
    volatility3.plugins.__path__ = list(volatility3.plugins.__path__) + [
        p for p in extra if p not in existing
    ]

    # Load all plugins; failures (missing yara, Crypto, …) are tolerated
    framework.import_files(volatility3.plugins, True)

    _plugin_list = framework.list_plugins()
    log.debug("Volatility3 initialised — %d plugins available", len(_plugin_list))
    _vol3_ready = True


def get_plugin_class(name: str) -> Optional[Type]:
    """Return a plugin class by its dotted Vol3 name, or None if not found.

    Examples of valid names: ``"timeliner.Timeliner"``,
    ``"windows.mftscan.MFTScan"``, ``"windows.shellbags.ShellBags"``.
    """
    initialize_vol3()

    # list_plugins() keys are fully-qualified module paths.  Try an exact match
    # first, then a suffix match so callers can use short names.
    if name in _plugin_list:
        return _plugin_list[name]

    # suffix match (e.g. "windows.mftscan.MFTScan" matches
    # "volatility3.plugins.windows.mftscan.MFTScan")
    suffix = "." + name
    for key, cls in _plugin_list.items():
        if key.endswith(suffix) or key == name:
            return cls

    log.warning("Plugin not found in Vol3 registry: %s", name)
    return None


# ---------------------------------------------------------------------------
# Plugin runner
# ---------------------------------------------------------------------------

def run_plugin(
    image_path: str | Path,
    plugin_class: Type,
    plugin_config: Optional[dict[str, Any]] = None,
    progress_callback: Optional[Callable[[float, str], None]] = None,
) -> list[dict[str, Any]]:
    """Run a Volatility3 plugin programmatically and return rows as a list of dicts.

    Parameters
    ----------
    image_path:
        Absolute path to the memory image file.
    plugin_class:
        The Volatility3 plugin *class* to run (resolved via ``get_plugin_class``).
    plugin_config:
        Optional dict of extra plugin-level config keys → values.
    progress_callback:
        Optional ``callable(percentage: float, description: str)`` called
        periodically during execution.

    Returns
    -------
    List of dicts, one per result row, with column names as keys.
    """
    initialize_vol3()

    import volatility3.framework as framework
    from volatility3.framework import contexts, automagic, plugins

    ctx = contexts.Context()
    base_config_path = "plugins"

    # Point the layer stacker at the image
    single_location = f"file://{Path(image_path).resolve()}"
    ctx.config["automagic.LayerStacker.single_location"] = single_location

    # Inject any plugin-specific overrides
    if plugin_config:
        prefix = f"{base_config_path}.{plugin_class.__name__}"
        for k, v in plugin_config.items():
            ctx.config[f"{prefix}.{k}"] = v

    log.debug("Running plugin %s on %s", plugin_class.__name__, image_path)

    available_automagics = automagic.available(ctx)

    constructed = plugins.construct_plugin(
        ctx,
        available_automagics,
        plugin_class,
        base_config_path,
        progress_callback,
        None,  # file_consumer — we don't need auxiliary files
    )

    treegrid = constructed.run()

    # Materialise the TreeGrid into a plain list of dicts
    column_names = [col.name for col in treegrid.columns]
    rows: list[dict[str, Any]] = []

    def _visitor(node, accumulator: list) -> list:
        accumulator.append(dict(zip(column_names, node.values)))
        return accumulator

    treegrid.populate(_visitor, rows)
    log.debug("Plugin %s returned %d rows", plugin_class.__name__, len(rows))
    return rows
