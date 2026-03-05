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

import json
import logging
import os
import shutil
import tempfile
import urllib.request
import zipfile
from importlib import import_module
from pathlib import Path
from typing import Any, Callable, Optional, Type

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level initialisation (runs once per interpreter session)
# ---------------------------------------------------------------------------

_vol3_ready: bool = False
_plugin_list: dict[str, Type] = {}

REQUIRED_PLUGIN_MODULES: tuple[str, ...] = (
    "volatility3.plugins.timeliner",
    "volatility3.plugins.windows.mftscan",
    "volatility3.plugins.windows.shellbags",
    "volatility3.plugins.windows.info",
    "volatility3.plugins.linux.banners",
    "volatility3.plugins.linux.pslist",
    "volatility3.plugins.linux.bash",
    "volatility3.plugins.linux.lsof",
    "volatility3.plugins.mac.bash",
    "volatility3.plugins.mac.pslist",
    "volatility3.plugins.mac.lsof",
    # Additional Windows forensic plugins
    "volatility3.plugins.windows.psscan",
    "volatility3.plugins.windows.cmdline",
    "volatility3.plugins.windows.netscan",
    "volatility3.plugins.windows.registry.userassist",
    "volatility3.plugins.windows.dlllist",
    "volatility3.plugins.windows.svcscan",
    "volatility3.plugins.windows.filescan",
    "volatility3.plugins.windows.handles",
    "volatility3.plugins.windows.envars",
    "volatility3.plugins.windows.malfind",
)

SYMBOL_TABLE_URLS: dict[str, str] = {
    "windows": "https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip",
    "mac": "https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip",
    "linux": "https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip",
}

DEFAULT_SYMBOLS_DIR = Path.home() / ".cache" / "autotimeliner" / "volatility3" / "symbols"
PROFILE_CACHE_PATH = Path.home() / ".cache" / "autotimeliner" / "volatility3" / ".autotimeliner_profile_cache.json"


def _symbol_state_path(symbols_dir: Path) -> Path:
    return symbols_dir / ".autotimeliner_symbols.json"


def _read_profile_cache() -> dict[str, dict[str, Any]]:
    if not PROFILE_CACHE_PATH.exists():
        return {}
    try:
        raw = json.loads(PROFILE_CACHE_PATH.read_text(encoding="utf-8"))
        return raw if isinstance(raw, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def _write_profile_cache(data: dict[str, dict[str, Any]]) -> None:
    PROFILE_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_str = tempfile.mkstemp(
        dir=PROFILE_CACHE_PATH.parent,
        prefix=".autotimeliner_profile_cache.",
        suffix=".tmp",
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(data, indent=2, sort_keys=True))
            fh.flush()
            os.fsync(fh.fileno())
        Path(tmp_str).replace(PROFILE_CACHE_PATH)
    except Exception:
        try:
            os.unlink(tmp_str)
        except OSError:
            pass
        raise


def _profile_cache_key(image_path: str | Path) -> str:
    path = Path(image_path).resolve()
    try:
        stat = path.stat()
        return f"{path}|{stat.st_size}|{stat.st_mtime_ns}"
    except OSError:
        return str(path)


def _guess_os_from_filename(image_path: str | Path) -> Optional[str]:
    name = Path(image_path).name.lower()
    keyword_map = {
        "windows": ["windows", "win", "w10", "w11", "server", "memdump"],
        "linux": ["linux", "ubuntu", "debian", "kali", "centos", "rhel"],
        "mac": ["mac", "macos", "osx", "darwin"],
    }
    for family, keywords in keyword_map.items():
        if any(token in name for token in keywords):
            return family
    return None


def _build_probe_candidates(image_path: str | Path) -> list[tuple[str, list[str]]]:
    base: list[tuple[str, list[str]]] = [
        ("windows", ["windows.info.Info"]),
        ("linux", ["linux.banners.Banners", "linux.pslist.PsList"]),
        ("mac", ["mac.pslist.PsList", "mac.bash.Bash"]),
    ]
    guessed = _guess_os_from_filename(image_path)
    if not guessed:
        return base

    prioritized = [entry for entry in base if entry[0] == guessed]
    remaining = [entry for entry in base if entry[0] != guessed]
    return prioritized + remaining


def _read_symbol_state(symbols_dir: Path) -> dict[str, Any]:
    state_path = _symbol_state_path(symbols_dir)
    if not state_path.exists():
        return {}
    try:
        return json.loads(state_path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {}


def _write_symbol_state(symbols_dir: Path, state: dict[str, Any]) -> None:
    symbols_dir.mkdir(parents=True, exist_ok=True)
    state_path = _symbol_state_path(symbols_dir)
    fd, tmp_str = tempfile.mkstemp(
        dir=symbols_dir,
        prefix=".autotimeliner_symbols.",
        suffix=".tmp",
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(state, indent=2, sort_keys=True))
            fh.flush()
            os.fsync(fh.fileno())
        Path(tmp_str).replace(state_path)
    except Exception:
        try:
            os.unlink(tmp_str)
        except OSError:
            pass
        raise


def ensure_symbol_tables(symbols_dir: str | Path | None = None) -> Path:
    """Ensure Volatility3 symbol tables are available locally.

    Downloads and extracts Windows/macOS/Linux symbol archives from the
    Volatility Foundation mirror into ``symbols_dir`` (default:
    ``~/.cache/autotimeliner/volatility3/symbols``).
    """
    target_dir = Path(symbols_dir) if symbols_dir else DEFAULT_SYMBOLS_DIR
    target_dir.mkdir(parents=True, exist_ok=True)

    state = _read_symbol_state(target_dir)
    updated_state = dict(state)

    for family, url in SYMBOL_TABLE_URLS.items():
        archive_name = f"{family}.zip"
        archive_path = target_dir / archive_name
        family_state = state.get(family, {}) if isinstance(state.get(family), dict) else {}

        if family_state.get("source") == url and family_state.get("installed") is True:
            continue

        log.info("Downloading Volatility3 symbols: %s", url)
        with urllib.request.urlopen(url) as response, archive_path.open("wb") as out_file:
            shutil.copyfileobj(response, out_file)

        log.info("Installing Volatility3 symbols for %s", family)
        with zipfile.ZipFile(archive_path, "r") as zip_ref:
            zip_ref.extractall(target_dir)

        updated_state[family] = {
            "source": url,
            "archive": archive_name,
            "installed": True,
        }

    if updated_state != state:
        _write_symbol_state(target_dir, updated_state)

    return target_dir


def identify_memory_profile(image_path: str | Path, *, use_cache: bool = True) -> dict[str, Optional[str]]:
    """Best-effort memory profile identification for Volatility3.

    Volatility3 does not use Volatility2-style profiles. This helper probes
    lightweight OS-specific plugins to infer the memory image family and returns
    metadata that can be displayed to the user.
    """
    initialize_vol3()

    cache_key = _profile_cache_key(image_path)
    if use_cache:
        cache_data = _read_profile_cache()
        cached = cache_data.get(cache_key)
        if isinstance(cached, dict):
            cached_result = {
                "os": cached.get("os") or "unknown",
                "profile": cached.get("profile"),
                "probe_plugin": cached.get("probe_plugin"),
            }
            log.info(
                "Using cached OS identification: os=%s profile=%s probe=%s",
                cached_result["os"],
                cached_result["profile"] or "n/a",
                cached_result["probe_plugin"] or "n/a",
            )
            return cached_result

    candidates = _build_probe_candidates(image_path)
    guessed = _guess_os_from_filename(image_path)
    if guessed:
        log.info("OS probe order optimized from filename hint: %s", guessed)

    total_probes = sum(len(plugin_names) for _, plugin_names in candidates)
    log.info("Starting OS identification using %d probe plugins", total_probes)

    for os_family, plugin_names in candidates:
        for plugin_name in plugin_names:
            log.info("OS probe attempt: family=%s plugin=%s", os_family, plugin_name)
            log.debug("Profile probe attempt: os=%s plugin=%s", os_family, plugin_name)
            plugin_class = get_plugin_class(plugin_name)
            if plugin_class is None:
                log.info("OS probe skipped (plugin unavailable): %s", plugin_name)
                log.debug("Profile probe skipped (plugin unavailable): %s", plugin_name)
                continue

            try:
                rows = run_plugin(image_path=image_path, plugin_class=plugin_class)
            except Exception as exc:  # noqa: BLE001
                log.info("OS probe failed: %s (%s)", plugin_name, exc)
                log.debug("Profile probe %s failed: %s", plugin_name, exc)
                continue

            if not rows:
                log.info("OS probe returned no rows: %s", plugin_name)
                log.debug("Profile probe %s returned no rows", plugin_name)
                continue

            profile_hint: Optional[str] = None
            first = rows[0]
            if os_family == "windows":
                version = first.get("NTBuildLab") or first.get("BuildLab") or first.get("NtBuildLab")
                if version:
                    profile_hint = f"windows:{version}"
                else:
                    profile_hint = "windows"
            elif os_family == "linux":
                banner = first.get("Banner") or first.get("banner")
                profile_hint = f"linux:{banner}" if banner else "linux"
            elif os_family == "mac":
                profile_hint = "mac"

            result = {
                "os": os_family,
                "profile": profile_hint,
                "probe_plugin": plugin_name,
            }
            if use_cache:
                cache_data = _read_profile_cache()
                cache_data[cache_key] = result
                _write_profile_cache(cache_data)
            log.info(
                "Memory image identification succeeded: os=%s profile=%s probe=%s",
                result["os"],
                result["profile"] or "n/a",
                result["probe_plugin"] or "n/a",
            )
            return result

    log.warning("Memory image identification failed: unable to determine OS family")
    return {
        "os": "unknown",
        "profile": None,
        "probe_plugin": None,
    }


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

    # Ensure symbol packs are present and available to Volatility3
    symbols_dir = ensure_symbol_tables()
    symbol_path = str(symbols_dir)
    if hasattr(constants, "SYMBOL_BASEPATHS") and symbol_path not in constants.SYMBOL_BASEPATHS:
        constants.SYMBOL_BASEPATHS = [symbol_path, *list(constants.SYMBOL_BASEPATHS)]
    if hasattr(constants, "SYMBOL_PATHS") and symbol_path not in constants.SYMBOL_PATHS:
        constants.SYMBOL_PATHS = [symbol_path, *list(constants.SYMBOL_PATHS)]

    # Extend the plugin search path (idempotent-safe: only add new entries)
    extra = list(constants.PLUGINS_PATH)
    existing = set(volatility3.plugins.__path__)
    volatility3.plugins.__path__ = list(volatility3.plugins.__path__) + [
        p for p in extra if p not in existing
    ]

    # Load only plugin modules used by AutoTimeliner to avoid noisy optional
    # dependency warnings (e.g. yara-x / yara-python for YARA scan plugins).
    for module_name in REQUIRED_PLUGIN_MODULES:
        try:
            import_module(module_name)
        except Exception as exc:  # noqa: BLE001
            log.debug("Unable to import plugin module %s: %s", module_name, exc)

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

    # Use Volatility's automagic chooser to keep only automagics relevant to
    # the plugin category (windows/linux/mac), reducing unnecessary runs.
    selected_automagics = available_automagics
    try:
        selected_automagics = automagic.choose_automagic(available_automagics, plugin_class)
    except TypeError:
        # Compatibility fallback for alternate function signatures.
        try:
            selected_automagics = automagic.choose_automagic(plugin_class, available_automagics)
        except Exception as exc:  # noqa: BLE001
            log.debug("choose_automagic fallback failed: %s", exc)
            selected_automagics = available_automagics
    except Exception as exc:  # noqa: BLE001
        log.debug("choose_automagic failed, using full automagic list: %s", exc)
        selected_automagics = available_automagics

    if not selected_automagics:
        selected_automagics = available_automagics

    constructed = plugins.construct_plugin(
        ctx,
        selected_automagics,
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
