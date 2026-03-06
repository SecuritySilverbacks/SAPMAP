#!/usr/bin/env python3
"""
SAPMAP State Management — Save/load session state to JSON files.

Handles persistence of the full SAPMAP state including nodes, connections,
created users, RFC check cache, and scan configuration.
The RFC check cache persists across sessions to prevent user lockouts.
"""

import json
import os
import logging
from datetime import datetime
from pathlib import Path

from sapmap_models import SAPMAPState

logger = logging.getLogger(__name__)

# Default state directory
STATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "states")
RFC_CACHE_FILE = os.path.join(STATE_DIR, ".sapmap_rfc_cache.json")
DEST_LOG_FILE = os.path.join(STATE_DIR, ".sapmap_created_destinations.json")


def _ensure_state_dir():
    """Create states directory if it doesn't exist."""
    os.makedirs(STATE_DIR, exist_ok=True)


def save_state(state: SAPMAPState, filepath: str) -> str:
    """Save full SAPMAP state to a JSON file.

    Args:
        state: The SAPMAPState to save.
        filepath: Target file path. If no extension, '.sapmap' is appended.

    Returns:
        The actual filepath used.
    """
    if not filepath.endswith(".sapmap") and not filepath.endswith(".json"):
        filepath += ".sapmap"

    state.timestamp = datetime.now().isoformat()

    try:
        parent = os.path.dirname(filepath)
        if parent:
            os.makedirs(parent, exist_ok=True)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(state.to_json(indent=2))

        logger.info(f"State saved to {filepath}")
        print(f"[+] State saved to {filepath}")

        # Also persist the RFC check cache separately
        _save_rfc_cache(state.rfc_check_cache)

        return filepath
    except Exception as e:
        logger.error(f"Failed to save state: {e}")
        print(f"[-] Failed to save state: {e}")
        raise


def load_state(filepath: str) -> SAPMAPState:
    """Load SAPMAP state from a JSON file.

    Args:
        filepath: Path to the .sapmap or .json file.

    Returns:
        Restored SAPMAPState.
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        state = SAPMAPState.from_dict(data)

        # Merge persistent RFC cache (the saved one might be newer)
        persistent_cache = _load_rfc_cache()
        for k, v in persistent_cache.items():
            if k not in state.rfc_check_cache:
                state.rfc_check_cache[k] = v

        stats = state.stats()
        logger.info(f"State loaded from {filepath}: "
                     f"{stats['systems']} systems, {stats['connections']} connections")
        print(f"[+] State loaded from {filepath}")
        print(f"    Systems: {stats['systems']}, Connections: {stats['connections']}, "
              f"Pwned: {stats['pwned']}, Users: {stats['users_created']}")

        return state
    except FileNotFoundError:
        logger.error(f"State file not found: {filepath}")
        print(f"[-] State file not found: {filepath}")
        raise
    except Exception as e:
        logger.error(f"Failed to load state: {e}")
        print(f"[-] Failed to load state: {e}")
        raise


# ---------------------------------------------------------------------------
# Persistent RFC check cache (survives across sessions)
# ---------------------------------------------------------------------------

def _save_rfc_cache(cache: dict) -> None:
    """Save the RFC check cache to a persistent file."""
    _ensure_state_dir()
    try:
        with open(RFC_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump({
                "updated": datetime.now().isoformat(),
                "cache": cache,
            }, f, indent=2, default=str)
    except Exception as e:
        logger.warning(f"Could not persist RFC cache: {e}")


def _load_rfc_cache() -> dict:
    """Load the persistent RFC check cache."""
    try:
        if os.path.exists(RFC_CACHE_FILE):
            with open(RFC_CACHE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data.get("cache", {})
    except Exception as e:
        logger.warning(f"Could not load RFC cache: {e}")
    return {}


def load_rfc_cache_into(state: SAPMAPState) -> None:
    """Load the persistent RFC cache into a state object."""
    cache = _load_rfc_cache()
    for k, v in cache.items():
        if k not in state.rfc_check_cache:
            state.rfc_check_cache[k] = v
    if cache:
        logger.info(f"Loaded {len(cache)} entries from persistent RFC check cache")
        print(f"[*] Loaded {len(cache)} RFC check cache entries from previous sessions")


def reset_rfc_cache(state: SAPMAPState) -> None:
    """Explicitly reset the global RFC check cache (both in-memory and on disk)."""
    state.reset_rfc_cache()
    try:
        if os.path.exists(RFC_CACHE_FILE):
            os.remove(RFC_CACHE_FILE)
        logger.info("RFC check cache reset")
        print("[+] RFC check cache has been reset")
    except Exception as e:
        logger.warning(f"Could not remove RFC cache file: {e}")


# ---------------------------------------------------------------------------
# Persistent created TCP/IP destinations log (survives across sessions)
# ---------------------------------------------------------------------------

def save_created_destination(entry: dict) -> None:
    """Append a created TCP/IP destination to the persistent log."""
    _ensure_state_dir()
    try:
        dests = _load_dest_log()
        dests.append(entry)
        with open(DEST_LOG_FILE, "w", encoding="utf-8") as f:
            json.dump(dests, f, indent=2, default=str)
    except Exception as e:
        logger.warning(f"Could not persist destination log: {e}")


def _load_dest_log() -> list:
    """Load the persistent created destinations log."""
    try:
        if os.path.exists(DEST_LOG_FILE):
            with open(DEST_LOG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                return data
    except Exception as e:
        logger.warning(f"Could not load destination log: {e}")
    return []


def load_created_destinations_into(state: SAPMAPState) -> None:
    """Load the persistent destinations log into a state object."""
    dests = _load_dest_log()
    existing = {d["dest_name"] for d in state.created_destinations}
    for d in dests:
        if d.get("dest_name") not in existing:
            state.created_destinations.append(d)
    if dests:
        logger.info(f"Loaded {len(dests)} entries from persistent destinations log")
        print(f"[*] Loaded {len(state.created_destinations)} created TCP/IP destination(s) from previous sessions")


def clear_created_destinations(state: SAPMAPState) -> None:
    """Clear the created destinations list (both in-memory and on disk)."""
    state.created_destinations.clear()
    try:
        if os.path.exists(DEST_LOG_FILE):
            os.remove(DEST_LOG_FILE)
        print("[+] Created TCP/IP destinations list has been cleared")
    except Exception as e:
        logger.warning(f"Could not remove destinations log file: {e}")


def auto_save_path() -> str:
    """Generate an auto-save file path based on timestamp."""
    _ensure_state_dir()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return os.path.join(STATE_DIR, f"sapmap_autosave_{ts}.sapmap")


def list_saved_states() -> list:
    """List all saved state files in the states directory."""
    _ensure_state_dir()
    files = []
    for f in sorted(Path(STATE_DIR).glob("*.sapmap"), reverse=True):
        try:
            stat = f.stat()
            files.append({
                "path": str(f),
                "name": f.name,
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            })
        except Exception:
            pass
    return files
