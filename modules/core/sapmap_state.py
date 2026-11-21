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
import sys
import traceback
from datetime import datetime
from pathlib import Path

from sapmap_models import SAPMAPState

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Silent-wipe detection (issue #217)
#
# A pentest in 2026-11 lost a looted-PSE wallet entry + forged-ticket bundles
# between two consecutive autosaves with no operator action.  Code inspection
# could not find a single call site that explicitly wipes the wallet, so a
# future-proof defence is to make a destructive diff IMPOSSIBLE to miss:
# before overwriting state to disk, compare the new state to the MOST RECENT
# prior autosave.  On populated → empty regression for the fields flagged in
# #217 (snc_credentials, forged_tickets), write a ``.WIPE_TRACE_<ts>.txt``
# beside the new file carrying the stack trace at save-time + the per-field
# diff, and emit a loud stderr banner.  Non-blocking — the operator may have a
# legitimate reason to clear them; the trace file is diagnostic, not a veto.
#
# Scope is narrow on purpose: only #137-wallet + MYSAPSSO2 forgery loot.
# Both are hard-won loot that has triggered the historical silent-wipe.
# Node-level fields (``node.sapsys_cert_issuer_dn``, ``node.forged_tickets``)
# are covered implicitly via the global ``state.forged_tickets`` list the
# forge chain mirrors into.
# ---------------------------------------------------------------------------

# Field names in state.to_dict() that are tracked for silent-wipe detection.
# Each value here is a count; the detector fires when a value was >0 in the
# most-recent prior autosave and is now 0 in the pending save.
_WIPE_TRACKED_FIELDS = ("snc_credentials", "forged_tickets")

# Project root — this file now lives in modules/core/, so climb two
# directory levels to reach the SAPMAP project root.  All session
# artefacts (state, loot) hang off here so that moving Python modules
# around doesn't relocate user data.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

# Default state directory
STATE_DIR = os.path.join(PROJECT_ROOT, "states")
RFC_CACHE_FILE = os.path.join(STATE_DIR, ".sapmap_rfc_cache.json")
DEST_LOG_FILE = os.path.join(STATE_DIR, ".sapmap_created_destinations.json")

# Default loot directory — separate from state files. Contains downloaded
# secrets, hashes, table dumps, BIA exports etc., organized by category
# subdirectory.  Already excluded by .gitignore.
LOOT_DIR = os.path.join(PROJECT_ROOT, "loot")
LOOT_SECSTORE_DIR = os.path.join(LOOT_DIR, "secstore")
LOOT_HASHES_DIR = os.path.join(LOOT_DIR, "hashes")
LOOT_TABLES_DIR = os.path.join(LOOT_DIR, "tables")
LOOT_BIA_DIR = os.path.join(LOOT_DIR, "bia")


def _ensure_state_dir():
    """Create states directory if it doesn't exist."""
    os.makedirs(STATE_DIR, exist_ok=True)


def ensure_loot_dir(subdir: str = "") -> str:
    """Create the loot directory (and optional subdir) and return its path.

    Pass subdir="hashes", "secstore", "tables", "bia" or any custom name.
    """
    target = os.path.join(LOOT_DIR, subdir) if subdir else LOOT_DIR
    os.makedirs(target, exist_ok=True)
    return target


def _tracked_field_counts(payload: dict) -> dict:
    """Return {field_name: count} for every #217-tracked field on a
    state payload (the dict produced by ``state.to_dict()``).

    Handles the dict-shaped (``snc_credentials``) and list-shaped
    (``forged_tickets``) variants.  Unknown / missing fields count as 0
    so a schema older than #137 compares cleanly against a current save.
    """
    counts: dict = {}
    for name in _WIPE_TRACKED_FIELDS:
        v = payload.get(name)
        if isinstance(v, dict):
            counts[name] = len(v)
        elif isinstance(v, list):
            counts[name] = len(v)
        else:
            counts[name] = 0
    return counts


def _most_recent_autosave(state_dir: str, exclude_path: str = "") -> str:
    """Return the full path of the most-recent prior .sapmap under
    ``state_dir`` (excluding ``exclude_path`` — the file we're about to
    write), or ``""`` when there is none.

    The glob is cheap: a typical states/ directory holds a handful of
    autosaves per engagement.  Sorted by mtime so a non-autosave file
    (operator-named save) is still picked up when it's the newest.
    """
    try:
        if not os.path.isdir(state_dir):
            return ""
        exclude_abs = os.path.abspath(exclude_path) if exclude_path else ""
        candidates = []
        for f in Path(state_dir).glob("*.sapmap"):
            try:
                abs_f = os.path.abspath(str(f))
                if abs_f == exclude_abs:
                    continue
                candidates.append((f.stat().st_mtime, abs_f))
            except Exception:
                continue
        if not candidates:
            return ""
        candidates.sort(reverse=True)
        return candidates[0][1]
    except Exception:
        return ""


def _load_prior_counts(prior_path: str) -> dict:
    """Read just the tracked field counts off the most-recent prior
    .sapmap.  Returns ``{}`` on any read / parse failure — detection
    silently stays off rather than blocking the save.
    """
    if not prior_path or not os.path.isfile(prior_path):
        return {}
    try:
        with open(prior_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {}
        return _tracked_field_counts(data)
    except Exception as e:
        logger.debug(f"Could not read prior autosave for wipe detection: {e}")
        return {}


def _check_for_silent_wipe(filepath: str,
                           prior_path: str,
                           prior_counts: dict,
                           new_counts: dict,
                           caller_stack: str) -> str:
    """When a tracked field went populated → empty between ``prior_path``
    and the save about to land at ``filepath``, drop a stack-trace file
    beside it and print a stderr banner.  Returns the trace path or ``""``
    when nothing fired.

    Non-blocking: the save still completes.  The trace file is the forensic
    hook #217 asked for — operators attach it to the bug report so the
    code path that wiped the wallet / forged tickets can be fixed.
    """
    wiped = []
    for name in _WIPE_TRACKED_FIELDS:
        before = prior_counts.get(name, 0)
        after = new_counts.get(name, 0)
        if before > 0 and after == 0:
            wiped.append((name, before, after))
    if not wiped:
        return ""

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    # Place the trace file beside the save we're about to write, so an
    # operator who spots the regression after the fact finds the diagnostic
    # next to the file whose contents surprised them.  `.WIPE_TRACE` is a
    # distinctive suffix so `rsync --delete` and autosave-prune scripts
    # never catch it by mistake.
    trace_path = f"{filepath}.WIPE_TRACE_{ts}.txt"

    lines = []
    lines.append(
        "SAPMAP silent-wipe detection (issue #217)\n"
        "=========================================\n"
    )
    lines.append(f"Save target     : {filepath}\n")
    lines.append(f"Prior autosave  : {prior_path}\n")
    lines.append(f"Detected at     : {datetime.now().isoformat()}\n\n")
    lines.append("Tracked-field regression (populated → empty):\n")
    for name, before, after in wiped:
        lines.append(f"  - {name:<20}  {before}  ->  {after}\n")
    lines.append("\nSave-time stack trace:\n")
    lines.append(caller_stack)
    lines.append(
        "\nWhat to do:\n"
        "  1. Restore the loot by loading the prior autosave listed above.\n"
        "  2. Attach THIS file to the SAPMAP GitHub issue (#217) so the\n"
        "     code path that wiped the fields can be fixed upstream.\n"
        "  3. The save still completed — this trace is diagnostic, not a veto.\n"
    )
    try:
        with open(trace_path, "w", encoding="utf-8") as f:
            f.writelines(lines)
    except Exception as e:
        logger.warning(f"Could not write silent-wipe trace: {e}")
        return ""

    # Loud banner — stderr so it's unmissable in a terminal log.
    banner = (
        "\n"
        "============================================================\n"
        "  [!] SAPMAP silent-wipe detected (issue #217)\n"
        "      " + ", ".join(
            f"{n}: {b}->{a}" for n, b, a in wiped) + "\n"
        f"      trace: {trace_path}\n"
        "============================================================\n"
    )
    try:
        print(banner, file=sys.stderr)
    except Exception:
        pass
    logger.warning(banner.strip())
    return trace_path


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

        # Snapshot live findings alongside state so the banner/drawer/bell
        # history survives a reopen.  Stored as a top-level field rather
        # than inside SAPMAPState to keep the existing dataclass clean.
        import json as _json
        payload = _json.loads(state.to_json())
        try:
            import sapmap_findings as _sf
            payload["_findings"] = _sf.snapshot()
        except Exception:
            pass

        # #217 silent-wipe detection — compare the incoming state's
        # tracked-field counts against the most-recent prior autosave.
        # Runs BEFORE the write so the trace is anchored to the moment we
        # noticed the regression, not a later probe.  Capturing the stack
        # here (via traceback.format_stack()) also pins down WHICH caller
        # drove the save, which is the forensic signal the issue asked
        # for.
        try:
            prior_path = _most_recent_autosave(
                os.path.dirname(filepath) or STATE_DIR, exclude_path=filepath)
            prior_counts = _load_prior_counts(prior_path)
            if prior_counts:
                new_counts = _tracked_field_counts(payload)
                caller_stack = "".join(traceback.format_stack())
                _check_for_silent_wipe(
                    filepath, prior_path, prior_counts, new_counts,
                    caller_stack)
        except Exception as _e:
            logger.debug(f"Silent-wipe detection skipped: {_e}")

        with open(filepath, "w", encoding="utf-8") as f:
            _json.dump(payload, f, indent=2)

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

        # Restore findings bus so the drawer repopulates after reload.
        if isinstance(data, dict) and data.get("_findings"):
            try:
                import sapmap_findings as _sf
                _sf.load_snapshot(data["_findings"])
            except Exception as _e:
                logger.warning(f"Could not restore findings snapshot: {_e}")

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
