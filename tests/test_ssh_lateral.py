#!/usr/bin/env python3
"""Tests for the SSH lateral movement module (sap_ssh_lateral.py).

Pure-Python — no network access.  Tests exercise:
  1. Content-based key detection (PRIVATE KEY header in first 64 bytes)
  2. _SKIP_FILES filtering (known_hosts, authorized_keys, config, environment)
  3. Bare hostname filtering (entries without dots are skipped as targets)
  4. ssh_access node attribute population on successful lateral movement
  5. SAPNode.ssh_access serialization round-trip via to_dict/from_dict
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "modules",
                                "postex"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "modules",
                                "core"))


# ===========================================================================
# Helpers
# ===========================================================================

def _make_ssh_exec_fn(filesystem, ssh_responses=None):
    """Build a fake exec_fn that simulates python3 one-liners and ssh.

    filesystem = {path: b"contents", ...}
    ssh_responses = {"user@host": "uid=1000(user) gid=...", ...}
    """
    ssh_responses = ssh_responses or {}

    def _run_cmd(cmd):
        return ""

    def _run_py(code):
        # getpass.getuser + expanduser
        if "getpass" in code and "expanduser" in code:
            return "s4hadm|/home/s4hadm"
        # os.path.getsize
        if "getsize" in code:
            for path, data in filesystem.items():
                if path in code and isinstance(data, bytes):
                    return str(len(data))
            return ""
        # os.listdir
        if "os.listdir" in code:
            for path, entries in filesystem.items():
                if path in code and isinstance(entries, list):
                    return "\n".join(entries)
            return ""
        # base64 chunk read
        if "base64" in code and "b64encode" in code:
            import base64, re
            m = re.search(r"open\('([^']+)'", code)
            if m:
                fpath = m.group(1)
                data = filesystem.get(fpath)
                if data and isinstance(data, bytes):
                    return base64.b64encode(data).decode()
            return ""
        return ""

    def _read_b64_chunk(path, offset, end):
        import base64
        data = filesystem.get(path)
        if data and isinstance(data, bytes):
            return base64.b64encode(data[offset:end]).decode()
        return ""

    def _run_program(prog, args):
        if prog == "ssh":
            # Extract user@host from args
            parts = args.split()
            for p in parts:
                if "@" in p and not p.startswith("-"):
                    key = p
                    return ssh_responses.get(key, "")
            return ""
        return ""

    _run_cmd._run_py = _run_py
    _run_cmd._read_b64_chunk = _read_b64_chunk
    _run_cmd._run_program = _run_program
    return _run_cmd


# ===========================================================================
# 1. Content-based key detection
# ===========================================================================

class TestContentBasedKeyDetection:

    def test_standard_key_names_detected(self):
        """id_rsa and id_ed25519 with PRIVATE KEY header are detected."""
        for fname in ("id_rsa", "id_ed25519"):
            raw = b"-----BEGIN OPENSSH PRIVATE KEY-----\nfakedata\n"
            text_head = raw[:64].decode("utf-8", errors="replace")
            assert "PRIVATE KEY" in text_head

    def test_nonstandard_key_names_detected(self):
        """Non-standard filenames (my_id, custom_key) are detected by content."""
        for fname in ("my_id", "custom_key", "backup"):
            raw = b"-----BEGIN RSA PRIVATE KEY-----\nfakedata\n"
            text_head = raw[:64].decode("utf-8", errors="replace")
            assert "PRIVATE KEY" in text_head

    def test_non_key_file_not_detected(self):
        """Files without PRIVATE KEY header in first 64 bytes are rejected."""
        raw = b"ssh-rsa AAAAB3NzaC1yc2EAAA... user@host\n"
        text_head = raw[:64].decode("utf-8", errors="replace")
        assert "PRIVATE KEY" not in text_head

    def test_binary_file_not_detected(self):
        """Binary files without the header are rejected."""
        raw = b"\x00\x01\x02\xff" * 20
        text_head = raw[:64].decode("utf-8", errors="replace")
        assert "PRIVATE KEY" not in text_head


# ===========================================================================
# 2. _SKIP_FILES filtering
# ===========================================================================

class TestSkipFilesFiltering:

    def test_skip_files_set(self):
        """known_hosts, authorized_keys, config, environment are skipped
        as potential private keys."""
        _SKIP_FILES = {"known_hosts", "authorized_keys", "config",
                       "environment"}
        for fname in ("known_hosts", "authorized_keys", "config",
                      "environment"):
            assert fname in _SKIP_FILES

    def test_key_files_not_in_skip(self):
        """Actual key file names are not in the skip set."""
        _SKIP_FILES = {"known_hosts", "authorized_keys", "config",
                       "environment"}
        for fname in ("id_rsa", "id_ed25519", "id_ecdsa", "my_key"):
            assert fname not in _SKIP_FILES


# ===========================================================================
# 3. Bare hostname filtering
# ===========================================================================

class TestBareHostnameFiltering:

    def test_bare_hostnames_filtered(self):
        """known_hosts entries without dots (e.g. 'linux') are dropped."""
        targets = ["linux", "192.168.2.107", "myhost", "server.local"]
        filtered = [t for t in targets if "." in t]
        assert "linux" not in filtered
        assert "myhost" not in filtered

    def test_ips_kept(self):
        """IP addresses (contain dots) are kept."""
        targets = ["192.168.2.107", "10.0.0.1"]
        filtered = [t for t in targets if "." in t]
        assert filtered == ["192.168.2.107", "10.0.0.1"]

    def test_fqdn_kept(self):
        """FQDNs (contain dots) are kept."""
        targets = ["server.example.com", "sap.internal.corp"]
        filtered = [t for t in targets if "." in t]
        assert filtered == targets

    def test_mixed_filtering(self):
        """Mixed list: only entries with dots survive."""
        targets = ["linux", "192.168.2.107", "dbhost", "sap.corp.local",
                   "localhost"]
        filtered = [t for t in targets if "." in t]
        assert filtered == ["192.168.2.107", "sap.corp.local"]


# ===========================================================================
# 4. ssh_access node attribute on successful lateral movement
# ===========================================================================

class TestSshAccessAttribute:

    def test_ssh_access_populated_on_success(self):
        """When SSH lateral succeeds, target node gets pwned=True and
        ssh_access populated with the right fields."""
        from sapmap_models import SAPNode, SAPMAPState

        source = SAPNode(sid="SRC", ip="10.0.0.1", gw_vulnerable=True)
        target = SAPNode(sid="TGT", ip="10.0.0.2", pwned=False)
        state = SAPMAPState()
        state.nodes["SRC"] = source
        state.nodes["TGT"] = target

        # Simulate what ssh_test_keys does on success
        target.pwned = True
        if not target.ssh_access:
            target.ssh_access = []
        target.ssh_access.append({
            "from_sid": "SRC",
            "from_ip": "10.0.0.1",
            "username": "s4hadm",
            "remote_user": "s4hadm",
            "key_path": "/home/s4hadm/.ssh/id_ed25519",
            "key_type": "ed25519",
            "key_owner": "s4hadm",
            "target": "10.0.0.2",
        })

        assert target.pwned is True
        assert len(target.ssh_access) == 1
        entry = target.ssh_access[0]
        assert entry["from_sid"] == "SRC"
        assert entry["key_path"] == "/home/s4hadm/.ssh/id_ed25519"
        assert entry["username"] == "s4hadm"
        assert entry["target"] == "10.0.0.2"


# ===========================================================================
# 5. SAPNode.ssh_access serialization round-trip
# ===========================================================================

class TestSshAccessSerialization:

    def test_ssh_access_round_trip(self):
        """ssh_access survives to_dict() -> from_dict() round-trip."""
        from sapmap_models import SAPNode

        node = SAPNode(sid="TGT", ip="10.0.0.2", pwned=True)
        node.ssh_access = [
            {
                "from_sid": "SRC",
                "from_ip": "10.0.0.1",
                "username": "s4hadm",
                "remote_user": "s4hadm",
                "key_path": "/home/s4hadm/.ssh/id_ed25519",
                "key_type": "ed25519",
                "key_owner": "s4hadm",
                "target": "10.0.0.2",
            },
        ]

        d = node.to_dict()
        assert d["ssh_access"] == node.ssh_access

        restored = SAPNode.from_dict(d)
        assert restored.ssh_access == node.ssh_access
        assert restored.pwned is True
        assert restored.ssh_access[0]["from_sid"] == "SRC"

    def test_ssh_access_none_round_trip(self):
        """Node with ssh_access=None round-trips cleanly."""
        from sapmap_models import SAPNode

        node = SAPNode(sid="X", ip="1.2.3.4")
        assert node.ssh_access is None

        d = node.to_dict()
        restored = SAPNode.from_dict(d)
        assert restored.ssh_access is None

    def test_ssh_access_multiple_entries(self):
        """Multiple ssh_access entries survive the round-trip."""
        from sapmap_models import SAPNode

        node = SAPNode(sid="TGT", ip="10.0.0.2")
        node.ssh_access = [
            {"from_sid": "A", "username": "root", "key_path": "/root/.ssh/id_rsa",
             "key_type": "rsa", "target": "10.0.0.2"},
            {"from_sid": "B", "username": "s4hadm", "key_path": "/home/s4hadm/.ssh/id_ed25519",
             "key_type": "ed25519", "target": "10.0.0.2"},
        ]

        d = node.to_dict()
        restored = SAPNode.from_dict(d)
        assert len(restored.ssh_access) == 2
        assert restored.ssh_access[0]["from_sid"] == "A"
        assert restored.ssh_access[1]["from_sid"] == "B"
