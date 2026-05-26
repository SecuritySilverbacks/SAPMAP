#!/usr/bin/env python3
"""Tests for MYSAPSSO2 ticket delivery artifacts (commit 6).

Tests the .sap shortcut writer, curl command builder, pyrfc kwargs
builder, and loot persistence — all pure-Python, no live SAP needed.
"""
from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..",
                                "modules", "exploitation"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..",
                                "modules", "core"))


# A fake base64 ticket for testing (doesn't need to be real)
FAKE_COOKIE_B64 = "AgQxMDMAAQAIUwBBAFAAKgACAAADAAMAUzRI"


# ===================================================================
# SAP GUI shortcut (.sap file)
# ===================================================================

class TestSapGuiShortcut:

    def test_basic_shortcut_structure(self):
        from sap_ticket_delivery import make_sapgui_shortcut
        content = make_sapgui_shortcut(
            server="prdhost.example.com", sysnr="00",
            client="100", sid="PRD",
            cookie_b64=FAKE_COOKIE_B64, user="SAP*")
        assert "[System]" in content
        assert "[User]" in content
        assert "[Function]" in content
        assert "[Configuration]" in content

    def test_shortcut_fields(self):
        from sap_ticket_delivery import make_sapgui_shortcut
        content = make_sapgui_shortcut(
            server="s4h.corp.local", sysnr="01",
            client="000", sid="S4H",
            cookie_b64=FAKE_COOKIE_B64, user="DDIC")
        assert "Server=s4h.corp.local" in content
        assert "SystemNumber=01" in content
        assert "Client=000" in content
        assert "Name=S4H" in content
        assert "Command=SU01" in content

    def test_at_value_url_encoded(self):
        """The at= line contains URL-encoded MYSAPSSO2=<b64>."""
        from sap_ticket_delivery import make_sapgui_shortcut
        content = make_sapgui_shortcut(
            server="host", sysnr="00", client="000",
            sid="S4H", cookie_b64=FAKE_COOKIE_B64)
        # Find the at= line
        at_line = [l for l in content.splitlines()
                   if l.startswith("at=")][0]
        at_value = at_line[3:]  # strip "at="
        # URL-decode and verify
        import urllib.parse
        decoded = urllib.parse.unquote(at_value)
        assert decoded.startswith("MYSAPSSO2=")
        assert FAKE_COOKIE_B64 in decoded

    def test_custom_tcode(self):
        from sap_ticket_delivery import make_sapgui_shortcut
        content = make_sapgui_shortcut(
            server="host", sysnr="00", client="000",
            sid="S4H", cookie_b64=FAKE_COOKIE_B64,
            tcode="se38")
        assert "Command=SE38" in content

    def test_sysnr_zero_padded(self):
        from sap_ticket_delivery import make_sapgui_shortcut
        content = make_sapgui_shortcut(
            server="host", sysnr="1", client="000",
            sid="S4H", cookie_b64=FAKE_COOKIE_B64)
        assert "SystemNumber=01" in content

    def test_client_zero_padded(self):
        from sap_ticket_delivery import make_sapgui_shortcut
        content = make_sapgui_shortcut(
            server="host", sysnr="00", client="1",
            sid="S4H", cookie_b64=FAKE_COOKIE_B64)
        assert "Client=001" in content

    def test_description_auto_generated(self):
        from sap_ticket_delivery import make_sapgui_shortcut
        content = make_sapgui_shortcut(
            server="host", sysnr="00", client="000",
            sid="S4H", cookie_b64=FAKE_COOKIE_B64,
            user="SAP*")
        assert "S4H via MYSAPSSO2 ticket" in content

    def test_custom_description(self):
        from sap_ticket_delivery import make_sapgui_shortcut
        content = make_sapgui_shortcut(
            server="host", sysnr="00", client="000",
            sid="S4H", cookie_b64=FAKE_COOKIE_B64,
            description="My custom desc")
        assert "Description=My custom desc" in content


# ===================================================================
# curl command builder
# ===================================================================

class TestCurlCommand:

    def test_basic_curl(self):
        from sap_ticket_delivery import make_curl_command
        cmd = make_curl_command(
            server="host.example.com", port=44300,
            cookie_b64=FAKE_COOKIE_B64)
        assert cmd.startswith("curl")
        assert "-b" in cmd
        assert "MYSAPSSO2=" in cmd
        assert "host.example.com:44300" in cmd

    def test_https_default(self):
        from sap_ticket_delivery import make_curl_command
        cmd = make_curl_command(
            server="host", port=443,
            cookie_b64=FAKE_COOKIE_B64)
        assert "https://" in cmd

    def test_http_explicit(self):
        from sap_ticket_delivery import make_curl_command
        cmd = make_curl_command(
            server="host", port=8000,
            cookie_b64=FAKE_COOKIE_B64,
            use_https=False)
        assert "http://" in cmd

    def test_custom_path(self):
        from sap_ticket_delivery import make_curl_command
        cmd = make_curl_command(
            server="host", port=443,
            cookie_b64=FAKE_COOKIE_B64,
            path="/sap/bc/ping")
        assert "/sap/bc/ping" in cmd

    def test_client_in_url(self):
        from sap_ticket_delivery import make_curl_command
        cmd = make_curl_command(
            server="host", port=443,
            cookie_b64=FAKE_COOKIE_B64,
            client="100")
        assert "sap-client=100" in cmd

    def test_insecure_flag(self):
        """curl -k is needed for self-signed SAP TLS certs."""
        from sap_ticket_delivery import make_curl_command
        cmd = make_curl_command(
            server="host", port=443,
            cookie_b64=FAKE_COOKIE_B64)
        assert "-k" in cmd


# ===================================================================
# pyrfc kwargs builder
# ===================================================================

class TestPyrfcKwargs:

    def test_basic_kwargs(self):
        from sap_ticket_delivery import make_pyrfc_kwargs
        kwargs = make_pyrfc_kwargs(
            server="host.example.com", sysnr="00",
            client="100", cookie_b64=FAKE_COOKIE_B64)
        assert kwargs["ashost"] == "host.example.com"
        assert kwargs["sysnr"] == "00"
        assert kwargs["client"] == "100"
        assert kwargs["mysapsso2"] == FAKE_COOKIE_B64
        assert kwargs["lang"] == "EN"

    def test_sysnr_padded(self):
        from sap_ticket_delivery import make_pyrfc_kwargs
        kwargs = make_pyrfc_kwargs(
            server="host", sysnr="1",
            client="000", cookie_b64=FAKE_COOKIE_B64)
        assert kwargs["sysnr"] == "01"

    def test_client_padded(self):
        from sap_ticket_delivery import make_pyrfc_kwargs
        kwargs = make_pyrfc_kwargs(
            server="host", sysnr="00",
            client="1", cookie_b64=FAKE_COOKIE_B64)
        assert kwargs["client"] == "001"

    def test_custom_language(self):
        from sap_ticket_delivery import make_pyrfc_kwargs
        kwargs = make_pyrfc_kwargs(
            server="host", sysnr="00", client="000",
            cookie_b64=FAKE_COOKIE_B64, language="de")
        assert kwargs["lang"] == "DE"

    def test_kwargs_are_json_serializable(self):
        from sap_ticket_delivery import make_pyrfc_kwargs
        kwargs = make_pyrfc_kwargs(
            server="host", sysnr="00", client="000",
            cookie_b64=FAKE_COOKIE_B64)
        # Must not raise
        serialized = json.dumps(kwargs)
        assert "mysapsso2" in serialized


# ===================================================================
# Loot persistence
# ===================================================================

class TestLootPersistence:

    def test_save_artifacts_full(self, tmp_path, monkeypatch):
        """Save with server + port creates all artifacts."""
        import sapmap_state
        monkeypatch.setattr(sapmap_state, "LOOT_DIR",
                            os.path.join(tmp_path, "loot"))
        from sap_ticket_delivery import save_ticket_artifacts
        r = save_ticket_artifacts(
            sid="S4H", user="SAP*", client="000",
            cookie_b64=FAKE_COOKIE_B64,
            ticket_bytes=b"\x02test",
            parsed={"validity_min": 120, "codepage": "4103"},
            server="s4h.corp.local", sysnr="00", port=44300)
        assert r["saved"] is True
        assert os.path.isdir(r["loot_path"])
        assert "ticket.b64" in r["files"]
        assert "SAP*@S4H.sap" in r["files"]
        assert "curl.sh" in r["files"]
        assert "pyrfc.json" in r["files"]
        assert "_meta.txt" in r["files"]

        # Verify file contents
        b64_content = open(os.path.join(
            r["loot_path"], "ticket.b64")).read()
        assert b64_content == FAKE_COOKIE_B64

        sap_content = open(os.path.join(
            r["loot_path"], "SAP*@S4H.sap")).read()
        assert "s4h.corp.local" in sap_content
        assert "[System]" in sap_content

        pyrfc_content = json.load(open(os.path.join(
            r["loot_path"], "pyrfc.json")))
        assert pyrfc_content["ashost"] == "s4h.corp.local"
        assert pyrfc_content["mysapsso2"] == FAKE_COOKIE_B64

    def test_save_without_server_skips_some(self, tmp_path,
                                              monkeypatch):
        """Without server, .sap/curl/pyrfc are skipped."""
        import sapmap_state
        monkeypatch.setattr(sapmap_state, "LOOT_DIR",
                            os.path.join(tmp_path, "loot"))
        from sap_ticket_delivery import save_ticket_artifacts
        r = save_ticket_artifacts(
            sid="S4H", user="SAP*", client="000",
            cookie_b64=FAKE_COOKIE_B64,
            ticket_bytes=b"\x02test",
            parsed={"validity_min": 120})
        assert r["saved"] is True
        assert "ticket.b64" in r["files"]
        assert "_meta.txt" in r["files"]
        assert "SAP*@S4H.sap" not in r["files"]
        assert "curl.sh" not in r["files"]

    def test_meta_file_content(self, tmp_path, monkeypatch):
        import sapmap_state
        monkeypatch.setattr(sapmap_state, "LOOT_DIR",
                            os.path.join(tmp_path, "loot"))
        from sap_ticket_delivery import save_ticket_artifacts
        r = save_ticket_artifacts(
            sid="PRD", user="DDIC", client="100",
            cookie_b64=FAKE_COOKIE_B64,
            ticket_bytes=b"\x02" * 500,
            parsed={"validity_min": 60, "codepage": "4110",
                     "recipient_sid": "QAS",
                     "recipient_client": "200"})
        meta = open(os.path.join(
            r["loot_path"], "_meta.txt")).read()
        assert "PRD" in meta
        assert "DDIC" in meta
        assert "60 min" in meta
        assert "4110" in meta
        assert "QAS" in meta  # recipient pinning shown

    def test_loot_path_contains_sid_and_user(self, tmp_path,
                                               monkeypatch):
        import sapmap_state
        monkeypatch.setattr(sapmap_state, "LOOT_DIR",
                            os.path.join(tmp_path, "loot"))
        from sap_ticket_delivery import save_ticket_artifacts
        r = save_ticket_artifacts(
            sid="s4h", user="SAP*", client="000",
            cookie_b64=FAKE_COOKIE_B64,
            ticket_bytes=b"\x02test",
            parsed={})
        assert "S4H" in r["loot_path"]  # SID uppercased
        assert "SAP*" in r["loot_path"]
