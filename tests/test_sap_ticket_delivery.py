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
        # Server= must use the universal direct-AS routing form
        # /H/<host>/S/<port>.  Validated empirically (variant Q
        # vs. variant P against live S4H): Java GUI accepts both
        # direct-AS and msgserver routing equivalently, so we use
        # direct-AS to avoid any dependency on a reachable
        # message-server port (3601).
        # Diag port = 3200 + sysnr → 3201 for sysnr "01".
        assert "Server=/H/s4h.corp.local/S/3201" in content
        assert "SystemNumber=01" in content
        assert "Client=000" in content
        # [System] block MUST emit Name=@01 — Java GUI rejects the
        # file with "Error in connection data document" if Name= is
        # absent (validated empirically: variant R, which dropped
        # Name= from [System], failed against live S4H while the
        # otherwise-identical Q variant with Name=@01 succeeded).
        # The @01 placeholder is what Java GUI itself writes when
        # saving a fresh landscape entry.  Windows GUI ignores it.
        system_block = content.split("[System]", 1)[1]
        next_section = system_block.index("\n[")
        system_block = system_block[:next_section]
        assert "Name=@01" in system_block, \
            "[System] must emit Name=@01 (Java-GUI canonical form)"
        assert "Command=SU01" in content

    def test_server_uses_direct_as_routing_string(self):
        """Server= line emits /H/<host>/S/<port>, never a bare host."""
        from sap_ticket_delivery import make_sapgui_shortcut
        content = make_sapgui_shortcut(
            server="192.168.2.209", sysnr="00",
            client="001", sid="S4H",
            cookie_b64=FAKE_COOKIE_B64)
        assert "Server=/H/192.168.2.209/S/3200" in content
        # No bare-host Server= line should ever leak through
        for line in content.splitlines():
            if line.startswith("Server="):
                assert line.startswith("Server=/H/"), \
                    f"Server line must start with /H/ routing: {line!r}"

    def test_diag_port_derived_from_sysnr(self):
        """Default Diag port = 3200 + sysnr (unencrypted)."""
        from sap_ticket_delivery import make_sapgui_shortcut
        for sysnr, expected_port in [
                ("00", 3200), ("01", 3201), ("42", 3242), ("99", 3299)]:
            content = make_sapgui_shortcut(
                server="h", sysnr=sysnr, client="000",
                sid="X", cookie_b64=FAKE_COOKIE_B64)
            assert f"Server=/H/h/S/{expected_port}" in content, \
                f"sysnr={sysnr} should yield port {expected_port}"

    def test_diag_port_override(self):
        """Operators can supply a non-default Diag port (e.g. SNC)."""
        from sap_ticket_delivery import make_sapgui_shortcut
        # SNC Diag listener convention: 4700 + sysnr
        content = make_sapgui_shortcut(
            server="snchost", sysnr="00", client="000",
            sid="X", cookie_b64=FAKE_COOKIE_B64,
            diag_port=4700)
        assert "Server=/H/snchost/S/4700" in content
        # And an entirely arbitrary port works too
        content = make_sapgui_shortcut(
            server="h", sysnr="00", client="000",
            sid="X", cookie_b64=FAKE_COOKIE_B64,
            diag_port=32000)
        assert "Server=/H/h/S/32000" in content

    def test_guiparm_present_in_system_section(self):
        """SAP note 2630575 mandates GuiParm for SAP GUI for Java.

        Validated against the canonical Java GUI .sap export
        ("Save Connection Data as Document"): ``GuiParm`` MUST
        live inside the ``[System]`` block — putting it under
        ``[Configuration]`` causes Java GUI to fail with
        "No valid host specification for connection: tmp"
        because the parser creates a temporary placeholder
        connection ("tmp") and then can't find a host for it.

        Without GuiParm anywhere, Java GUI emits the different
        error "Error in connection data document" (per the note).
        """
        from sap_ticket_delivery import make_sapgui_shortcut
        content = make_sapgui_shortcut(
            server="192.168.2.209", sysnr="00", client="001",
            sid="S4H", cookie_b64=FAKE_COOKIE_B64)
        # GuiParm must use the same /H/<host>/S/<port> routing form
        assert "GuiParm=/H/192.168.2.209/S/3200" in content
        # And it must live inside [System], BEFORE any [Configuration]
        # section that may follow.
        sys_idx = content.index("[System]")
        guiparm_idx = content.index("GuiParm=")
        assert guiparm_idx > sys_idx, \
            "GuiParm must appear after [System] header"
        # If a [Configuration] section exists, GuiParm must come
        # before it (i.e. still inside [System]).
        if "[Configuration]" in content:
            cfg_idx = content.index("[Configuration]")
            assert guiparm_idx < cfg_idx, \
                ("GuiParm must live in [System], not [Configuration] "
                 "— canonical Java GUI export confirms this.")

    def test_guiparm_matches_server_port(self):
        """GuiParm and Server must point at the same listener."""
        from sap_ticket_delivery import make_sapgui_shortcut
        for sysnr, expected_port in [
                ("00", 3200), ("01", 3201), ("42", 3242)]:
            content = make_sapgui_shortcut(
                server="h", sysnr=sysnr, client="000",
                sid="X", cookie_b64=FAKE_COOKIE_B64)
            assert f"Server=/H/h/S/{expected_port}" in content
            assert f"GuiParm=/H/h/S/{expected_port}" in content

    def test_guiparm_honors_diag_port_override(self):
        """GuiParm tracks the diag_port override (e.g. SNC port)."""
        from sap_ticket_delivery import make_sapgui_shortcut
        content = make_sapgui_shortcut(
            server="snchost", sysnr="00", client="000",
            sid="X", cookie_b64=FAKE_COOKIE_B64,
            diag_port=4700)
        assert "Server=/H/snchost/S/4700" in content
        assert "GuiParm=/H/snchost/S/4700" in content

    def test_others_sso2_section_present(self):
        """SAP GUI for Java reads MYSAPSSO2 from [Others] SSO2=.

        Per chapter 5.6 of the SAP GUI for Java reference v7.80
        (connection parameters table), ``sso2`` is a documented
        URL parameter.  Validated by round-tripping a manual
        ``conn=...&sso2=longstring`` through Java GUI's "Save
        Connection Data as Document" feature: it lands in the
        ``[Others]`` section verbatim, no URL-decoding, no prefix.

        Windows GUI ignores ``[Others]`` so the dual emission
        (``at=`` for Windows, ``SSO2=`` for Java) is safe.
        """
        from sap_ticket_delivery import make_sapgui_shortcut
        content = make_sapgui_shortcut(
            server="h", sysnr="00", client="001",
            sid="X", cookie_b64=FAKE_COOKIE_B64)
        assert "[Others]" in content, \
            "[Others] section required for SAP GUI for Java"
        # SSO2 holds the RAW base64 ticket — no MYSAPSSO2= prefix,
        # no URL encoding.
        assert f"SSO2={FAKE_COOKIE_B64}" in content
        # The Java-GUI SSO2 value must NOT be URL-encoded
        assert "SSO2=MYSAPSSO2" not in content, \
            "SSO2 takes raw b64, never the MYSAPSSO2= prefix"
        assert "SSO2=MYSAPSSO2%3D" not in content, \
            "SSO2 takes raw b64, never URL-encoded"

    def test_others_section_before_user_at(self):
        """[Others] SSO2 must appear before [User] at= in the file.

        We don't strictly *require* the ordering, but this pins the
        canonical order matching what Java GUI itself emits, which
        avoids surprises if some parser cares about section order.
        """
        from sap_ticket_delivery import make_sapgui_shortcut
        content = make_sapgui_shortcut(
            server="h", sysnr="00", client="001",
            sid="X", cookie_b64=FAKE_COOKIE_B64)
        others_idx = content.index("[Others]")
        user_idx = content.index("[User]")
        assert others_idx < user_idx, \
            "[Others] should precede [User] (canonical order)"

    def test_both_ticket_injection_mechanisms_present(self):
        """One .sap file must carry BOTH ticket-injection forms.

        SAP GUI for Windows reads ``at="MYSAPSSO2=<raw-b64>"``
        (double-quoted, NOT URL-encoded) from [User]; SAP GUI for
        Java reads ``SSO2=<raw-b64>`` (raw, no prefix) from [Others].
        A single shortcut that dual-targets both clients must emit
        both — otherwise it only works on one.

        Caveat: Java GUI's SSO2 mechanism is "Reserved" (non-functional)
        per the SAP GUI for Java reference v7.80 chapter 5.6, validated
        against live S4H — Java GUI parses & stores SSO2 but never
        transmits it in the Diag handshake.  We emit SSO2 anyway because
        (a) it's harmless on Windows GUI, (b) future Java GUI versions
        may wire it up, and (c) operators reading the .sap can see the
        intent.
        """
        from sap_ticket_delivery import make_sapgui_shortcut
        content = make_sapgui_shortcut(
            server="h", sysnr="00", client="001",
            sid="X", cookie_b64=FAKE_COOKIE_B64)

        # Java GUI form: raw b64 in [Others]
        assert f"SSO2={FAKE_COOKIE_B64}" in content

        # Windows GUI form: at="MYSAPSSO2=<raw-b64>" in [User]
        at_line = next(l for l in content.splitlines()
                       if l.startswith("at="))
        assert at_line == f'at="MYSAPSSO2={FAKE_COOKIE_B64}"', \
            f"at= must be quoted, raw b64; got: {at_line!r}"

    def test_user_prefilled_in_user_block(self):
        """[User] Name= pre-fills the username on Java GUI logon.

        Since Java GUI doesn't actually inject MYSAPSSO2 from the
        SSO2 field, the operator ends up at a normal logon screen.
        Emitting ``Name=<user>`` in the [User] block makes Java GUI
        pre-fill the username field so the operator only has to
        supply a password.  Windows GUI also reads Name= here, but
        is mostly redundant because at= already auto-authenticates.
        """
        from sap_ticket_delivery import make_sapgui_shortcut
        content = make_sapgui_shortcut(
            server="h", sysnr="00", client="001",
            sid="S4H", cookie_b64=FAKE_COOKIE_B64,
            user="JORIS")
        user_idx = content.index("[User]")
        user_block = content[user_idx:]
        next_section = user_block.index("\n[", 1)
        user_block = user_block[:next_section]
        assert "Name=JORIS" in user_block, \
            "[User] Name= should pre-fill the impersonated user"

    def test_user_prefill_empty_when_no_user_supplied(self):
        """When user kwarg is empty, [User] Name= is empty."""
        from sap_ticket_delivery import make_sapgui_shortcut
        content = make_sapgui_shortcut(
            server="h", sysnr="00", client="001",
            sid="S4H", cookie_b64=FAKE_COOKIE_B64)
        # The [User] block contains an empty Name= line
        user_block = content.split("[User]", 1)[1].split("\n[", 1)[0]
        assert "Name=\n" in user_block or "Name=\r\n" in user_block, \
            "[User] Name= should be empty when user is not supplied"

    def test_module_documents_java_gui_sso2_limitation(self):
        """The module-level comment must warn that Java GUI SSO2 is dead.

        Regression guard: if a future refactor strips the explanation,
        operators won't know why their Java GUI .sap files land at a
        password prompt instead of auto-authenticating.  The dead-end
        is non-obvious and easy to lose during a docs cleanup.
        """
        import inspect
        import sap_ticket_delivery
        src = inspect.getsource(sap_ticket_delivery)
        # The note must mention BOTH that Java GUI doesn't auto-auth
        # AND that SSO2 is "Reserved" / non-functional.
        assert "Reserved" in src, \
            "Module must reference 'Reserved' (the SAP doc term)"
        assert "Java GUI" in src, "Module must mention 'Java GUI'"
        # The pivot advice must be there
        assert "curl" in src.lower() or "HTTP" in src or "http" in src, \
            "Module must point operators to the curl/HTTP fallback"

    def test_at_value_quoted_not_url_encoded(self):
        """The at= line is double-quoted, base64 NOT URL-encoded.

        Validated against the canonical SAP shortcut reference impl
        (Procter & Gamble MYSAPSSO2 SP Token Adapter,
        ``SpSAPAdapter.java:233``):

            bOutput.append(("at=\\"MYSAPSSO2=" + ticket + "\\""));

        The base64 ticket is passed RAW inside the double quotes —
        the quotes are how the SAP shortcut parser handles the
        embedded ``=`` characters from base64 padding.  An earlier
        URL-encoded form (``at=MYSAPSSO2%3D...%3D%3D``) was silently
        dropped by SAP GUI for Windows; the GUI then fell through to
        manual logon with empty credentials and SAP returned
        "Name or password is incorrect".
        """
        from sap_ticket_delivery import make_sapgui_shortcut
        content = make_sapgui_shortcut(
            server="host", sysnr="00", client="000",
            sid="S4H", cookie_b64=FAKE_COOKIE_B64)
        at_line = [l for l in content.splitlines()
                   if l.startswith("at=")][0]
        # The literal value MUST be: at="MYSAPSSO2=<raw-b64>"
        assert at_line == f'at="MYSAPSSO2={FAKE_COOKIE_B64}"', \
            f"at= line must be quoted with raw b64, got: {at_line!r}"
        # And explicit checks for the format violations we used to
        # commit:
        assert '%3D' not in at_line, \
            "at= must not contain URL-encoded '=' (use raw base64)"
        assert '%2F' not in at_line, \
            "at= must not contain URL-encoded '/' (use raw base64)"
        assert '%2B' not in at_line, \
            "at= must not contain URL-encoded '+' (use raw base64)"

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
