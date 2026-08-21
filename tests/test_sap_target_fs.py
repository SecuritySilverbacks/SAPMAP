"""Tests for sap_target_fs — TargetFS class + helpers.

All tests use a fake ExecFn recorder that emulates a healthy Linux
target: python3 chunk writes accepted, md5sum returns hashes, stat
returns metadata, ls returns entries.  Real target-side testing
happens in integration runs against live SAP hosts.
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import tempfile

import pytest

from sap_target_fs import (
    TargetFS,
    _split_python3_spec,
    _py3_chunk_size,
    _py3_params,
    _parse_ls_line,
)


@pytest.fixture(autouse=True)
def _clear_py3_cache():
    """Wipe the module-level python3 probe cache before every test.
    The cache is keyed by ``id(exec_fn)`` and Python recycles ids
    after garbage-collection, causing spurious cache hits across
    tests when the previous test's fake exec_fn happens to reuse
    the same id."""
    from sap_dpmon_sapstar import _PY3_CACHE
    _PY3_CACHE.clear()
    yield
    _PY3_CACHE.clear()


# --------------------------------------------------------------------------
# Fake node + ExecFn
# --------------------------------------------------------------------------

class _FakeNode:
    def __init__(self, sid="TST", os_type="Linux"):
        self.sid = sid
        self.os_type = os_type


class _FakeLinuxTarget:
    """In-memory Linux target that responds to the exec-fn calls
    TargetFS makes.  Simulates a virtual filesystem so we can
    round-trip upload → download → verify without touching a real
    SAP host."""

    def __init__(self):
        self.fs = {}   # path -> bytes
        self.calls = []
        self.python3_can_write = True

    def exec_fn(self, program, args):
        self.calls.append((program, args))
        if program == "/bin/rm":
            paths = [p for p in args.split() if p.startswith("/")]
            for p in paths:
                self.fs.pop(p, None)
            return {"success": True, "output": [], "error": ""}
        if program == "/usr/bin/md5sum":
            path = args.strip()
            if path in self.fs:
                h = hashlib.md5(self.fs[path]).hexdigest()
                return {"success": True,
                         "output": [f"{h}  {path}"], "error": ""}
            return {"success": True,
                     "output": [f"md5sum: {path}: No such file"],
                     "error": ""}
        if program == "/usr/bin/openssl":
            m = re.match(r"^md5 -r (\S+)$", args)
            if m:
                path = m.group(1)
                if path in self.fs:
                    h = hashlib.md5(self.fs[path]).hexdigest()
                    return {"success": True,
                             "output": [f"{h}  {path}"], "error": ""}
            return {"success": False, "output": [], "error": "?"}
        if program == "/usr/bin/stat":
            m = re.match(r"^-c\s+\S+\s+(\S+)$", args)
            if m:
                path = m.group(1)
                if path in self.fs:
                    size = len(self.fs[path])
                    return {"success": True,
                             "output": [f"{size}|2026-08-20 09:00:00|0644|regular file"],
                             "error": ""}
                if path.rstrip("/") in {p.rstrip("/") for p in self.fs
                                          if p.endswith("/")}:
                    return {"success": True,
                             "output": ["4096|2026-08-20 09:00:00|0755|directory"],
                             "error": ""}
                return {"success": True,
                         "output": [f"stat: cannot stat '{path}': No such file"],
                         "error": ""}
        if program == "/bin/ls":
            # Just support the args our list_dir builds
            m = re.match(r"^-la\s+--time-style=\S+\s+(\S+)$", args)
            if m:
                path = m.group(1).rstrip("/") + "/"
                out = ["total 42"]
                for p, data in sorted(self.fs.items()):
                    if p.startswith(path) and "/" not in p[len(path):]:
                        name = p[len(path):]
                        out.append(f"-rw-r--r-- 1 owner group "
                                    f"{len(data)} 2026-08-20T09:00:00 "
                                    f"{name}")
                return {"success": True, "output": out, "error": ""}
        if program == "/bin/mkdir":
            return {"success": True, "output": [], "error": ""}
        if program.endswith("python3") or program == "/usr/bin/env":
            # Handle env-wrapped case
            if program == "/usr/bin/env":
                # args = "LD_LIBRARY_PATH=... /hana/.../python3 -c ..."
                # Extract the -c body
                m = re.search(r"-c\s+(.+)$", args)
                if not m:
                    return {"success": False, "output": [], "error": "no -c"}
                body = m.group(1)
            else:
                m = re.match(r"^-c\s+(.+)$", args)
                if not m:
                    return {"success": False, "output": [], "error": "no -c"}
                body = m.group(1)
            return self._exec_python(body)
        return {"success": False, "output": [], "error":
                 f"unmocked program: {program} {args}"}

    def _exec_python(self, body):
        """Emulate python3 -c <body> against our fake FS.  We only
        support the specific patterns TargetFS emits."""
        if not self.python3_can_write:
            return {"success": True, "output": [], "error": ""}
        # Pattern 1: open('path','wb'|'ab').write(b'CHUNK')
        m = re.match(
            r"^open\('([^']+)','(wb|ab)'\)\.write\(b'([A-Za-z0-9+/=]*)'\)$",
            body)
        if m:
            path, mode, chunk = m.group(1), m.group(2), m.group(3)
            existing = self.fs.get(path, b"")
            new_bytes = chunk.encode("ascii")
            if mode == "wb":
                self.fs[path] = new_bytes
            else:
                self.fs[path] = existing + new_bytes
            return {"success": True, "output": [], "error": ""}
        # Pattern 2: open('out','wb').write(__import__('base64')
        #             .b64decode(open('in','rb').read()))
        m = re.match(
            r"^open\('([^']+)','wb'\)\.write\("
            r"__import__\('base64'\)\.b64decode\("
            r"open\('([^']+)','rb'\)\.read\(\)\)\)$",
            body)
        if m:
            out_path, in_path = m.group(1), m.group(2)
            b64_data = self.fs.get(in_path, b"")
            try:
                self.fs[out_path] = base64.b64decode(b64_data)
            except Exception:
                return {"success": True, "output": [], "error": ""}
            return {"success": True, "output": [], "error": ""}
        # Pattern 3: __import__('sys').stdout.write(
        #             __import__('base64').b64encode(
        #             open('path','rb').read()[O:E]).decode())
        m = re.match(
            r"^__import__\('sys'\)\.stdout\.write\("
            r"__import__\('base64'\)\.b64encode\("
            r"open\('([^']+)','rb'\)\.read\(\)(?:\[(\d+):(\d+)\])?"
            r"\)\.decode\(\)\)$",
            body)
        if m:
            path = m.group(1)
            data = self.fs.get(path, b"")
            if m.group(2) and m.group(3):
                data = data[int(m.group(2)):int(m.group(3))]
            b64 = base64.b64encode(data).decode("ascii")
            return {"success": True, "output": [b64], "error": ""}
        # Pattern 4: print(__import__('base64').b64encode(
        #             open('path','rb').read()[O:E]).decode())
        # (chunked download uses this — print() is safer than
        # sys.stdout.write() against SAPXPG early-termination)
        m = re.match(
            r"^print\("
            r"__import__\('base64'\)\.b64encode\("
            r"open\('([^']+)','rb'\)\.read\(\)(?:\[(\d+):(\d+)\])?"
            r"\)\.decode\(\)\)$",
            body)
        if m:
            path = m.group(1)
            data = self.fs.get(path, b"")
            if m.group(2) and m.group(3):
                data = data[int(m.group(2)):int(m.group(3))]
            b64 = base64.b64encode(data).decode("ascii")
            return {"success": True, "output": [b64], "error": ""}
        # Trivial probe: print(42)
        if body == "print(42)":
            return {"success": True, "output": ["42"], "error": ""}
        return {"success": False, "output": [], "error":
                 f"unmocked python body: {body[:80]}"}


# --------------------------------------------------------------------------
# _split_python3_spec / _py3_chunk_size / _py3_params
# --------------------------------------------------------------------------

def test_split_bare_python3():
    cmd, prefix = _split_python3_spec("/usr/bin/python3")
    assert cmd == "/usr/bin/python3"
    assert prefix == ""


def test_split_env_wrapped_hana():
    spec = ("/usr/bin/env "
            "LD_LIBRARY_PATH=/hana/shared/HDB/exe/linuxx86_64/hdb/Python3/lib "
            "/hana/shared/HDB/exe/linuxx86_64/hdb/Python3/bin/python3")
    cmd, prefix = _split_python3_spec(spec)
    assert cmd == "/usr/bin/env"
    assert "LD_LIBRARY_PATH=" in prefix
    assert prefix.endswith("/python3")


def test_chunk_size_bare():
    """/usr/bin/python3 (0-byte prefix) leaves ~198B for base64."""
    size = _py3_chunk_size("/usr/bin/python3", "/tmp/sapmap_wrap.b64")
    assert size > 150   # plenty of room
    assert size < 220


def test_chunk_size_env_wrapped():
    """Env-wrapped HANA python3 (121B prefix) caps chunks near 80B."""
    spec = ("/usr/bin/env "
            "LD_LIBRARY_PATH=/hana/shared/HDB/exe/linuxx86_64/hdb/Python3/lib "
            "/hana/shared/HDB/exe/linuxx86_64/hdb/Python3/bin/python3")
    size = _py3_chunk_size(spec, "/tmp/sapmap_wrap.b64")
    assert 50 < size < 120, f"expected 50-120B, got {size}"


def test_py3_params_bare_prepends_nothing():
    cmd, params = _py3_params("/usr/bin/python3", "-c print(1)")
    assert cmd == "/usr/bin/python3"
    assert params == "-c print(1)"


def test_py3_params_env_wrapped_prepends_env():
    spec = "/usr/bin/env LD_LIBRARY_PATH=/tmp/foo /opt/python3"
    cmd, params = _py3_params(spec, "-c print(1)")
    assert cmd == "/usr/bin/env"
    assert params.startswith("LD_LIBRARY_PATH=/tmp/foo /opt/python3 -c")


def test_full_params_never_exceeds_255():
    """Regression against Julian's issue #8 root cause: env-wrapped
    python3 + a chunk of chunk_size bytes must produce PARAMS ≤ 255."""
    spec = ("/usr/bin/env "
            "LD_LIBRARY_PATH=/hana/shared/HDB/exe/linuxx86_64/hdb/Python3/lib "
            "/hana/shared/HDB/exe/linuxx86_64/hdb/Python3/bin/python3")
    tmp = "/tmp/sapmap_hana_wrap.b64"
    chunk_size = _py3_chunk_size(spec, tmp)
    body = f"-c open('{tmp}','ab').write(b'{'A' * chunk_size}')"
    cmd, params = _py3_params(spec, body)
    assert len(params) <= 255, \
        f"PARAMS length {len(params)} exceeds 255-byte SAPXPG limit"


# --------------------------------------------------------------------------
# _parse_ls_line
# --------------------------------------------------------------------------

def test_parse_ls_total_header():
    assert _parse_ls_line("total 42") is None


def test_parse_ls_regular_file():
    line = "-rw-r--r-- 1 root root 1234 2026-08-20T09:00:00 hello.txt"
    e = _parse_ls_line(line)
    assert e is not None
    assert e["name"] == "hello.txt"
    assert e["size"] == 1234
    assert not e["is_dir"]


def test_parse_ls_directory():
    line = "drwxr-xr-x 2 root root 4096 2026-08-20T09:00:00 mydir"
    e = _parse_ls_line(line)
    assert e is not None
    assert e["name"] == "mydir"
    assert e["is_dir"] is True


def test_parse_ls_symlink():
    line = "lrwxrwxrwx 1 root root 12 2026-08-20T09:00:00 mylink -> target"
    e = _parse_ls_line(line)
    assert e is not None
    assert e["name"] == "mylink"
    assert not e["is_dir"]


def test_parse_ls_skips_dot_entries():
    assert _parse_ls_line("drwxr-xr-x 2 root root 4096 2026-08-20T09:00:00 .") is None
    assert _parse_ls_line("drwxr-xr-x 2 root root 4096 2026-08-20T09:00:00 ..") is None


def test_parse_ls_blank():
    assert _parse_ls_line("") is None
    assert _parse_ls_line("   ") is None


# --------------------------------------------------------------------------
# TargetFS.upload — happy path + integrity
# --------------------------------------------------------------------------

def test_upload_roundtrip_verifies_md5(tmp_path):
    """Full upload happy path: bytes land on target, remote MD5
    matches local MD5, ok=True."""
    target = _FakeLinuxTarget()
    fs = TargetFS(_FakeNode(), target.exec_fn)
    local = tmp_path / "hello.txt"
    payload = b"hello sapmap"
    local.write_bytes(payload)

    r = fs.upload(str(local), "/tmp/hello.txt")
    assert r["ok"], r.get("error")
    assert r["bytes"] == len(payload)
    assert r["md5_local"] == hashlib.md5(payload).hexdigest()
    assert r["md5_remote"] == r["md5_local"]
    # Bytes actually landed in the fake FS
    assert target.fs["/tmp/hello.txt"] == payload


def test_upload_larger_payload_still_verifies(tmp_path):
    """Multi-chunk payload (400 bytes → 6-8 chunks) still verifies."""
    target = _FakeLinuxTarget()
    fs = TargetFS(_FakeNode(), target.exec_fn)
    local = tmp_path / "big.bin"
    payload = bytes(range(256)) * 4   # 1024 bytes
    local.write_bytes(payload)
    r = fs.upload(str(local), "/tmp/big.bin")
    assert r["ok"], r.get("error")
    assert r["md5_remote"] == r["md5_local"]
    assert target.fs["/tmp/big.bin"] == payload
    # More than one chunk should have been used for a 1 KB payload
    assert r["chunks"] > 1


def test_upload_md5_mismatch_fails():
    """If the target reports a different MD5 (simulated corruption),
    upload must ok=False with a mismatch message."""
    target = _FakeLinuxTarget()
    # Poison md5sum to return a wrong hash regardless of file content
    orig_exec = target.exec_fn
    def poisoned(program, args):
        if program == "/usr/bin/md5sum":
            return {"success": True,
                     "output": [f"deadbeef{'0'*24}  {args.strip()}"],
                     "error": ""}
        return orig_exec(program, args)
    fs = TargetFS(_FakeNode(), poisoned)
    with tempfile.NamedTemporaryFile("wb", delete=False) as f:
        f.write(b"hello")
        local = f.name
    try:
        r = fs.upload(local, "/tmp/hello")
        assert not r["ok"]
        assert "MD5 mismatch" in r["error"]
    finally:
        os.unlink(local)


def test_upload_env_wrapped_python3_uses_smaller_chunks(tmp_path):
    """Env-wrapped HANA python3 spec → chunks capped near 80B, more
    chunks needed for same payload."""
    target = _FakeLinuxTarget()
    spec = ("/usr/bin/env "
            "LD_LIBRARY_PATH=/hana/shared/HDB/exe/linuxx86_64/hdb/Python3/lib "
            "/hana/shared/HDB/exe/linuxx86_64/hdb/Python3/bin/python3")
    fs = TargetFS(_FakeNode(), target.exec_fn, python3_spec=spec)
    local = tmp_path / "hello.txt"
    payload = b"x" * 500
    local.write_bytes(payload)
    r = fs.upload(str(local), "/tmp/hello")
    assert r["ok"], r.get("error")
    # Bare python3 would need ~4 chunks for 500B; env-wrapped needs 8+
    assert r["chunks"] >= 6, f"env-wrap should force smaller chunks: {r}"
    assert r["chunk_size"] < 120


def test_upload_skip_integrity_still_writes(tmp_path):
    target = _FakeLinuxTarget()
    fs = TargetFS(_FakeNode(), target.exec_fn)
    local = tmp_path / "hello.txt"
    local.write_bytes(b"data")
    r = fs.upload(str(local), "/tmp/hello", skip_integrity=True)
    assert r["ok"]
    assert r["md5_remote"] == ""
    assert target.fs.get("/tmp/hello") == b"data"


def test_upload_missing_local_returns_error():
    target = _FakeLinuxTarget()
    fs = TargetFS(_FakeNode(), target.exec_fn)
    r = fs.upload("/nonexistent/path/that/does/not/exist",
                    "/tmp/x")
    assert not r["ok"]
    assert "local read failed" in r["error"]


# --------------------------------------------------------------------------
# TargetFS.download
# --------------------------------------------------------------------------

def test_download_reads_file_from_target(tmp_path):
    target = _FakeLinuxTarget()
    target.fs["/tmp/loot.txt"] = b"secret data"
    fs = TargetFS(_FakeNode(), target.exec_fn)
    r = fs.download("/tmp/loot.txt", loot_dir=str(tmp_path))
    assert r["ok"], r.get("error")
    assert r["bytes"] == 11
    assert r["md5"] == hashlib.md5(b"secret data").hexdigest()
    with open(r["loot_path"], "rb") as f:
        assert f.read() == b"secret data"


def test_download_missing_file_fails(tmp_path):
    target = _FakeLinuxTarget()
    fs = TargetFS(_FakeNode(), target.exec_fn)
    r = fs.download("/tmp/nothere", loot_dir=str(tmp_path))
    assert not r["ok"]
    assert "does not exist" in r["error"]


def test_download_respects_size_cap(tmp_path):
    target = _FakeLinuxTarget()
    target.fs["/tmp/huge"] = b"x" * 1000
    fs = TargetFS(_FakeNode(), target.exec_fn)
    r = fs.download("/tmp/huge", loot_dir=str(tmp_path), max_size=100)
    assert not r["ok"]
    assert "too large" in r["error"]


def test_download_empty_file(tmp_path):
    target = _FakeLinuxTarget()
    target.fs["/tmp/empty"] = b""
    fs = TargetFS(_FakeNode(), target.exec_fn)
    r = fs.download("/tmp/empty", loot_dir=str(tmp_path))
    assert r["ok"]
    assert r["bytes"] == 0


def test_download_chunked_multi_slice(tmp_path):
    """Large file (>5KB) forces the chunked-read code path."""
    target = _FakeLinuxTarget()
    payload = bytes(range(256)) * 40  # 10 KB
    target.fs["/tmp/big"] = payload
    fs = TargetFS(_FakeNode(), target.exec_fn)
    r = fs.download("/tmp/big", loot_dir=str(tmp_path))
    assert r["ok"], r.get("error")
    assert r["bytes"] == len(payload)
    with open(r["loot_path"], "rb") as f:
        assert f.read() == payload


# --------------------------------------------------------------------------
# TargetFS.list_dir + stat
# --------------------------------------------------------------------------

def test_list_dir_returns_entries():
    target = _FakeLinuxTarget()
    target.fs["/tmp/a.txt"] = b"aaa"
    target.fs["/tmp/b.txt"] = b"bbbb"
    fs = TargetFS(_FakeNode(), target.exec_fn)
    r = fs.list_dir("/tmp")
    assert r["ok"], r.get("error")
    names = sorted(e["name"] for e in r["entries"])
    assert names == ["a.txt", "b.txt"]
    for e in r["entries"]:
        assert not e["is_dir"]
        assert e["size"] in (3, 4)


def test_list_dir_dedupes_sapxpg_double_echo():
    """SAPXPG P3+P4 TLV frames can each echo the same stdout line —
    list_dir must dedupe by (name, mode, size) so the browser doesn't
    show each entry twice.  Reproduces the exact bug the user
    reported in the first-feedback screenshots."""
    def _fake_exec(program, args):
        if program != "/bin/ls":
            return {"success": False, "output": [], "error": "?"}
        # Emit each line TWICE — the SAPXPG P3+P4 double-echo pattern
        raw = ("total 8\n"
                "drwxr-xr-x 2 root root 4096 2026-08-20T09:00:00 bin\n"
                "drwxr-xr-x 2 root root 4096 2026-08-20T09:00:00 bin\n"
                "drwxr-xr-x 3 root root 4096 2026-08-20T09:00:00 etc\n"
                "drwxr-xr-x 3 root root 4096 2026-08-20T09:00:00 etc\n")
        return {"success": True, "output": raw.splitlines(),
                 "error": ""}
    fs = TargetFS(_FakeNode(), _fake_exec)
    r = fs.list_dir("/")
    assert r["ok"], r.get("error")
    names = [e["name"] for e in r["entries"]]
    assert names == ["bin", "etc"], f"duplicates not stripped: {names}"


def test_list_dir_falls_back_to_find_when_ls_empty():
    """When both ls variants return empty (SAPXPG buffer drop on
    populous /tmp, /etc, /var/log), list_dir falls back to
    ``find -printf`` which fits under the SAPXPG stdout cap.
    Reproduces the reported '/tmp cannot be read' failure."""
    def _fake_exec(program, args):
        if program == "/bin/ls":
            # Both ls variants return NOTHING — SAPXPG cap exceeded
            return {"success": True, "output": [], "error": ""}
        if program == "/usr/bin/stat":
            # Path is a directory
            return {"success": True,
                     "output": ["4096|2026-08-20 09:00:00|0755|directory"],
                     "error": ""}
        if program == "/usr/bin/find":
            return {"success": True, "output": [
                "d|0755|4096|2026-08-20T09:00:00|systemd-private-xxx",
                "f|0644|123|2026-08-20T09:01:00|.X0-lock",
                "f|0644|456|2026-08-20T09:02:00|somefile.tmp",
            ], "error": ""}
        return {"success": False, "output": [], "error": "?"}
    fs = TargetFS(_FakeNode(), _fake_exec)
    r = fs.list_dir("/tmp")
    assert r["ok"], r.get("error")
    names = sorted(e["name"] for e in r["entries"])
    assert names == [".X0-lock", "somefile.tmp", "systemd-private-xxx"]
    # Verify types
    by_name = {e["name"]: e for e in r["entries"]}
    assert by_name["systemd-private-xxx"]["is_dir"]
    assert not by_name["somefile.tmp"]["is_dir"]
    assert by_name["somefile.tmp"]["size"] == 456


def test_list_dir_falls_back_to_ls1_when_find_also_empty():
    """SAPXPG's PARAMS tokenizer can mangle find's -printf escape
    sequence so find returns unparseable garbage; ls -1a is the
    last-resort fallback that just lists names."""
    def _fake_exec(program, args):
        if program == "/usr/bin/stat":
            return {"success": True,
                     "output": ["4096|2026-08-20 09:00:00|0755|directory"],
                     "error": ""}
        if program == "/bin/ls" and "-la" in args:
            return {"success": True, "output": [], "error": ""}
        if program in ("/usr/bin/find", "/bin/find"):
            # find returns unparseable output — mimics SAPXPG mangling
            # of the \n in -printf
            return {"success": True, "output": ["gibberish no pipes"],
                     "error": ""}
        if program == "/bin/ls" and args.startswith("-1a"):
            return {"success": True, "output": [
                ".", "..", "hosts", "passwd", "shadow", "resolv.conf"
            ], "error": ""}
        return {"success": False, "output": [], "error": "?"}
    fs = TargetFS(_FakeNode(), _fake_exec)
    r = fs.list_dir("/etc")
    assert r["ok"], r.get("error")
    names = sorted(e["name"] for e in r["entries"])
    assert names == ["hosts", "passwd", "resolv.conf", "shadow"]


def test_ls1_fallback_populates_metadata_via_batched_stat():
    """When ls -la / find both fail (SAPXPG cap), ls -1a gives us
    names and then batched `stat` calls fill in size/mode/mtime/
    is_dir per entry.  Verifies the "ls /tmp works but ls -la /tmp
    doesn't" workaround the operator suggested."""
    fs_data = {
        "/tmp/foo.log":  (500,  "0644", "regular file"),
        "/tmp/bar.txt":  (128,  "0600", "regular file"),
        "/tmp/subdir":   (4096, "0755", "directory"),
    }
    stat_calls = {"n": 0}
    def _fake_exec(program, args):
        if program == "/usr/bin/stat" and args.startswith("-c %n|%s|%y|%a|%F"):
            stat_calls["n"] += 1
            out = []
            # Parse the paths off the end of args
            paths = args.split()[2:]
            for p in paths:
                if p in fs_data:
                    size, mode, ftype = fs_data[p]
                    out.append(f"{p}|{size}|2026-08-20 09:00:00|{mode}|{ftype}")
                else:
                    out.append(f"stat: cannot stat '{p}': No such file")
            return {"success": True, "output": out, "error": ""}
        # /tmp itself for the up-front stat short-circuit
        if program == "/usr/bin/stat" and args.endswith("/tmp"):
            return {"success": True,
                     "output": ["4096|2026-08-20 09:00:00|0755|directory"],
                     "error": ""}
        # ls -la returns nothing — mimics SAPXPG buffer overflow
        if program == "/bin/ls" and "-la" in args:
            return {"success": True, "output": [], "error": ""}
        # find returns nothing
        if program in ("/usr/bin/find", "/bin/find"):
            return {"success": True, "output": [], "error": ""}
        # ls -1a returns just names — this succeeds
        if program == "/bin/ls" and args.startswith("-1a"):
            return {"success": True, "output": [
                ".", "..", "foo.log", "bar.txt", "subdir",
            ], "error": ""}
        return {"success": False, "output": [], "error": "?"}
    fs = TargetFS(_FakeNode(), _fake_exec)
    r = fs.list_dir("/tmp")
    assert r["ok"], r.get("error")
    by_name = {e["name"]: e for e in r["entries"]}
    assert set(by_name) == {"foo.log", "bar.txt", "subdir"}
    # Metadata was populated by batched stat, not left as 0/blank
    assert by_name["foo.log"]["size"] == 500
    assert by_name["foo.log"]["mode"] == "0644"
    assert not by_name["foo.log"]["is_dir"]
    assert by_name["subdir"]["is_dir"]
    assert by_name["subdir"]["size"] == 4096
    assert by_name["bar.txt"]["mtime"] == "2026-08-20 09:00:00"
    # 3 files should fit in one stat batch (paths are short)
    assert stat_calls["n"] >= 1


def test_download_tolerates_truncated_b64_padding():
    """If /usr/bin/base64's output is truncated so the total length
    isn't a multiple of 4, we pad with '=' and decode leniently.
    The size-check then decides whether to fall back to python3."""
    def _fake_exec(program, args):
        if program == "/usr/bin/stat":
            return {"success": True,
                     "output": ["100|2026-08-20 09:00:00|0644|regular file"],
                     "error": ""}
        if program == "/usr/bin/base64":
            # Return 5 chars of b64 → not a multiple of 4, decode
            # would raise "Incorrect padding" without the fix.
            return {"success": True, "output": ["ABCDE"], "error": ""}
        if program in ("/bin/base64", "/usr/local/bin/base64"):
            return {"success": True, "output": [], "error": ""}
        # python3 fallback returns full content
        if program == "/usr/bin/python3":
            m = re.search(r"\[(\d+):(\d+)\]", args)
            if m:
                lo, hi = int(m.group(1)), int(m.group(2))
                data = (b"x" * 100)[lo:hi]
                return {"success": True,
                         "output": [base64.b64encode(data).decode()],
                         "error": ""}
        if program == "/bin/cat" and args == "/etc/hostname":
            return {"success": True, "output": ["host1"], "error": ""}
        if program == "/bin/ls":
            # python3 probe expects /bin/ls readback
            return {"success": True, "output": [args.split()[-1]],
                     "error": ""}
        return {"success": False, "output": [], "error": "?"}
    fs = TargetFS(_FakeNode(), _fake_exec)
    import tempfile as _tf
    with _tf.TemporaryDirectory() as td:
        r = fs.download("/tmp/x", loot_dir=td)
    # Should succeed via python3 fallback after b64 length-mismatch
    # falls through (not via the "Incorrect padding" exception).
    assert r["ok"], r.get("error")
    assert r["bytes"] == 100


def test_list_dir_treats_file_as_single_entry():
    """When the operator types a file path (e.g. /etc/passwd) as the
    directory to browse, list_dir returns a single entry with
    abs_path set so the UI can offer download without corrupting
    the path via /current_dir/name join.  Reproduces the
    '/etc/passwd//etc/passwd' download bug."""
    def _fake_exec(program, args):
        if program == "/usr/bin/stat":
            # Path is a regular file
            return {"success": True,
                     "output": ["2841|2026-08-20 09:00:00|0644|regular file"],
                     "error": ""}
        return {"success": False, "output": [], "error": "?"}
    fs = TargetFS(_FakeNode(), _fake_exec)
    r = fs.list_dir("/etc/passwd")
    assert r["ok"], r.get("error")
    assert len(r["entries"]) == 1
    e = r["entries"][0]
    assert e["name"] == "passwd"
    assert e["abs_path"] == "/etc/passwd"
    assert e["size"] == 2841
    assert not e["is_dir"]


def test_list_dir_falls_back_to_bare_la_when_time_style_returns_empty():
    """Some builds of ls print an "unrecognized option --time-style"
    to stderr and produce no stdout — list_dir must retry with bare
    -la instead of returning empty.  Same failure pattern as the
    "/tmp returned empty" issue the user reported."""
    calls = []
    def _fake_exec(program, args):
        calls.append((program, args))
        if program != "/bin/ls":
            return {"success": False, "output": [], "error": "?"}
        # First call (with --time-style) → empty. Retry (bare -la) → entries.
        if "--time-style" in args:
            return {"success": True, "output": [], "error": ""}
        return {"success": True, "output": [
            "total 4",
            "-rw-r--r-- 1 root root 5 Aug 20 09:00 hello.txt",
        ], "error": ""}
    fs = TargetFS(_FakeNode(), _fake_exec)
    r = fs.list_dir("/tmp")
    assert r["ok"], r.get("error")
    names = [e["name"] for e in r["entries"]]
    assert names == ["hello.txt"]
    # Both variants must have been attempted
    variants = [c[1] for c in calls if c[0] == "/bin/ls"]
    assert any("--time-style" in v for v in variants)
    assert any("--time-style" not in v for v in variants)


def test_download_prefers_usr_bin_base64():
    """The new download path tries /usr/bin/base64 first — it works
    without python3 (fixes downloads on HANA hosts where python3 is
    only under /hana/shared/...)."""
    called = []
    payload = b"hello world content\n"
    def _fake_exec(program, args):
        called.append(program)
        if program in ("/usr/bin/base64", "/bin/base64",
                        "/usr/local/bin/base64"):
            if program == "/usr/bin/base64" and args == "/tmp/x":
                return {"success": True,
                         "output": [base64.b64encode(payload).decode()],
                         "error": ""}
            return {"success": True, "output": [], "error": ""}
        if program == "/usr/bin/stat":
            return {"success": True,
                     "output": [f"{len(payload)}|2026-08-20 09:00:00|0644|regular file"],
                     "error": ""}
        return {"success": False, "output": [], "error": "?"}
    fs = TargetFS(_FakeNode(), _fake_exec)
    import tempfile as _tf
    with _tf.TemporaryDirectory() as td:
        r = fs.download("/tmp/x", loot_dir=td)
    assert r["ok"], r.get("error")
    assert r["bytes"] == len(payload)
    # /usr/bin/base64 must have been called first
    assert "/usr/bin/base64" in called


def test_stat_returns_size_and_mtime():
    target = _FakeLinuxTarget()
    target.fs["/etc/hostname"] = b"host1\n"
    fs = TargetFS(_FakeNode(), target.exec_fn)
    r = fs.stat("/etc/hostname")
    assert r["ok"]
    assert r["exists"]
    assert r["size"] == 6
    assert not r["is_dir"]


def test_stat_missing_file_ok_exists_false():
    target = _FakeLinuxTarget()
    fs = TargetFS(_FakeNode(), target.exec_fn)
    r = fs.stat("/nonexistent")
    assert r["ok"]
    assert not r["exists"]


# --------------------------------------------------------------------------
# OS detection
# --------------------------------------------------------------------------

def test_detect_windows_from_os_type():
    node = _FakeNode(os_type="Windows Server 2019")
    fs = TargetFS(node, lambda p, a: {"success": True, "output": [], "error": ""})
    assert fs.os_family == "windows"


def test_detect_linux_default():
    node = _FakeNode(os_type="")
    fs = TargetFS(node, lambda p, a: {"success": True, "output": [], "error": ""})
    assert fs.os_family == "linux"


def test_windows_upload_returns_not_implemented(tmp_path):
    """Phase 1 stubs Windows out with a clear error message."""
    node = _FakeNode(os_type="Windows")
    fs = TargetFS(node, lambda p, a: {"success": True, "output": [], "error": ""})
    local = tmp_path / "x"
    local.write_bytes(b"y")
    r = fs.upload(str(local), "C:\\tmp\\x")
    assert not r["ok"]
    assert "Phase 2" in r["error"]
