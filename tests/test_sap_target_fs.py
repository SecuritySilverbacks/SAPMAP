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
    _parse_win_dir_line,
    _decode_certutil_b64,
    ntpath_basename,
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


def test_list_dir_falls_back_to_ls1_names_when_ls_la_empty():
    """When ls -la variants return empty (SAPXPG buffer drop on
    populous /tmp, /etc, /var/log), list_dir falls back to
    ``ls -1 <path>`` which fits under the SAPXPG stdout cap, then
    fills in metadata via batched stat."""
    fs_data = {
        "/tmp/systemd-private-xxx": (4096, "0755", "directory"),
        "/tmp/.X0-lock":             (123,  "0644", "regular file"),
        "/tmp/somefile.tmp":         (456,  "0644", "regular file"),
    }
    def _fake_exec(program, args):
        # ls -la variants (with or without --time-style) → empty
        if program == "/bin/ls" and "-la" in args:
            return {"success": True, "output": [], "error": ""}
        # ls -1 <path> → visible names only
        if program == "/bin/ls" and args.startswith("-1 /"):
            return {"success": True,
                     "output": ["somefile.tmp"], "error": ""}
        # ls -1 -a <path> → with hidden
        if program == "/bin/ls" and args.startswith("-1 -a"):
            return {"success": True, "output": [
                ".", "..", "systemd-private-xxx",
                ".X0-lock", "somefile.tmp",
            ], "error": ""}
        # Directory stat
        if program == "/usr/bin/stat" and args.endswith(" /tmp"):
            return {"success": True,
                     "output": ["4096|2026-08-20 09:00:00|0755|directory"],
                     "error": ""}
        # Batched stat
        if program == "/usr/bin/stat" and args.startswith("-c %n"):
            out = []
            for p in args.split()[2:]:
                if p in fs_data:
                    size, mode, ftype = fs_data[p]
                    out.append(f"{p}|{size}|2026-08-20 09:00:00|{mode}|{ftype}")
            return {"success": True, "output": out, "error": ""}
        return {"success": False, "output": [], "error": "?"}
    fs = TargetFS(_FakeNode(), _fake_exec)
    r = fs.list_dir("/tmp")
    assert r["ok"], r.get("error")
    names = sorted(e["name"] for e in r["entries"])
    # First fallback (ls -1) returns only the visible file
    assert "somefile.tmp" in names


def test_list_dir_skips_ls_variants_that_return_find_errors():
    """The reported 'find: paths must precede expression' error
    from SAPXPG-mangled args must not abort the chain — we should
    move on to the next candidate command."""
    def _fake_exec(program, args):
        if program == "/usr/bin/stat" and args.endswith("/tmp"):
            return {"success": True,
                     "output": ["4096|2026-08-20 09:00:00|0755|directory"],
                     "error": ""}
        if program == "/bin/ls" and "-la" in args:
            return {"success": True, "output": [], "error": ""}
        if program == "/bin/ls":
            return {"success": True, "output": [], "error": ""}
        if program in ("/usr/bin/find", "/bin/find"):
            # find rejects the args — same as the reported
            # 'possible unquoted pattern' failure
            return {"success": True, "output": [
                "find: paths must precede expression: `/tmp'",
                "find: possible unquoted pattern after predicate `-printf'?",
            ], "error": ""}
        return {"success": False, "output": [], "error": "?"}
    fs = TargetFS(_FakeNode(), _fake_exec)
    r = fs.list_dir("/tmp")
    # All strategies came up empty, but no crash and clear error
    assert not r["ok"]
    assert "no parseable output" in r["error"].lower()


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
        # ls -1 returns just names — this succeeds
        if program == "/bin/ls" and args.startswith("-1 /"):
            return {"success": True, "output": [
                "foo.log", "bar.txt", "subdir",
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


def test_linux_list_dir_file_redirect_fallback():
    """When all ls/find variants overflow SAPXPG stdout on a populous
    Linux directory, the file-redirect fallback kicks in:
    ls -1 > /tmp/sapmap_xxx.ls + download temp file + parse names."""
    real_files = {
        "/usr/sap/S4H/D00/exe/disp+work": (12345, "0755", "regular file"),
        "/usr/sap/S4H/D00/exe/gwrd":      (67890, "0755", "regular file"),
        "/usr/sap/S4H/D00/exe/icman":     (11111, "0755", "regular file"),
    }
    listing_text = "disp+work\ngwrd\nicman\n"
    listing_bytes = listing_text.encode()
    tmp_state = {}  # track the temp file written by the redirect

    def _fake_exec(program, args):
        # ls -la variants → empty (overflow)
        if program == "/bin/ls" and "-la" in args:
            return {"success": True, "output": [], "error": ""}
        # Shell-wrapped ls -la → empty (overflow)
        if program == "/bin/sh" and args.startswith("-c ls${IFS}-la"):
            return {"success": True, "output": [], "error": ""}
        # Shell-wrapped ls -1 / ls (names-only) → empty (overflow)
        if program == "/bin/sh" and args.startswith("-c ls"):
            # Check if this is a redirect (contains ">")
            if ">" in args:
                # File-redirect: ls -1 path > tmpfile
                m = re.search(r'>(/tmp/sapmap_\w+\.ls)', args)
                if m:
                    tmp_state["path"] = m.group(1)
                    tmp_state["data"] = listing_bytes
                    return {"success": True, "output": [], "error": ""}
            return {"success": True, "output": [], "error": ""}
        # Direct ls → empty
        if program == "/bin/ls":
            return {"success": True, "output": [], "error": ""}
        # Shell-wrapped find → empty (overflow)
        if program == "/bin/sh" and "find" in args:
            return {"success": True, "output": [], "error": ""}
        # Direct find → mangled args error
        if program in ("/usr/bin/find", "/bin/find"):
            return {"success": True, "output": [
                "find: paths must precede expression: "
                "`/usr/sap/S4H/D00/exe'",
            ], "error": ""}
        # stat on the directory itself
        if program == "/usr/bin/stat" and \
                args.endswith("/usr/sap/S4H/D00/exe"):
            return {"success": True,
                     "output": ["4096|2026-08-20 09:00:00|0755|directory"],
                     "error": ""}
        # stat on the temp file
        if program == "/usr/bin/stat" and tmp_state.get("path") \
                and tmp_state["path"] in args:
            sz = len(tmp_state["data"])
            return {"success": True,
                     "output": [f"{sz}|2026-08-20 09:00:00|0644|regular file"],
                     "error": ""}
        # base64 read of the temp file (single-shot download)
        if program in ("/usr/bin/base64", "/bin/base64",
                        "/usr/local/bin/base64"):
            path = args.strip()
            if tmp_state.get("path") and path == tmp_state["path"]:
                b64 = base64.b64encode(tmp_state["data"]).decode()
                return {"success": True, "output": [b64], "error": ""}
            return {"success": True, "output": [], "error": ""}
        # Batched stat for the actual files
        if program == "/usr/bin/stat" and args.startswith("-c %n"):
            out = []
            for p in args.split()[2:]:
                bn = os.path.basename(p)
                full = f"/usr/sap/S4H/D00/exe/{bn}"
                if full in real_files:
                    sz, mode, ftype = real_files[full]
                    out.append(f"{p}|{sz}|2026-08-20 09:00:00|{mode}|{ftype}")
            return {"success": True, "output": out, "error": ""}
        # rm -f (cleanup)
        if program == "/bin/rm":
            tmp_state.clear()
            return {"success": True, "output": [], "error": ""}
        return {"success": False, "output": [], "error": "?"}

    fs = TargetFS(_FakeNode(), _fake_exec)
    r = fs.list_dir("/usr/sap/S4H/D00/exe")
    assert r["ok"], r.get("error", "")
    names = {e["name"] for e in r["entries"]}
    assert "disp+work" in names
    assert "gwrd" in names
    assert "icman" in names
    assert len(r["entries"]) == 3
    # Verify metadata was filled in via batched stat
    by_name = {e["name"]: e for e in r["entries"]}
    assert by_name["disp+work"]["size"] == 12345
    assert by_name["gwrd"]["size"] == 67890


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


# --------------------------------------------------------------------------
# ntpath_basename / _decode_certutil_b64 / _parse_win_dir_line
# --------------------------------------------------------------------------

def test_ntpath_basename_backslash():
    assert ntpath_basename("C:\\Windows\\notepad.exe") == "notepad.exe"


def test_ntpath_basename_forward_slash():
    assert ntpath_basename("C:/Windows/notepad.exe") == "notepad.exe"


def test_ntpath_basename_trailing_slash():
    assert ntpath_basename("C:\\Windows\\") == "Windows"


def test_decode_certutil_b64_roundtrip():
    payload = b"hello world" * 20
    b64 = base64.b64encode(payload).decode()
    # certutil wraps at 64 chars and adds the PEM markers.
    wrapped = "\n".join(b64[i:i+64] for i in range(0, len(b64), 64))
    text = (f"-----BEGIN CERTIFICATE-----\r\n{wrapped}\r\n"
            f"-----END CERTIFICATE-----\r\n")
    assert _decode_certutil_b64(text) == payload


def test_decode_certutil_b64_returns_none_for_garbage():
    assert _decode_certutil_b64("") is None
    assert _decode_certutil_b64("nothing here") is None


def test_decode_certutil_b64_tolerates_truncation():
    """SAPXPG can drop the tail; lenient decode should still return
    whatever prefix decodes cleanly."""
    payload = b"hello world"
    b64 = base64.b64encode(payload).decode()
    # Chop off the trailing '=' padding certutil emits.
    truncated = b64.rstrip("=")
    text = (f"-----BEGIN CERTIFICATE-----\n{truncated}\n"
            f"-----END CERTIFICATE-----\n")
    r = _decode_certutil_b64(text)
    assert r is not None
    assert r.startswith(b"hello")


def test_parse_win_dir_us_file():
    e = _parse_win_dir_line("08/20/2026  09:00 AM              1234 hosts")
    assert e is not None
    assert e["name"] == "hosts"
    assert e["size"] == 1234
    assert not e["is_dir"]


def test_parse_win_dir_us_dir():
    e = _parse_win_dir_line("08/20/2026  09:00 AM    <DIR>          System32")
    assert e is not None
    assert e["name"] == "System32"
    assert e["is_dir"] is True
    assert e["size"] == 0


def test_parse_win_dir_de_locale():
    e = _parse_win_dir_line("20.08.2026  09:00                 1234 hosts")
    assert e is not None
    assert e["name"] == "hosts"
    assert e["size"] == 1234


def test_parse_win_dir_skips_headers():
    assert _parse_win_dir_line(" Volume in drive C is Windows") is None
    assert _parse_win_dir_line(" Directory of C:\\Windows") is None
    assert _parse_win_dir_line("               42 File(s)  99999 bytes") is None
    assert _parse_win_dir_line("") is None


def test_parse_win_dir_skips_dot_entries():
    assert _parse_win_dir_line(
        "08/20/2026  09:00 AM    <DIR>          .") is None
    assert _parse_win_dir_line(
        "08/20/2026  09:00 AM    <DIR>          ..") is None


def test_parse_win_dir_name_with_spaces():
    e = _parse_win_dir_line(
        "08/20/2026  09:00 AM              1024 my file.txt")
    assert e is not None
    assert e["name"] == "my file.txt"
    assert e["size"] == 1024


# --------------------------------------------------------------------------
# _FakeWindowsTarget + Windows upload/download/list/stat round-trips
# --------------------------------------------------------------------------

class _FakeWindowsTarget:
    """In-memory Windows target that responds to the cmd.exe /C
    invocations TargetFS emits.  Supports enough of dir /-C /A,
    echo>>, certutil -encode/-decode, and certutil -hashfile to
    round-trip upload → verify → download."""

    def __init__(self):
        self.fs = {}     # normalised path -> bytes
        self.calls = []

    @staticmethod
    def _norm(path: str) -> str:
        return path.replace("/", "\\").strip('"').lower()

    def exec_fn(self, program, args):
        self.calls.append((program, args))
        # _win_cmd now puts full "cmd.exe /C ..." in program, args=""
        if program.startswith("cmd.exe /C "):
            cmd = program[len("cmd.exe /C "):]
        elif program == "cmd.exe" and args.startswith("/C "):
            cmd = args[3:]
        else:
            return {"success": False, "output": [],
                     "error": f"unmocked program {program}"}

        # del /q /f "PATH" ["PATH2"] 2>nul
        m = re.match(r'^del\s+/q\s+/f\s+(.+?)(?:\s+2>nul)?$', cmd)
        if m:
            for tok in re.findall(r'"([^"]+)"', m.group(1)):
                self.fs.pop(self._norm(tok), None)
            return {"success": True, "output": [], "error": ""}

        # echo BASE64>"path"   or   echo BASE64>>"path"
        m = re.match(r'^echo\s+([A-Za-z0-9+/=]+)(>{1,2})"([^"]+)"$', cmd)
        if m:
            chunk, op, path = m.group(1), m.group(2), m.group(3)
            key = self._norm(path)
            existing = self.fs.get(key, b"")
            data = chunk.encode("ascii") + b"\r\n"
            self.fs[key] = data if op == ">" else existing + data
            return {"success": True, "output": [], "error": ""}

        # certutil -decode "src" "dst" >nul
        m = re.match(
            r'^certutil\s+-decode\s+"([^"]+)"\s+"([^"]+)"(?:\s+>nul)?$',
            cmd)
        if m:
            src, dst = self._norm(m.group(1)), self._norm(m.group(2))
            blob = self.fs.get(src, b"")
            clean = re.sub(rb"[^A-Za-z0-9+/=]", b"", blob)
            try:
                self.fs[dst] = base64.b64decode(clean, validate=False)
                return {"success": True, "output": [], "error": ""}
            except Exception as e:
                return {"success": False, "output": [str(e)], "error": ""}

        # certutil -encode "src" "tmp" (writes PEM-wrapped b64 to tmp)
        m = re.match(
            r'^certutil\s+-encode\s+"([^"]+)"\s+"([^"]+)"$', cmd)
        if m:
            src = self._norm(m.group(1))
            dst = self._norm(m.group(2))
            if src not in self.fs:
                return {"success": False,
                         "output": ["CertUtil: -encode command FAILED: 0x1"],
                         "error": ""}
            payload = self.fs[src]
            b64 = base64.b64encode(payload).decode()
            wrapped = "-----BEGIN CERTIFICATE-----\n"
            wrapped += "\n".join(b64[i:i+64]
                                  for i in range(0, len(b64), 64))
            wrapped += "\n-----END CERTIFICATE-----\n"
            self.fs[dst] = wrapped.encode("ascii")
            return {"success": True, "output": [], "error": ""}

        # type "path" — return file contents as output lines
        m = re.match(r'^type\s+"([^"]+)"$', cmd)
        if m:
            path = self._norm(m.group(1))
            if path not in self.fs:
                return {"success": False,
                         "output": ["The system cannot find the file specified."],
                         "error": ""}
            content = self.fs[path]
            if isinstance(content, bytes):
                content = content.decode("ascii", errors="replace")
            return {"success": True,
                     "output": content.split("\n"), "error": ""}

        # certutil -hashfile "path" MD5
        m = re.match(r'^certutil\s+-hashfile\s+"([^"]+)"\s+MD5$', cmd)
        if m:
            path = self._norm(m.group(1))
            if path not in self.fs:
                return {"success": False,
                         "output": ["CertUtil: -hashfile FAILED: 0x2"],
                         "error": ""}
            h = hashlib.md5(self.fs[path]).hexdigest()
            return {"success": True,
                     "output": [f"MD5 hash of {m.group(1)}:", h,
                                 "CertUtil: -hashfile command completed."],
                     "error": ""}

        # dir /-C /A "path"
        m = re.match(r'^dir\s+/-C\s+/A\s+"([^"]+)"$', cmd)
        if m:
            path = self._norm(m.group(1))
            # File?
            if path in self.fs:
                name = ntpath_basename(m.group(1))
                size = len(self.fs[path])
                return {"success": True,
                         "output": [
                            f" Volume in drive C is Windows",
                            f" Directory of {m.group(1)}",
                            f"08/20/2026  09:00 AM              {size} {name}",
                            f"               1 File(s)     {size} bytes",
                         ], "error": ""}
            # Directory? — enumerate entries whose parent is `path`
            prefix = path.rstrip("\\") + "\\"
            children = [(p, data) for p, data in self.fs.items()
                          if p.startswith(prefix)
                          and "\\" not in p[len(prefix):]]
            if not children and prefix != "c:\\windows\\temp\\":
                return {"success": True,
                         "output": ["File Not Found"], "error": ""}
            out = [
                " Volume in drive C is Windows",
                f" Directory of {m.group(1)}",
            ]
            for p, data in sorted(children):
                name = p[len(prefix):]
                out.append(
                    f"08/20/2026  09:00 AM              "
                    f"{len(data)} {name}")
            out.append(
                f"               {len(children)} File(s)  100 bytes")
            out.append("               1 Dir(s)  99999999 bytes free")
            return {"success": True, "output": out, "error": ""}

        # dir /B /A "path" >"tmpfile" — redirect to file
        m = re.match(r'^dir\s+/B\s+/A\s+"([^"]+)"\s+>"([^"]+)"$', cmd)
        if m:
            path = self._norm(m.group(1))
            dst = self._norm(m.group(2))
            prefix = path.rstrip("\\") + "\\"
            children = [(p, data) for p, data in self.fs.items()
                          if p.startswith(prefix)
                          and "\\" not in p[len(prefix):]]
            if not children:
                return {"success": True, "output": [], "error": ""}
            names = "\r\n".join(p[len(prefix):]
                                 for p, _ in sorted(children)) + "\r\n"
            self.fs[dst] = names.encode("ascii")
            return {"success": True, "output": [], "error": ""}

        # dir /B /A "path" — bare names only
        m = re.match(r'^dir\s+/B\s+/A\s+"([^"]+)"$', cmd)
        if m:
            path = self._norm(m.group(1))
            prefix = path.rstrip("\\") + "\\"
            children = [(p, data) for p, data in self.fs.items()
                          if p.startswith(prefix)
                          and "\\" not in p[len(prefix):]]
            if not children:
                return {"success": True,
                         "output": ["File Not Found"], "error": ""}
            out = [p[len(prefix):] for p, _ in sorted(children)]
            return {"success": True, "output": out, "error": ""}

        # mkdir "path"
        m = re.match(r'^mkdir\s+"([^"]+)"$', cmd)
        if m:
            return {"success": True, "output": [], "error": ""}

        # wmic logicaldisk get name
        if cmd.strip().startswith("wmic logicaldisk"):
            return {"success": True,
                     "output": ["Name", "C:", "D:", "P:"],
                     "error": ""}

        return {"success": False, "output": [],
                 "error": f"unmocked cmd tail: {cmd[:100]}"}


def test_windows_upload_roundtrip_verifies_md5(tmp_path):
    target = _FakeWindowsTarget()
    node = _FakeNode(os_type="Windows Server 2019")
    fs = TargetFS(node, target.exec_fn)
    local = tmp_path / "payload.bin"
    payload = b"hello windows world " * 10
    local.write_bytes(payload)
    r = fs.upload(str(local), "C:\\Windows\\Temp\\payload.bin")
    assert r["ok"], r
    assert r["bytes"] == len(payload)
    assert r["md5_local"] == r["md5_remote"]
    assert target.fs["c:\\windows\\temp\\payload.bin"] == payload


def test_windows_upload_mkdir_stat(tmp_path):
    target = _FakeWindowsTarget()
    node = _FakeNode(os_type="Windows")
    fs = TargetFS(node, target.exec_fn)
    r_mkdir = fs.mkdir("C:\\Windows\\Temp\\newdir")
    assert r_mkdir["ok"]

    # Put a file, then stat it
    target.fs["c:\\windows\\temp\\hi.txt"] = b"hey"
    r_stat = fs.stat("C:\\Windows\\Temp\\hi.txt")
    assert r_stat["ok"] and r_stat["exists"]
    assert r_stat["size"] == 3
    assert not r_stat["is_dir"]


def test_windows_download_roundtrip(tmp_path):
    target = _FakeWindowsTarget()
    target.fs["c:\\windows\\temp\\loot.bin"] = b"secret bytes " * 50
    node = _FakeNode(os_type="Windows")
    fs = TargetFS(node, target.exec_fn)
    r = fs.download("C:\\Windows\\Temp\\loot.bin",
                     loot_dir=str(tmp_path))
    assert r["ok"], r
    assert r["bytes"] == len(b"secret bytes " * 50)
    with open(r["loot_path"], "rb") as fh:
        assert fh.read() == b"secret bytes " * 50


def test_windows_list_dir_and_file(tmp_path):
    target = _FakeWindowsTarget()
    target.fs["c:\\windows\\temp\\a.txt"] = b"aaa"
    target.fs["c:\\windows\\temp\\b.log"] = b"bbbbbb"
    node = _FakeNode(os_type="Windows")
    fs = TargetFS(node, target.exec_fn)

    # Directory listing
    r_dir = fs.list_dir("C:\\Windows\\Temp")
    assert r_dir["ok"]
    names = sorted(e["name"] for e in r_dir["entries"])
    assert "a.txt" in names and "b.log" in names

    # Single-file listing (short-circuits to stat)
    r_file = fs.list_dir("C:\\Windows\\Temp\\a.txt")
    assert r_file["ok"]
    assert len(r_file["entries"]) == 1
    assert r_file["entries"][0]["name"] == "a.txt"
    assert r_file["entries"][0]["abs_path"] == "C:\\Windows\\Temp\\a.txt"


def test_windows_stat_missing():
    target = _FakeWindowsTarget()
    node = _FakeNode(os_type="Windows")
    fs = TargetFS(node, target.exec_fn)
    r = fs.stat("C:\\Windows\\Temp\\does_not_exist.txt")
    assert r["ok"]
    assert not r["exists"]


def test_windows_enumerate_drives():
    target = _FakeWindowsTarget()
    node = _FakeNode(os_type="Windows")
    fs = TargetFS(node, target.exec_fn)
    r = fs.enumerate_drives()
    assert r["ok"]
    assert "C:" in r["drives"]
    assert "P:" in r["drives"]
    assert len(r["drives"]) == 3


def test_enumerate_drives_linux_returns_error():
    target = _FakeWindowsTarget()
    node = _FakeNode(os_type="Linux")
    fs = TargetFS(node, target.exec_fn)
    r = fs.enumerate_drives()
    assert not r["ok"]


def test_windows_bare_drive_path_normalized():
    """list_dir('P:') normalizes to 'P:\\' so dir sees a root."""
    target = _FakeWindowsTarget()
    target.fs["p:\\readme.txt"] = b"hello"
    node = _FakeNode(os_type="Windows")
    fs = TargetFS(node, target.exec_fn)
    r = fs.list_dir("P:")
    assert r["ok"]
    assert any(e["name"] == "readme.txt" for e in r["entries"])


def test_windows_list_dir_file_redirect_fallback():
    """When dir /-C /A and dir /B /A both overflow SAPXPG stdout,
    the file-redirect fallback (dir > tmp + type tmp) kicks in."""
    target = _FakeWindowsTarget()
    target.fs["c:\\windows\\temp\\a.txt"] = b"aaa"
    target.fs["c:\\windows\\temp\\b.log"] = b"bbb"
    node = _FakeNode(os_type="Windows")

    # Patch: make non-redirect dir calls return empty for this path
    # to simulate SAPXPG stdout overflow.
    orig_exec = target.exec_fn
    _overflow_path = target._norm("C:\\Windows\\Temp")

    def overflow_exec(program, args):
        # Intercept: if this is a non-redirect dir call on the
        # overflow path, return empty to simulate stdout drop.
        if program.startswith("cmd.exe /C "):
            cmd = program[len("cmd.exe /C "):]
        elif program == "cmd.exe" and args.startswith("/C "):
            cmd = args[3:]
        else:
            cmd = None
        if cmd:
            stripped = cmd.strip()
            # dir /-C /A "path" (no redirect) → empty
            if re.match(r'^dir\s+/-C\s+/A\s+"([^"]+)"$', stripped):
                m = re.match(r'^dir\s+/-C\s+/A\s+"([^"]+)"$', stripped)
                if target._norm(m.group(1)) == _overflow_path:
                    return {"success": True, "output": [], "error": ""}
            # dir /B /A "path" (no redirect) → empty
            if re.match(r'^dir\s+/B\s+/A\s+"([^"]+)"$', stripped):
                m = re.match(r'^dir\s+/B\s+/A\s+"([^"]+)"$', stripped)
                if target._norm(m.group(1)) == _overflow_path:
                    return {"success": True, "output": [], "error": ""}
        return orig_exec(program, args)

    fs = TargetFS(node, overflow_exec)
    r = fs.list_dir("C:\\Windows\\Temp")
    assert r["ok"], r.get("error", "")
    names = {e["name"] for e in r["entries"]}
    assert "a.txt" in names
    assert "b.log" in names
    assert len(r["entries"]) == 2
