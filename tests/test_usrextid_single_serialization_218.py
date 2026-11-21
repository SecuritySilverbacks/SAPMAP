"""usrextid_entries is declared + serialized exactly once (issue #218).

Issue #218 flagged ``usrextid_entries`` as duplicated — the report
framed it as "top-level + nested, both written whole, ~30 KB disk
waste."  Investigation corrected that: the field was declared TWICE
on ``SAPNode`` (dead first decl, overridden by the second) and the
key was emitted TWICE in ``SAPNode.to_dict()`` (dead first key,
overridden by the second in the dict literal).  Python dedupes both,
so the on-disk JSON always had exactly ONE copy per node — there was
never any disk doubling.  The defect was dead/confusing SOURCE: editing
the first occurrence silently had no effect, a maintenance trap and a
lint smell (flake8 F601 duplicate-key / F811 redefinition).

These tests pin the single-occurrence invariant at every layer so the
duplicate can't silently creep back:
  1. the dataclass exposes exactly one ``usrextid_entries`` field;
  2. ``to_dict()`` emits the key exactly once (guards the dict-literal
     dedup — a re-added duplicate would still pass a naive round-trip
     test, so we assert against the source, see below, AND the dict);
  3. the serialized JSON string contains the key exactly once per node;
  4. a full round-trip through SAPMAPState preserves the value.
"""
import ast
import json
import os

from dataclasses import fields

from sapmap_models import SAPNode, SAPMAPState


_MODELS_SRC = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "modules", "core", "sapmap_models.py",
)


def _sample_rows():
    # Mixed-shape rows exercise BOTH documented populate paths:
    #   * USREXTID table read  → MANDT/BNAME/EXTID/TYPE/SEQNO
    #   * STRUSTSSO2 user-kind → extid/bname/trusting_client/source
    return [
        {"MANDT": "001", "BNAME": "DDIC", "EXTID": "CN=ddic,O=SAP",
         "TYPE": "DN", "SEQNO": "000"},
        {"extid": "CN=svc,O=corp", "bname": "SVC_USER",
         "trusting_client": "100", "source": "strustsso2"},
    ]


def test_dataclass_resolves_usrextid_entries_to_one_field():
    """Runtime sanity: the resolved dataclass schema exposes exactly one
    ``usrextid_entries`` field.

    NOTE: this does NOT catch a re-added duplicate *declaration* —
    ``dataclasses.fields()`` reads name-deduped ``__annotations__`` so
    it returns 1 regardless of how many times the field appears in the
    source.  The authoritative regression guard against the #218
    duplicate is the AST check below
    (``test_source_has_no_duplicate_key_or_field``).  This test only
    documents that the resolved schema is singular."""
    n = sum(1 for f in fields(SAPNode) if f.name == "usrextid_entries")
    assert n == 1, f"expected 1 usrextid_entries field, found {n}"


def test_to_dict_emits_key_once():
    """Runtime node dict has exactly one ``usrextid_entries`` key."""
    node = SAPNode(sid="NPL", hostname="h", ip="10.0.0.1")
    node.usrextid_entries = _sample_rows()
    d = node.to_dict()
    n = sum(1 for k in d if k == "usrextid_entries")
    assert n == 1, f"expected 1 key in node dict, found {n}"
    assert d["usrextid_entries"] == _sample_rows()


def test_source_has_no_duplicate_key_or_field():
    """Parse sapmap_models.py and assert the SOURCE carries no duplicate
    ``usrextid_entries`` — a dict literal / dataclass body dedupes at
    runtime so a re-introduced duplicate would pass the runtime tests
    above.  This AST check is the real regression guard: it counts
    occurrences in SAPNode's class body (annotated assignments) and in
    its to_dict() return-dict literal (string keys)."""
    with open(_MODELS_SRC, encoding="utf-8") as f:
        tree = ast.parse(f.read())

    sapnode = next(
        node for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef) and node.name == "SAPNode"
    )

    # (a) annotated field declarations in the class body
    field_decls = sum(
        1 for stmt in sapnode.body
        if isinstance(stmt, ast.AnnAssign)
        and isinstance(stmt.target, ast.Name)
        and stmt.target.id == "usrextid_entries"
    )
    assert field_decls == 1, (
        f"SAPNode source declares usrextid_entries {field_decls} times "
        f"(expected 1) — a duplicate dataclass field is dead code")

    # (b) string keys in the to_dict() return-dict literal
    to_dict_fn = next(
        fn for fn in sapnode.body
        if isinstance(fn, ast.FunctionDef) and fn.name == "to_dict"
    )
    key_count = 0
    for sub in ast.walk(to_dict_fn):
        if isinstance(sub, ast.Dict):
            for k in sub.keys:
                if isinstance(k, ast.Constant) and k.value == "usrextid_entries":
                    key_count += 1
    assert key_count == 1, (
        f"SAPNode.to_dict() literal has usrextid_entries as a key "
        f"{key_count} times (expected 1) — a duplicate dict key is "
        f"dead (last wins) and trips flake8 F601")


def test_serialized_json_has_one_occurrence_per_node():
    """The serialized state JSON must carry ``usrextid_entries`` exactly
    once per node — the original issue's stated worry (two whole copies
    on disk).  Two nodes → exactly two occurrences."""
    state = SAPMAPState()
    for sid in ("NPL", "S4H"):
        node = SAPNode(sid=sid, hostname=sid.lower(), ip="10.0.0.1")
        node.usrextid_entries = _sample_rows()
        state.add_node(node)
    js = state.to_json()
    occurrences = js.count('"usrextid_entries"')
    assert occurrences == 2, (
        f"expected 1 usrextid_entries per node (2 nodes → 2), "
        f"found {occurrences} in serialized JSON")


def test_round_trip_preserves_usrextid_cluster():
    """A full SAPMAPState save/load keeps the whole USREXTID /
    PP-impersonation cluster.  ``to_dict`` always serialized these but
    ``from_dict`` dropped ``usrextid_read_at`` + the three pp_* fields,
    so a reload silently lost the "last read" timestamp and the entire
    PP-impersonation analysis the #167 Phase-F report renders.  Fixed
    alongside the #218 dedup; this test pins the symmetry."""
    state = SAPMAPState()
    node = SAPNode(sid="NPL", hostname="h", ip="10.0.0.1")
    node.usrextid_entries = _sample_rows()
    node.usrextid_read_at = "2026-11-21T10:00:00"
    node.pp_impersonation = {"scc_host": "scc1", "matched_users": ["DDIC"]}
    node.pp_verification = {"ok": True, "verified_at": "2026-11-21T10:05:00"}
    node.pp_verification_confirmed = True
    state.add_node(node)

    restored = SAPMAPState.from_dict(json.loads(state.to_json()))
    rnode = restored.get_node("NPL")
    assert rnode is not None
    assert rnode.usrextid_entries == _sample_rows()
    assert rnode.usrextid_read_at == "2026-11-21T10:00:00"
    assert rnode.pp_impersonation == {"scc_host": "scc1",
                                      "matched_users": ["DDIC"]}
    assert rnode.pp_verification == {"ok": True,
                                     "verified_at": "2026-11-21T10:05:00"}
    assert rnode.pp_verification_confirmed is True


def test_from_dict_defaults_empty_when_absent():
    """A legacy .sapmap node dict with no usrextid_entries key loads to
    an empty list, not a KeyError — the on-disk format was always a
    single key, so there is no 'nested form' to fall back to."""
    node_d = SAPNode(sid="OLD", hostname="old", ip="10.0.0.9").to_dict()
    node_d.pop("usrextid_entries", None)
    restored = SAPNode.from_dict(node_d)
    assert restored.usrextid_entries == []


def test_explicit_null_pp_fields_do_not_crash_load():
    """A hand-edited / forensic .sapmap (external consumers #218 names)
    with an explicit JSON ``null`` for the PP cluster must load to empty
    defaults, not crash the whole SAPMAPState.from_dict with
    ``TypeError: dict(None)``.  from_dict's ``or {}`` / ``or ""`` guards
    mirror to_dict's own None-handling so the round-trip is symmetric
    even for values SAPMAP's own serializer never writes."""
    node_d = SAPNode(sid="NUL", hostname="n", ip="10.0.0.7").to_dict()
    node_d["pp_impersonation"] = None
    node_d["pp_verification"] = None
    node_d["usrextid_read_at"] = None
    node_d["usrextid_entries"] = None
    restored = SAPNode.from_dict(node_d)
    assert restored.pp_impersonation == {}
    assert restored.pp_verification == {}
    assert restored.usrextid_read_at == ""
    assert restored.usrextid_entries == []


def test_to_dict_from_dict_key_symmetry():
    """GENERAL regression guard for the serialize-but-never-deserialize
    bug class this PR repaired for the PP cluster.

    Parse SAPNode and assert that every string key emitted by the
    ``to_dict()`` return-literal is read back as a keyword argument in
    the ``from_dict()`` ``cls(...)`` constructor call.  Had this guard
    existed, the dropped ``usrextid_read_at`` / ``pp_impersonation`` /
    ``pp_verification`` / ``pp_verification_confirmed`` reads would have
    failed the suite instead of silently discarding loot on reload.

    Scoped to SAPNode (the class #218 touches).  Keys intentionally
    excluded from the constructor (none today) would be listed in
    ``_WRITE_ONLY`` with a reason."""
    _WRITE_ONLY = set()  # keys to_dict writes that from_dict deliberately omits

    with open(_MODELS_SRC, encoding="utf-8") as f:
        tree = ast.parse(f.read())
    sapnode = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.ClassDef) and n.name == "SAPNode"
    )

    to_dict_fn = next(
        fn for fn in sapnode.body
        if isinstance(fn, ast.FunctionDef) and fn.name == "to_dict"
    )
    written = set()
    for sub in ast.walk(to_dict_fn):
        if isinstance(sub, ast.Dict):
            for k in sub.keys:
                if isinstance(k, ast.Constant) and isinstance(k.value, str):
                    written.add(k.value)

    from_dict_fn = next(
        fn for fn in sapnode.body
        if isinstance(fn, ast.FunctionDef) and fn.name == "from_dict"
    )
    read = set()
    for sub in ast.walk(from_dict_fn):
        if isinstance(sub, ast.Call):
            for kw in sub.keywords:
                if kw.arg:          # named kwarg (skips **kwargs splat)
                    read.add(kw.arg)

    dropped = written - read - _WRITE_ONLY
    assert not dropped, (
        f"SAPNode.to_dict() writes keys that from_dict() never reads "
        f"back — they are silently lost on every .sapmap reload: "
        f"{sorted(dropped)}")
