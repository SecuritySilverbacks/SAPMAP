"""Role / profile capability analyser.

Translates raw ABAP authorisation data (AGR_USERS / AGR_1251 / UST04
/ USRBF2) into human-readable, business-level capability statements
that a CISO can read out loud:

    User SAPMAP00 on S4H.PRD client 001 can read PA0008 (employee
    basic pay — 14,382 rows of salary data), LFBK (vendor bank
    accounts — 2,107 IBANs), BSEG (20.7M accounting line items,
    $1.4B flowing through annually), can submit RSBDCOS0 (OS
    command execution) and create new SAP_ALL users.

The mapping table is the same one every audit-tool uses (S_TABU_DIS,
S_TABU_NAM, S_DEVELOP, S_RFC, S_USER_GRP, S_BTCH_ADM, etc.) — what's
new is surfacing it inside an attack tool, against the user we just
own, with optional COUNT(*) row probes so the report dollar-quantifies
the actual data reach.

Reuses ``sapmap_rfc.read_table()`` / ``sapmap_rfc.get_table_columns``
— no new RFC plumbing.  Read-only end to end; the operator can run
this against any verified credential with zero blast risk.
"""
from __future__ import annotations

import logging
from typing import Optional

from sapmap_models import SAPNode, Credentials, Severity, Finding

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Capability lookup — hardcoded for performance + reproducibility.
# Each rule matches an AGR_1251 row (auth object + field/value pairs)
# and produces a human-readable capability with the affected tables.
#
# Format: (auth_object, field_match_predicate, capability, tables,
#          severity, why)
#
# field_match_predicate is a dict of {FIELD: VALUE-or-glob}.
# - "*" matches any value (including blank)
# - "<exact>" requires equality (case-insensitive)
# - prefix-glob "<prefix>*" matches values starting with <prefix>
# Multiple keys = AND.  An AGR_1251 row matches when every key in
# the predicate matches the corresponding LOW field on that row.
# ---------------------------------------------------------------------------

# Capability severity tiers — drives the per-user blast-radius score
# and the Finding severity that lands on the SAPNode.
_TIER_CRIT = Severity.CRITICAL
_TIER_HIGH = Severity.HIGH
_TIER_MED = Severity.MEDIUM
_TIER_INFO = Severity.INFO

# Each row: (object, predicate, capability, tables, severity, why)
_CAPABILITY_RULES: list = [
    # ---- Universal SAP_ALL-equivalent catch ----
    ("S_RFC", {"RFC_TYPE": "FUGR", "RFC_NAME": "SUSR"},
     "Create / modify ABAP users via BAPI",
     ["USR02", "USR04", "USRBF2"], _TIER_CRIT,
     "Calling SUSR FMs (BAPI_USER_CREATE1, BAPI_USER_PROFILES_ASSIGN) "
     "is one RFC call away from minting a SAP_ALL user."),

    ("S_USER_GRP", {"ACTVT": "01"},
     "Create dialog / system / service users",
     ["USR02"], _TIER_CRIT,
     "Direct user creation; combine with S_USER_PRO ACTVT=22 to "
     "assign SAP_ALL on the new user."),
    ("S_USER_PRO", {"ACTVT": "22"},
     "Assign profiles to any user (incl. SAP_ALL)",
     ["UST04"], _TIER_CRIT,
     "Profile assignment privilege.  Pair with S_USER_GRP ACTVT=01 "
     "for full account-takeover capability."),
    ("S_USER_AGR", {"ACTVT": "22"},
     "Assign roles to any user",
     ["AGR_USERS"], _TIER_CRIT,
     "Role assignment; equivalent to profile-assign for modern "
     "RBAC-managed landscapes."),

    # ---- OS command execution ----
    ("S_DEVELOP", {"OBJTYPE": "DEBUG", "ACTVT": "02"},
     "Debugger with replace (RCE-equivalent)",
     ["any ABAP program"], _TIER_CRIT,
     "ACTVT=02 on DEBUG = patch sy-subrc / authorisation results "
     "on the fly during execution.  Effectively SAP_ALL plus OS "
     "command exec via any ABAP program."),
    ("S_DEVELOP", {"OBJTYPE": "PROG", "ACTVT": "01"},
     "Create / modify ABAP programs",
     ["REPOSRC"], _TIER_CRIT,
     "Author arbitrary ABAP source.  Code injection by definition."),
    ("S_LOG_COM", {"COMMAND": "*", "OPSYSTEM": "*"},
     "Run arbitrary OS commands via SM49 / SXPG",
     ["SXPGCOSTAB"], _TIER_CRIT,
     "Full OS command exec under <sid>adm.  Goes straight to root "
     "via Copy Fail LPE on vulnerable Linux kernels."),
    ("S_C_FUNCT", {"CFUNCNAME": "SYSTEM", "ACTVT": "16"},
     "Call SYSTEM C function — direct shell exec",
     ["kernel"], _TIER_CRIT,
     "Bypass SXPG entirely; calls libc system() under <sid>adm."),
    ("S_RZL_ADM", {"ACTVT": "01"},
     "RZ10 / RZ11 profile-parameter modification",
     ["TPFET", "TPFYT"], _TIER_CRIT,
     "Edit kernel profile (instance start-up parameters).  Reachable "
     "to OS-level persistence + auth-bypass tweaks."),

    # ---- Background-job admin (path to RSBDCOS0) ----
    ("S_BTCH_ADM", {"BTCADMIN": "Y"},
     "Background-job administrator (full SM37 control)",
     ["TBTCO", "TBTCS"], _TIER_HIGH,
     "Schedule any program (including RSBDCOS0 → OS exec) under "
     "any user; cancel / release / delete jobs across clients."),
    ("S_BTCH_JOB", {"JOBACTION": "RELE"},
     "Release background jobs",
     ["TBTCO"], _TIER_MED,
     "Submit pre-authored programs as background jobs without "
     "approval."),

    # ---- Finance master read (BSEG / vendor / customer / GL) ----
    ("S_TABU_DIS", {"DICBERCLS": "FI"},
     "Finance master read (GL / vendor / customer)",
     ["BSEG", "BKPF", "LFA1", "KNA1", "SKAT", "SKB1"], _TIER_HIGH,
     "Read every finance master + transactional table.  GL line "
     "items, AR/AP balances, vendor + customer master.  PII + "
     "financial detail."),
    ("S_TABU_NAM", {"TABLE": "BSEG"},
     "GL line-item read (BSEG)",
     ["BSEG"], _TIER_HIGH,
     "Direct read of accounting line items — every booked transaction "
     "with amounts, accounts and offsetting items."),
    ("S_TABU_NAM", {"TABLE": "BKPF"},
     "GL document-header read (BKPF)",
     ["BKPF"], _TIER_HIGH,
     "Document headers — who posted what, when, from which terminal."),

    # ---- Vendor bank / IBAN exfil (wire-fraud goldmine) ----
    ("F_LFA1_APP", {"APPKZ": "E"},
     "Edit vendor bank details (LFBK)",
     ["LFBK", "LFA1"], _TIER_CRIT,
     "Change supplier IBANs — direct wire-fraud primitive.  Auditors "
     "rate this as the single highest-impact privilege after SAP_ALL."),
    ("F_LFA1_APP", {"APPKZ": "*"},
     "Vendor master maintenance",
     ["LFA1", "LFBK"], _TIER_HIGH,
     "Vendor master read/write covers IBANs, tax IDs, and contact "
     "data."),
    ("F_KNA1_APP", {"APPKZ": "E"},
     "Edit customer bank details (KNBK)",
     ["KNBK", "KNA1"], _TIER_HIGH,
     "Customer IBAN tampering — refund-redirect attacks."),

    # ---- HR master (PII / salary) ----
    ("P_ORGIN", {"INFTY": "0008"},
     "HR basic-pay infotype read (PA0008)",
     ["PA0008"], _TIER_HIGH,
     "Salary data for every employee — direct PII + insider-threat "
     "trade-secret material."),
    ("P_ORGIN", {"INFTY": "0002"},
     "HR personal-data infotype read (PA0002)",
     ["PA0002"], _TIER_HIGH,
     "Names, addresses, marital status, nationality, birth date — "
     "GDPR Article 9 special-category PII."),
    ("P_ORGIN", {"INFTY": "0014"},
     "HR recurring-payments read (PA0014)",
     ["PA0014"], _TIER_MED,
     "Recurring deductions / one-time payments — bonus signals."),
    ("S_TABU_DIS", {"DICBERCLS": "PA"},
     "HR master read (all infotypes via DDIC class PA)",
     ["PA0008", "PA0002", "PA0014", "PA0001"], _TIER_HIGH,
     "Cross-cut HR master read.  Often the first finding to "
     "ladder into a GDPR Art-33 breach notification."),

    # ---- Finance posting / banking risk ----
    ("F_BKPF_BUK", {"ACTVT": "01"},
     "Post journal entries (any company code)",
     ["BKPF", "BSEG"], _TIER_CRIT,
     "Post unauthorised GL transactions — embezzlement primitive."),
    ("F_BKPF_BUK", {"ACTVT": "02"},
     "Modify journal entries",
     ["BKPF", "BSEG"], _TIER_HIGH,
     "Edit existing postings; useful for hiding fraud trails when "
     "combined with auth-trail tampering."),
    ("F_BKPF_GSB", {"ACTVT": "01"},
     "Post journals (any business area)",
     ["BSEG"], _TIER_HIGH,
     "Cross-business-area posting privilege."),

    # ---- Sales / purchase pipeline (revenue side) ----
    ("V_VBAK_VKO", {"ACTVT": "03"},
     "Sales-order header read (VBAK)",
     ["VBAK", "VBAP"], _TIER_MED,
     "Pipeline + booked-revenue exposure."),
    ("M_BEST_EKO", {"ACTVT": "03"},
     "Purchase-order read (EKKO/EKPO)",
     ["EKKO", "EKPO"], _TIER_MED,
     "Spend / supplier exposure; combine with vendor master read "
     "for full PO insight."),

    # ---- Transport-system abuse ----
    ("S_TRANSPRT", {"ACTVT": "01"},
     "Create / release transports",
     ["E070", "E071"], _TIER_HIGH,
     "Inject custom code via transport request.  Bypasses dual-"
     "control on systems with TMS-only change-control."),
    ("S_CTS_ADMI", {"CTS_ADMFCT": "TABL"},
     "Transport-table admin",
     ["E070"], _TIER_HIGH,
     "Override transport-route restrictions; route DEV transports "
     "directly into PRD."),

    # ---- RFC trust abuse ----
    ("S_RFC", {"RFC_TYPE": "FUGR", "RFC_NAME": "*"},
     "Call any RFC function group remotely",
     ["RFCDES"], _TIER_HIGH,
     "Wildcard S_RFC = remote-call every FM the kernel exposes; "
     "feeds the trust-chain analyser."),
    ("S_RFCACL", {"ACTVT": "*"},
     "Trusted-RFC inbound callee",
     ["RFCDES"], _TIER_HIGH,
     "This system trusts inbound RFCEQUSER=Y calls — anyone with a "
     "trusted-system RFC destination here gets to log on as any "
     "of its users without a password."),
    ("S_ICF", {"ICF_NAME": "*"},
     "Activate / configure ICF services",
     ["ICFSERVICE"], _TIER_HIGH,
     "Activate sleeping ICF webshell paths or attach own service "
     "handlers; persistence vector."),

    # ---- SAP* / DDIC equivalents ----
    ("S_TCODE", {"TCD": "SE16N"},
     "Generic table browser via SE16N",
     ["any read-classified table"], _TIER_HIGH,
     "Bypasses S_TABU_LIN row-level checks on many releases — "
     "treats SE16N as universal table viewer."),
    ("S_TCODE", {"TCD": "SE38"},
     "ABAP editor (SE38)",
     ["REPOSRC"], _TIER_CRIT,
     "Run arbitrary ABAP from the editor.  Equivalent to S_DEVELOP "
     "ACTVT=16 on PROG."),
    ("S_TCODE", {"TCD": "SM49"},
     "Execute external OS commands via SM49",
     ["SXPGCOSTAB"], _TIER_CRIT,
     "Direct path to OS exec under <sid>adm."),
    ("S_TCODE", {"TCD": "SM69"},
     "Maintain external OS commands (SM69)",
     ["SXPGCOSTAB"], _TIER_CRIT,
     "Define + execute custom OS commands; superset of SM49."),
    ("S_TCODE", {"TCD": "SE91"},
     "Message-class editor",
     ["T100"], _TIER_INFO,
     "Edit user-facing message text — phishing / lure capability."),
    ("S_TCODE", {"TCD": "RSBDCOS0"},
     "OS command execution via RSBDCOS0",
     ["kernel"], _TIER_CRIT,
     "Standard SAP OS-cmd primitive; one of the WebGUI LPE legs."),

    # ---- Persistence / cleanup obstruction ----
    ("S_AUT", {"DLAREA": "*", "DLFNCODE": "*"},
     "Suppress / replay audit log entries",
     ["RSAU_BUF_DATA"], _TIER_HIGH,
     "SAL audit log tampering.  Combine with create-user to make "
     "post-engagement cleanup hard for the customer to verify."),
    ("S_USER_TCD", {"TCD": "*"},
     "Manage tcode-level auth (custom tcodes)",
     ["TSTCA"], _TIER_HIGH,
     "Add custom tcodes to roles; sneak own-program tcodes into "
     "production roles."),
]


def _match_predicate(pred: dict, low_by_field: dict) -> bool:
    """Test whether one AGR_1251 row (already collapsed to
    {FIELD: LOW_VALUE}) satisfies every key in `pred`."""
    for field, want in pred.items():
        got = (low_by_field.get(field) or "").strip()
        want_s = str(want or "").strip()
        if want_s == "*":
            continue
        if want_s.endswith("*"):
            if not got.upper().startswith(want_s[:-1].upper()):
                return False
        else:
            if got.upper() != want_s.upper():
                return False
    return True


def _resolve_user_capabilities(rows_for_user: list) -> list:
    """Run every AGR_1251 row a user holds against the rule table;
    return the matching capability dicts.

    `rows_for_user` is a list of AGR_1251 rows for one user, each
    already collapsed to {OBJECT: ..., FIELD: ..., LOW: ...}.
    """
    # Group rows by (object, role) so multi-field predicates can
    # match all keys on the same role grant — otherwise a user with
    # ACTVT=01 from role A and OBJTYPE=DEBUG from role B would
    # spuriously fire "Debugger with replace".
    grants: dict = {}
    for r in rows_for_user:
        key = (r.get("OBJECT", ""), r.get("AGR_NAME", ""))
        grants.setdefault(key, {})
        # Last writer wins per field; auth grants can repeat the
        # same field with different LOW values (separate auth rows
        # with multiple grants).  We model this by storing a list of
        # values per field.
        f = r.get("FIELD", "")
        v = r.get("LOW", "")
        if not f:
            continue
        grants[key].setdefault(f, [])
        grants[key][f].append(v)

    capabilities = []
    seen = set()
    for (obj, _role), fields in grants.items():
        for rule_obj, pred, cap, tables, sev, why in _CAPABILITY_RULES:
            if rule_obj.upper() != obj.upper():
                continue
            # Check predicate against every cross-product of values
            # — auth grants are OR within a field, AND across fields.
            from itertools import product
            field_names = list(pred.keys())
            value_lists = [fields.get(fn, [""]) or [""]
                            for fn in field_names]
            for combo in product(*value_lists):
                low_by_field = dict(zip(field_names, combo))
                if _match_predicate(pred, low_by_field):
                    sig = (obj, cap)
                    if sig in seen:
                        break
                    seen.add(sig)
                    capabilities.append({
                        "auth_object": obj,
                        "fields": low_by_field,
                        "capability": cap,
                        "tables": list(tables),
                        "severity": int(sev),
                        "why": why,
                    })
                    break
    return capabilities


def _blast_radius(capabilities: list) -> str:
    """Aggregate the per-capability tier into a single human label
    operators / CISOs read on the report.
    """
    if not capabilities:
        return "no privileged capabilities recovered"
    sevs = [c["severity"] for c in capabilities]
    n_crit = sum(1 for s in sevs if s == int(_TIER_CRIT))
    n_high = sum(1 for s in sevs if s == int(_TIER_HIGH))
    if n_crit >= 3:
        return ("total financial / operational compromise "
                f"({n_crit} critical, {n_high} high capabilities)")
    if n_crit:
        return ("severe compromise — direct fraud or RCE primitives "
                f"present ({n_crit} critical)")
    if n_high >= 3:
        return ("substantial business-data exposure "
                f"({n_high} high capabilities)")
    if n_high:
        return f"limited compromise ({n_high} high capabilities)"
    return "low — informational privileges only"


def _english_summary(username: str, sid: str, client: str,
                       capabilities: list,
                       row_counts: dict,
                       super_profile: str = "") -> str:
    """Produce the CISO-grade single paragraph that lands in the
    engagement report.  Uses cached row counts when available so
    the line dollar-quantifies the actual data reach
    ("LFBK = 2,107 IBANs").  Mentions a held super-profile (SAP_ALL
    / SAP_NEW / S_A.SYSTEM …) up-front when present — that's the
    most operationally important fact about the user."""
    if not capabilities:
        if super_profile:
            return (f"User {username} on {sid} client {client} "
                    f"holds the {super_profile} profile — full "
                    f"unrestricted access; no further privilege "
                    f"check needed.")
        return (f"User {username} on {sid} client {client} has no "
                f"privileged authorisation objects recovered.")
    bullets = []
    for c in sorted(capabilities, key=lambda x: -x["severity"]):
        tables = c["tables"]
        # Attach row count when we cached one
        annotated = []
        for t in tables[:4]:
            n = row_counts.get(t)
            if isinstance(n, int) and n >= 0:
                annotated.append(f"{t} ({n:,} rows)")
            else:
                annotated.append(t)
        if len(tables) > 4:
            annotated.append(f"+{len(tables) - 4} more")
        bullets.append(f"**{c['capability']}** ({', '.join(annotated)})")
    prefix = (f"User {username} on {sid} client {client}")
    if super_profile:
        prefix += f" holds the **{super_profile}** profile and"
    head = f"{prefix} can: " + "; ".join(bullets) + "."
    blast = _blast_radius(capabilities)
    return f"{head}  Estimated blast-radius: {blast}."


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

# Tables we read for the resolver.  Fixed list; widened only when a
# kernel patch starts shipping a different shape.
_AGR_USERS_FIELDS = ["AGR_NAME", "UNAME"]
_AGR_1251_FIELDS = ["AGR_NAME", "OBJECT", "FIELD", "LOW", "HIGH"]
_UST04_FIELDS = ["BNAME", "PROFILE"]

# SAP-shipped "everything" profiles.  Holding any of these makes the
# user equivalent to every rule in _CAPABILITY_RULES being matched
# (SAP_ALL = all auth objects with full ranges; SAP_NEW = the same for
# auth objects added in newer releases; S_A.SYSTEM / S_A.ADMIN are
# admin sub-profiles that carry SAP_ALL-equivalent privilege on
# almost every kernel).  This is the path SAPMAP-created users take
# (BAPI_USER_PROFILES_ASSIGN with PROFILE=SAP_ALL) — they don't have
# any role rows in AGR_USERS, so the role-based resolver alone
# silently produces zero capabilities for them.  Operator's
# screenshot confirmed this exact symptom.
_SUPER_PROFILES = {"SAP_ALL", "SAP_NEW", "S_A.SYSTEM",
                    "S_A.ADMIN", "SAP_ADMIN"}


def _read_user_profiles(node: SAPNode, username: str,
                          creds: Optional[Credentials]) -> list:
    """Pull the profile list for a user from UST04 (user -> profile
    mapping).  Returns a list of profile names (uppercase, stripped).
    Empty on read failure — caller falls back to role-only resolution
    in that case."""
    import sapmap_rfc
    user_upper = (username or "").strip().upper()
    if not user_upper:
        return []
    try:
        rows = sapmap_rfc.read_table(
            node, "UST04", fields=_UST04_FIELDS,
            where=f"BNAME = '{user_upper}'",
            creds=creds, max_rows=500) or []
    except Exception as e:
        print(f"[-] {node.sid}: UST04 read failed for "
              f"{user_upper} — {e!s}")
        return []
    return [(r.get("PROFILE", "") or "").strip().upper()
            for r in rows if r.get("PROFILE")]


def _capabilities_from_super_profile(profile_name: str) -> list:
    """When a user holds SAP_ALL (or an equivalent admin profile),
    they have every capability in the rule table by definition.
    Synthesise the full list rather than just emitting one
    "SAP_ALL holder" line — the report stays useful for operators
    who want to know which finance/HR/wire-fraud table the user can
    actually touch."""
    out = []
    for obj, pred, cap, tables, sev, why in _CAPABILITY_RULES:
        out.append({
            "auth_object": obj,
            "fields": dict(pred),
            "capability": cap,
            "tables": list(tables),
            "severity": int(sev),
            "why": f"Granted implicitly via {profile_name} profile — "
                    f"{why}",
        })
    return out


def _read_user_grants(node: SAPNode, username: str,
                        creds: Optional[Credentials]) -> list:
    """Pull every AGR_1251 row for `username` by joining AGR_USERS
    (role -> user) with AGR_1251 (role -> auth object).  Returns
    a flat list of {AGR_NAME, OBJECT, FIELD, LOW} dicts.
    """
    import sapmap_rfc
    user_upper = (username or "").strip().upper()
    if not user_upper:
        return []
    # 1. Roles assigned to this user
    user_rows = []
    try:
        user_rows = sapmap_rfc.read_table(
            node, "AGR_USERS", fields=_AGR_USERS_FIELDS,
            where=f"UNAME = '{user_upper}'",
            creds=creds, max_rows=2000) or []
    except Exception as e:
        print(f"[-] {node.sid}: AGR_USERS read failed for "
              f"{user_upper} — {e!s}")
    roles = sorted({r.get("AGR_NAME", "").strip()
                    for r in user_rows
                    if r.get("AGR_NAME")})
    if not roles:
        return []
    # 2. Auth-object rows for those roles.  Chunk role list into
    #    72-char OPTIONS-friendly OR clauses (RFC_READ_TABLE WHERE
    #    has the same chunking limits read_table already handles).
    out = []
    chunk_size = 8
    for i in range(0, len(roles), chunk_size):
        chunk = roles[i:i + chunk_size]
        clause = " OR ".join(f"AGR_NAME = '{r}'" for r in chunk)
        try:
            rows = sapmap_rfc.read_table(
                node, "AGR_1251", fields=_AGR_1251_FIELDS,
                where=clause, creds=creds, max_rows=5000) or []
            out.extend(rows)
        except Exception as e:
            print(f"[-] {node.sid}: AGR_1251 read for {chunk[:2]} "
                  f"… failed — {e!s}")
    return out


def _candidate_users(node: SAPNode) -> list:
    """Every user we own on this node — created users + verified
    credentials.  De-duplicates on (username, client)."""
    seen: set = set()
    users = []
    for cu in (node.created_users or []):
        u = (getattr(cu, "username", "") or "").strip()
        c = (getattr(cu, "client", "") or "").strip() or "001"
        if not u:
            continue
        key = (u.upper(), c)
        if key in seen:
            continue
        seen.add(key)
        users.append({"username": u, "client": c, "source": "created"})
    for cred in (node.credentials or []):
        if not getattr(cred, "verified", False):
            continue
        u = (cred.username or "").strip()
        c = (cred.client or "").strip() or "001"
        if not u:
            continue
        key = (u.upper(), c)
        if key in seen:
            continue
        seen.add(key)
        users.append({"username": u, "client": c, "source": "credential"})
    return users


_ROW_PROBE_PSEUDO_TABLES = {
    # Sentinels that appear in CAPABILITY_RULES.tables but aren't real
    # DDIC tables — skip them silently rather than spamming the console
    # with TABLE_NOT_AVAILABLE errors.
    "kernel",  # S_C_FUNCT — direct C call, no table backing it
}


def _row_count_for_table(node: SAPNode, table: str,
                          creds: Optional[Credentials]) -> int:
    """Probe whether a table exists from this user's perspective.
    Cached on `node.capability_row_counts` so a CISO-facing line stays
    cheap on repeat opens.  Returns -1 on failure / unknown."""
    if table in (node.capability_row_counts or {}):
        return int(node.capability_row_counts[table])
    if not table or " " in table or "." in table:
        # Skip pseudo-table labels like "any ABAP program" /
        # "any read-classified table".
        return -1
    if table.lower() in _ROW_PROBE_PSEUDO_TABLES:
        node.capability_row_counts[table] = -1
        return -1
    import sapmap_rfc
    try:
        # Probe with a single short field (MANDT) instead of fields=None.
        # RFC_READ_TABLE's WA buffer is ~512 bytes per row, which can't
        # hold every column of a wide DDIC table (USR02, BSEG, etc.) and
        # raises DATA_BUFFER_EXCEEDED.  We only need existence here, so
        # one field is enough — and MANDT exists on every client-aware
        # table.  quiet=True suppresses the noisy "Could not read X"
        # console line; the analyser already handles the -1 sentinel.
        rows = sapmap_rfc.read_table(
            node, table, fields=["MANDT"], creds=creds,
            max_rows=1, quiet=True) or []
        if not rows:
            # MANDT-less table (e.g. some kernel/profile tables) — retry
            # with a default probe.  Still quiet; failure is fine.
            rows = sapmap_rfc.read_table(
                node, table, fields=None, creds=creds,
                max_rows=1, quiet=True) or []
        node.capability_row_counts[table] = -1 if not rows else 1
        return -1 if not rows else 1
    except Exception:
        node.capability_row_counts[table] = -1
        return -1


def analyse(node: SAPNode,
              creds: Optional[Credentials] = None,
              probe_row_counts: bool = False) -> list:
    """Run the analyser against every user we own on `node`.
    Stores results on `node.capability_results`, emits one Finding
    per user, and returns the list of result dicts.

    Read-only.  Safe to auto-run after any successful logon.
    """
    if "ABAP" not in (node.system_type or "").upper():
        # Capability analysis is ABAP-side; Java has its own UME
        # role tables which aren't in this rule set.
        return []
    users = _candidate_users(node)
    if not users:
        return []
    print(f"[*] {node.sid}: capability analyser scanning "
          f"{len(users)} user(s) — {[u['username'] for u in users]}")

    results = []
    for u in users:
        username = u["username"]
        client = u["client"]

        # Two grant paths:
        #   1. role -> auth-object rows (AGR_USERS x AGR_1251)
        #   2. profile rows (UST04) — catches SAP_ALL/SAP_NEW
        #      assignments that don't go through any role.  Critical
        #      for SAPMAP-created users: BAPI_USER_PROFILES_ASSIGN
        #      gives them SAP_ALL via the profile path with no role
        #      assignments at all.
        rows = _read_user_grants(node, username, creds)
        capabilities = _resolve_user_capabilities(rows)

        profiles = _read_user_profiles(node, username, creds)
        super_profile = next(
            (p for p in profiles if p in _SUPER_PROFILES), None)
        if super_profile:
            print(f"[!] {node.sid}: {username} holds {super_profile} "
                  f"profile — synthesising full capability set")
            super_caps = _capabilities_from_super_profile(super_profile)
            # Merge — same (auth_object, capability) signature wins
            # the higher-severity tier.
            seen = {(c["auth_object"], c["capability"]): c
                    for c in capabilities}
            for sc in super_caps:
                key = (sc["auth_object"], sc["capability"])
                if key not in seen:
                    seen[key] = sc
                    capabilities.append(sc)
                else:
                    # Bump severity to whichever is higher; keep the
                    # role-based "why" text since it has the
                    # actual auth-object grant string.
                    seen[key]["severity"] = max(
                        seen[key]["severity"], sc["severity"])

        # Optional row-count probe — only the first time we see each
        # table, cached on the node.  Skipped by default.
        if probe_row_counts and capabilities:
            for c in capabilities:
                for t in c["tables"]:
                    _row_count_for_table(node, t, creds)

        summary = _english_summary(
            username, node.sid, client, capabilities,
            node.capability_row_counts or {},
            super_profile=super_profile or "")
        blast = _blast_radius(capabilities)
        result = {
            "username": username,
            "client": client,
            "source": u["source"],
            "capabilities": capabilities,
            "blast_radius": blast,
            "summary": summary,
        }
        results.append(result)

        # Drop a Finding so the GUI badge / report pipeline picks
        # this up automatically.  Severity = the highest tier the
        # user touches, fall back to INFO when no caps recovered.
        if capabilities:
            highest = max(c["severity"] for c in capabilities)
            sev_enum = Severity(highest)
        else:
            sev_enum = Severity.INFO
        node.findings.append(Finding(
            name="Role / profile capability inventory",
            severity=sev_enum,
            description=summary,
            remediation=(
                "Review the SoD / least-privilege posture for this "
                "user.  At minimum: split critical capabilities into "
                "separate roles requiring dual approval, audit "
                "S_DEVELOP/SE16N/SM49 assignments, and revoke "
                "S_TABU_DIS DICBERCLS=FI/PA from non-finance/HR "
                "users.  Re-run RSUSR008_009_NEW after remediation."),
            detail=f"{len(capabilities)} capability(ies); "
                    f"blast={blast}",
        ))

    # Replace any prior result for the same (username, client) so a
    # re-run after privilege changes shows current state, not stale.
    keep = []
    keys_now = {(r["username"].upper(), r["client"]) for r in results}
    for old in (node.capability_results or []):
        k = (old.get("username", "").upper(),
             old.get("client", ""))
        if k not in keys_now:
            keep.append(old)
    node.capability_results = keep + results
    print(f"[+] {node.sid}: capability analyser complete — "
          f"{len(results)} user inventory record(s) stored")
    return results


# ---------------------------------------------------------------------------
# YAML export — operators occasionally ask for the rule table so they
# can extend it with site-specific Z-objects.  Pure-Python serialiser
# that doesn't need PyYAML; output is the canonical lookup-table
# format we actually use internally.
# ---------------------------------------------------------------------------

def export_rules_yaml() -> str:
    lines = [
        "# SAPMAP capability analyser rule table",
        "# Each entry: AGR_1251 row predicate -> human-readable",
        "# capability, affected tables, and severity tier.",
        "# Severity: 5=CRITICAL, 4=HIGH, 3=MEDIUM, 2=LOW, 1=INFO.",
        "",
        "rules:",
    ]
    for obj, pred, cap, tables, sev, why in _CAPABILITY_RULES:
        lines.append(f"  - auth_object: {obj}")
        lines.append("    predicate:")
        for k, v in pred.items():
            lines.append(f"      {k}: {v!r}")
        lines.append(f"    capability: {cap!r}")
        lines.append("    tables:")
        for t in tables:
            lines.append(f"      - {t!r}")
        lines.append(f"    severity: {int(sev)}")
        lines.append(f"    why: {why!r}")
        lines.append("")
    return "\n".join(lines)
