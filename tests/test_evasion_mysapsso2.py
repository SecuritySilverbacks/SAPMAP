"""Tests for Tier 2 T2.4 — MYSAPSSO2 service-user-first identity fanout."""

from sapmap_evasion import (EvasionConfig, effective_mysapsso2_users,
                              MYSAPSSO2_BLENDER_USERS,
                              MYSAPSSO2_ESCALATION_USERS)


# ---------------------------------------------------------------------------
# Constant pool contents — guard against accidental edits
# ---------------------------------------------------------------------------

def test_blender_pool_does_not_include_textbook_iocs():
    """SAP*, DDIC, SAP_NEW, SAPSYS are the strings every SAP SIEM
    rule looks for — they must never appear in the blender pool."""
    iocs = {"SAP*", "DDIC", "SAP_NEW", "SAPSYS", "SAPADM", "EARLYWATCH"}
    blender = set(MYSAPSSO2_BLENDER_USERS)
    assert blender.isdisjoint(iocs)


def test_escalation_pool_holds_sap_star_and_ddic():
    assert "SAP*" in MYSAPSSO2_ESCALATION_USERS
    assert "DDIC" in MYSAPSSO2_ESCALATION_USERS


def test_blender_pool_includes_canonical_service_users():
    """At least the four most common service-RFC identities should be
    in the blender pool — these are the ones that blend with normal
    background traffic on every standard SAP install."""
    expected = {"CPIC_USER", "SAPCPIC", "TMSADM", "SOLMAN_BTC"}
    blender = set(MYSAPSSO2_BLENDER_USERS)
    assert expected <= blender


# ---------------------------------------------------------------------------
# Selector — ordering and override behaviour
# ---------------------------------------------------------------------------

def test_default_ordering_is_blender_first_escalation_last():
    users, mode = effective_mysapsso2_users(EvasionConfig())
    assert mode == "blender_first"
    # Blender users must all come before any escalation user
    last_blender_idx = max(users.index(u) for u in MYSAPSSO2_BLENDER_USERS)
    first_escalation_idx = min(users.index(u)
                                for u in MYSAPSSO2_ESCALATION_USERS)
    assert last_blender_idx < first_escalation_idx, (
        f"Escalation user appeared before a blender user in {users}")


def test_none_evasion_treated_as_default_blender_first():
    users, mode = effective_mysapsso2_users(None)
    assert mode == "blender_first"
    assert "CPIC_USER" in users
    assert users.index("CPIC_USER") < users.index("SAP*")


def test_operator_override_used_verbatim_no_escalation_appended():
    """When the operator pins a specific list (e.g. 'just CPIC_USER'),
    we honour it exactly — no SAP*/DDIC tacked on, no reordering."""
    cfg = EvasionConfig(mysapsso2_users="CPIC_USER,TMSADM")
    users, mode = effective_mysapsso2_users(cfg)
    assert mode == "operator"
    assert users == ("CPIC_USER", "TMSADM")
    assert "SAP*" not in users
    assert "DDIC" not in users


def test_operator_override_preserves_explicit_order():
    cfg = EvasionConfig(mysapsso2_users="DDIC,SAP*,CPIC_USER")
    users, _ = effective_mysapsso2_users(cfg)
    assert users == ("DDIC", "SAP*", "CPIC_USER")


def test_operator_override_strips_whitespace_and_empties():
    cfg = EvasionConfig(mysapsso2_users=" CPIC_USER , , TMSADM ")
    users, mode = effective_mysapsso2_users(cfg)
    assert users == ("CPIC_USER", "TMSADM")
    assert mode == "operator"


def test_blank_operator_override_falls_back_to_default():
    cfg = EvasionConfig(mysapsso2_users="   ")
    users, mode = effective_mysapsso2_users(cfg)
    assert mode == "blender_first"


def test_evasion_config_roundtrip_preserves_mysapsso2_users():
    cfg = EvasionConfig(mysapsso2_users="CPIC_USER,SAPCPIC")
    d = cfg.to_dict()
    cfg2 = EvasionConfig.from_dict(d)
    assert cfg2.mysapsso2_users == "CPIC_USER,SAPCPIC"


# ---------------------------------------------------------------------------
# Autopwn integration — uses the selector, not the hardcoded list
# ---------------------------------------------------------------------------

def test_autopwn_default_ticket_users_is_blender_first():
    """Backstop: the module-level constant must reflect the
    blender-first pool — regression for the original
    `("SAP*", "DDIC")` hardcoded ordering that put both IoC identities
    at the front."""
    import sapmap_autopwn
    first = sapmap_autopwn._AUTOPWN_TICKET_USERS[0]
    assert first in MYSAPSSO2_BLENDER_USERS, (
        f"First fanout identity {first!r} is not in the blender pool "
        "— SAP* / DDIC must not be tried first")
    # And both escalation identities must still be in the fanout list,
    # just at the tail end.
    assert "SAP*" in sapmap_autopwn._AUTOPWN_TICKET_USERS
    assert "DDIC" in sapmap_autopwn._AUTOPWN_TICKET_USERS


def test_forge_default_tickets_uses_effective_selector():
    """The forge loop body should reference effective_mysapsso2_users
    so operator overrides via state.evasion take effect at run time
    rather than being baked in at module import."""
    import inspect
    import sapmap_autopwn
    src = inspect.getsource(sapmap_autopwn._forge_default_tickets)
    assert "effective_mysapsso2_users" in src
