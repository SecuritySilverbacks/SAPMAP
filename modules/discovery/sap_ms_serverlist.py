"""sap_ms_serverlist — enumerate SAP application servers via the public
Message Server protocol (binary, port 36NN).

The Message Server's *public* port (3600 + instance number) exists so
that SAPGUI / RFC clients can resolve logon groups to the concrete
application servers behind them — i.e. ask the MS "which app servers
are up and what are their dispatcher ports?".  That same, entirely
*intended*, request returns the full server list to any client that
completes the (passwordless) external login.  No exploit, no ACL
bypass: this is the load-balancing query the port is designed to
answer.  Where ``ms/acl_info_ext`` / the external ACL is left at its
permissive default, it answers anyone on the network.

Protocol (verified against OWASP pysap ``pysap/SAPMS.py`` and the
``ms_monitor`` / ``ms_dump_info`` example clients):

    1. NI frame everything: 4-byte big-endian length prefix + payload.
    2. LOGIN_2  — flag=UNKNOWN(0x00) iflag=LOGIN_2(0x08),
                   toname == fromname == our client name.
                   The reply's ``fromname`` is the MS's own server
                   name, which we must quote as ``toname`` afterwards.
    3. MS_SERVER_LST (opcode 0x05) — flag=REQUEST(0x02)
                   iflag=SEND_NAME(0x01).  Reply carries N fixed-size
                   client records; the reply's ``opcode_version`` byte
                   (1..4) selects the record layout (SAPMSClient1..4).

Each record yields the application server's logical name, host,
dispatcher service/port, active work-process types (DIA/UPD/ENQ/…),
IP address and status — exactly the landscape-fan-out data SAPMAP's
discovery wants from a single known Message Server.

Read-only, stateless, performs only the documented login + list query.
For authorised security testing only — see DISCLAIMER.md.
"""
from __future__ import annotations

import socket
import struct
from typing import Optional

# Reuse the single source of truth for SAP NI framing + the SAPMS
# header wire format.  `modules/__init__.py` puts every subpackage on
# sys.path, so this flat import resolves for normal in-app use; when the
# file is run directly as a script that bootstrap hasn't happened yet, so
# import the top-level `modules` package once to trigger it.
try:
    from sap_ms_betrusted import ms_build_header  # noqa: F401  (probe)
except ModuleNotFoundError:  # pragma: no cover — direct `python3 …` run
    import os as _os
    import sys as _sys
    _root = _os.path.dirname(_os.path.dirname(_os.path.dirname(
        _os.path.abspath(__file__))))
    if _root not in _sys.path:
        _sys.path.insert(0, _root)
    import modules  # noqa: F401  — registers every subpackage on sys.path

from sap_ms_betrusted import (
    ni_send, ni_recv,
    ms_build_header, ms_parse_header, ms_parse_opcode,
    FLAG_UNKNOWN, FLAG_REQUEST,
    IFLAG_LOGIN_2, IFLAG_SEND_NAME,
    MSG_DIA, DOMAIN_ABAP,
)

# Public (external) MS port base — 3600 + instance number.  Distinct
# from the *internal* MS port (3900+NN) used by betrusted: the server
# list is served on the public port that clients use for logon LB.
DEFAULT_MS_EXT_BASE = 3600

# MS-level opcode (4-byte opcode section, not an ADM record opcode).
MS_SERVER_LST = 0x05

# opcode_version we advertise in the request.  0x68 is what the pysap
# ms_monitor client sends; the MS answers with its own supported record
# version in the reply's opcode_version byte, which is what we parse by.
_REQ_OPCODE_VERSION = 0x68
# pysap SAPMSPayload default; harmless for this request, echoed back.
_REQ_OPCODE_CHARSET = 0x03

# Default client name we announce.  Any name works; keep it recognisable
# in the target's MS trace without masquerading as a real dispatcher.
DEFAULT_CLIENT_NAME = "sapmap-msq"

# Fixed record size per SAPMSClientN version, derived field-by-field from
# pysap's definitions (see _parse_record for the per-version layout).
_RECORD_SIZE = {1: 67, 2: 115, 3: 150, 4: 160}

# SAPMS header (110) + 4-byte opcode section precede the record list.
_HEADER_LEN = 110
_OPCODE_LEN = 4

# ms_client_status_values (pysap) — server lifecycle state.
_STATUS = {
    0: "UNKNOWN", 1: "ACTIVE", 2: "INACTIVE", 3: "SHUTDOWN",
    4: "STOP", 5: "STARTING", 6: "INIT", 7: "RECONNECT",
}

# ms_msgtype_values (pysap) — work-process type bitmask, bit 0..7.
_WP_TYPES = ["DIA", "UPD", "ENQ", "BTC", "SPO", "UP2", "ATP", "ICM"]

# ms_errorno_values (pysap) — the subset we are likely to surface on a
# failed login / request.  Unknown codes fall back to the raw number.
_ERRORNO = {
    0: "OK/RECONNECTION", 62: "NOTATTACHED", 63: "INUSE",
    67: "CLIENTVERSREQUIRED", 70: "INCOMPATIBLEKERNEL", 72: "NOTINIT",
    76: "MOREDATA", 83: "TYPESNOTALLOWED", 84: "ACCESSDENIED",
    92: "WRONGVERSION",
}


def ms_ext_port(instance_nr: int) -> int:
    """Public Message Server port for instance NN: 3600 + NN."""
    return DEFAULT_MS_EXT_BASE + int(instance_nr)


def _decode(raw: bytes) -> str:
    """Strip SAP's space/null padding and decode a fixed-length field."""
    return raw.rstrip(b" \x00").decode("utf-8", errors="replace")


def _decode_wp_types(msgtype: int) -> list:
    """Expand the work-process-type bitmask to a list of WP names."""
    return [_WP_TYPES[i] for i in range(8) if msgtype & (1 << i)]


def _decode_addr(v6: bytes, v4: bytes) -> str:
    """Prefer the IPv4 address; fall back to IPv6 (unmapping ::ffff:)."""
    if v4 and v4 != b"\x00\x00\x00\x00":
        return socket.inet_ntoa(v4)
    if v6 and v6 != b"\x00" * 16:
        # ::ffff:a.b.c.d → a.b.c.d
        if v6[:12] == b"\x00" * 10 + b"\xff\xff":
            return socket.inet_ntoa(v6[12:16])
        try:
            return socket.inet_ntop(socket.AF_INET6, v6)
        except (OSError, ValueError):
            return ""
    return ""


def _parse_record(rec: bytes, version: int) -> dict:
    """Parse one SAPMSClient{version} record into a dict.

    Field layouts are taken verbatim from pysap SAPMSClient1..4; only
    the string widths and the presence of the v6 address / status /
    nitrace / sys_service tail differ between versions.
    """
    if version == 1:
        # client20 host20 service20 msgtype1 v4(4) servno2
        client, host, service = rec[0:20], rec[20:40], rec[40:60]
        msgtype = rec[60]
        v6 = b""
        v4 = rec[61:65]
        servno = struct.unpack("!H", rec[65:67])[0]
        status = None
    elif version == 2:
        # client40 host32 service20 msgtype1 v4(4) servno2 status1 nitrace1 padd14
        client, host, service = rec[0:40], rec[40:72], rec[72:92]
        msgtype = rec[92]
        v6 = b""
        v4 = rec[93:97]
        servno = struct.unpack("!H", rec[97:99])[0]
        status = rec[99]
    elif version == 3:
        # client40 host64 service20 msgtype1 v6(16) v4(4) servno2 status1 nitrace1 padd1
        client, host, service = rec[0:40], rec[40:104], rec[104:124]
        msgtype = rec[124]
        v6 = rec[125:141]
        v4 = rec[141:145]
        servno = struct.unpack("!H", rec[145:147])[0]
        status = rec[147]
    else:  # version 4 (modern 7.x/9.x kernels)
        # client40 host64 service20 msgtype1 v6(16) v4(4) servno2 status1
        # nitrace1 sys_service4 padd7
        client, host, service = rec[0:40], rec[40:104], rec[104:124]
        msgtype = rec[124]
        v6 = rec[125:141]
        v4 = rec[141:145]
        servno = struct.unpack("!H", rec[145:147])[0]
        status = rec[147]

    return {
        "name":       _decode(client),       # logical server, e.g. host_SID_NN
        "host":       _decode(host),
        "service":    _decode(service),      # dispatcher service / port string
        "ip":         _decode_addr(v6, v4),
        "servno":     servno,
        "wp_types":   _decode_wp_types(msgtype),
        "status":     _STATUS.get(status, str(status)) if status is not None else "",
    }


def _open_socket(host: str, port: int, timeout: float,
                 saprouter: str = "") -> socket.socket:
    """Open a TCP socket to the MS port, optionally via SAProuter.

    Uses NI_RAW_IO (talk_mode=1) for the router hop so the tunnel is a
    transparent byte pipe — our own ni_send/ni_recv do the NI framing
    end-to-end, exactly as the HTTP info-leak module does.
    """
    if saprouter:
        from sap_saprouter import connect_through_saprouter
        return connect_through_saprouter(
            saprouter + f"/H/{host}/S/{port}",
            timeout=timeout, talk_mode=1,
        )
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((host, port))
    return s


def _send_server_list_req(sock, toname: str, client_name: str,
                          timeout: float) -> bytes:
    """Send one MS_SERVER_LST request and return the raw reply frame."""
    req = ms_build_header(
        toname=toname, fromname=client_name,
        msgtype=MSG_DIA, flag=FLAG_REQUEST, iflag=IFLAG_SEND_NAME,
        domain=DOMAIN_ABAP,
    )
    # opcode section order (pysap SAPMSPayload / betrusted ms_parse_opcode):
    # opcode, opcode_error, opcode_version, opcode_charset.
    req += struct.pack("BBBB", MS_SERVER_LST, 0x00,
                       _REQ_OPCODE_VERSION, _REQ_OPCODE_CHARSET)
    ni_send(sock, req)
    return ni_recv(sock, timeout)


def _parse_server_list(resp: bytes) -> dict:
    """Parse an MS_SERVER_LST reply frame into {ok, servers[], version, error}."""
    rhdr = ms_parse_header(resp)
    if not rhdr:
        return {"ok": False, "error": "reply is not a SAPMS packet"}
    if rhdr["errorno"] != 0:
        return {"ok": False,
                "error": f"server-list error: {_errname(rhdr['errorno'])}"}
    opc = ms_parse_opcode(resp)
    if not opc:
        return {"ok": False, "error": "reply truncated (no opcode section)"}
    if opc.get("error"):
        return {"ok": False, "error": f"opcode error: {opc['error']}"}

    version = opc.get("version", 4)
    rec_size = _RECORD_SIZE.get(version)
    if rec_size is None:
        return {"ok": False, "error": f"unknown record version {version}"}

    body = resp[_HEADER_LEN + _OPCODE_LEN:]
    servers = []
    for off in range(0, len(body) - rec_size + 1, rec_size):
        parsed = _parse_record(body[off:off + rec_size], version)
        if not (parsed["name"] or parsed["host"]):
            continue
        # Skip the Message Server's own loopback self-entry — it registers
        # itself on 127.0.0.1 and isn't an application server to map.
        if parsed["ip"].startswith("127."):
            continue
        servers.append(parsed)
    return {"ok": True, "servers": servers, "version": version, "error": ""}


def _strategy_anon(sock, client_name: str, timeout: float,
                   dbg: list) -> dict:
    """External-port client query: ask for the server list WITHOUT the
    dispatcher-registration LOGIN_2.  The public port (36NN) is meant for
    read-only client queries, so a modern, hardened MS that rejects
    LOGIN_2 on 36NN will still answer this."""
    resp = _send_server_list_req(sock, "MSG_SERVER", client_name, timeout)
    dbg.append(("anon server-list reply", resp))
    return _parse_server_list(resp)


def _strategy_login(sock, client_name: str, timeout: float,
                    dbg: list) -> dict:
    """Registration-style path: LOGIN_2 then MS_SERVER_LST.  Works on the
    internal port (39NN) and on older/permissive external ports."""
    login = ms_build_header(
        toname=client_name, fromname=client_name,
        msgtype=MSG_DIA, flag=FLAG_UNKNOWN, iflag=IFLAG_LOGIN_2,
        domain=DOMAIN_ABAP, diag_port=0,
    )
    ni_send(sock, login)
    reply = ni_recv(sock, timeout)
    dbg.append(("login_2 reply", reply))
    hdr = ms_parse_header(reply)
    if not hdr:
        return {"ok": False, "error": "login reply is not a SAPMS packet "
                                      "(port may not be a Message Server)"}
    if hdr["errorno"] != 0:
        return {"ok": False,
                "error": f"LOGIN_2 rejected: {_errname(hdr['errorno'])} "
                         f"— the external port (36NN) commonly refuses the "
                         f"dispatcher-registration login once "
                         f"rdisp/msserv_internal is set; try the internal "
                         f"port (39NN) instead"}
    server_string = hdr["fromname"] or "MSG_SERVER"
    resp = _send_server_list_req(sock, server_string, client_name, timeout)
    dbg.append(("login server-list reply", resp))
    out = _parse_server_list(resp)
    out["server_string"] = server_string
    return out


def query_app_servers(host: str, inst_nr: Optional[int] = None,
                      port: Optional[int] = None,
                      client_name: str = DEFAULT_CLIENT_NAME,
                      timeout: float = 8.0,
                      saprouter: str = "",
                      debug: bool = False) -> dict:
    """Query a Message Server for its application-server list.

    Two strategies are tried in order, each on a fresh connection:

      1. *anon*  — a read-only client query (no login).  This is what the
                   public port (36NN) is designed to answer and is the
                   path that works against hardened, modern systems.
      2. *login* — LOGIN_2 (dispatcher registration) then the list query.
                   Needed on the internal port (39NN) and older kernels;
                   rejected on 36NN when rdisp/msserv_internal is set.

    Args:
        host        : target hostname / IP of the Message Server.
        inst_nr     : SAP instance number (0-99); the public MS port is
                      derived as 3600+inst_nr when ``port`` is omitted.
        port        : explicit MS port — takes precedence over inst_nr.
        client_name : name we announce (appears in the MS trace).
        timeout     : per-operation socket timeout in seconds.
        saprouter   : optional SAProuter route prefix to tunnel through.
        debug       : when True, include raw reply hexdumps under "debug".

    Returns a dict:
        {
            "success"       : bool,
            "port"          : int,
            "strategy"      : str,   # "anon" | "login" | ""
            "server_string" : str,
            "record_version": int,
            "count"         : int,
            "servers"       : [ {name, host, service, ip, servno,
                                 wp_types[], status}, ... ],
            "error"         : str,   # non-empty iff success == False
            "debug"         : [ "<label>:\\n<hexdump>", ... ],  # if debug
        }
    """
    if port is None:
        if inst_nr is None:
            return _fail(0, "neither port nor inst_nr supplied")
        port = ms_ext_port(inst_nr)

    dbg: list = []
    errors = []
    for strat_name, strat in (("anon", _strategy_anon),
                              ("login", _strategy_login)):
        try:
            sock = _open_socket(host, port, timeout, saprouter=saprouter)
        except (socket.timeout, ConnectionError, OSError, ValueError) as e:
            return _fail(port, f"connect: {type(e).__name__}: {e}",
                         dbg if debug else None)
        try:
            res = strat(sock, client_name, timeout, dbg)
        except (socket.timeout, ConnectionError, OSError, ValueError) as e:
            res = {"ok": False, "error": f"io: {type(e).__name__}: {e}"}
        finally:
            _safe_close(sock)

        if res.get("ok"):
            return {
                "success":        True,
                "port":           port,
                "strategy":       strat_name,
                "server_string":  res.get("server_string", "MSG_SERVER"),
                "record_version": res.get("version", 0),
                "count":          len(res["servers"]),
                "servers":        res["servers"],
                "error":          "",
                **({"debug": _fmt_debug(dbg)} if debug else {}),
            }
        errors.append(f"{strat_name}: {res.get('error', 'unknown')}")

    return _fail(port, " | ".join(errors), dbg if debug else None)


def _fmt_debug(dbg: list) -> list:
    return [f"{label} ({len(data)}B):\n{_hexdump(data)}" for label, data in dbg]


def _hexdump(data: bytes, width: int = 16, maxlen: int = 512) -> str:
    out = []
    for i in range(0, min(len(data), maxlen), width):
        chunk = data[i:i + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        asciipart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"  {i:04x}  {hexpart:<{width * 3}}  {asciipart}")
    if len(data) > maxlen:
        out.append(f"  … ({len(data) - maxlen} more bytes)")
    return "\n".join(out)


def _errname(code: int) -> str:
    name = _ERRORNO.get(code)
    if name:
        return f"{name}({code})"
    signed = code - 256 if code > 127 else code
    return f"MSE_UNKNOWN(code={code}, signed={signed})"


def _fail(port: int, error: str, dbg: Optional[list] = None) -> dict:
    res = {
        "success": False, "port": port, "strategy": "", "server_string": "",
        "record_version": 0, "count": 0, "servers": [], "error": error,
    }
    if dbg is not None:
        res["debug"] = _fmt_debug(dbg)
    return res


def _safe_close(sock) -> None:
    try:
        sock.close()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Minimal standalone CLI — handy for authorised spot-checks without the GUI.
# ---------------------------------------------------------------------------
if __name__ == "__main__":  # pragma: no cover
    import argparse

    ap = argparse.ArgumentParser(
        description="Enumerate SAP application servers via the public "
                    "Message Server protocol (port 36NN).")
    ap.add_argument("host", help="Message Server host / IP")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("-n", "--nr", type=int, help="instance number (0-99)")
    g.add_argument("-p", "--port", type=int, help="explicit MS port")
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--saprouter", default="",
                    help="SAProuter route prefix, e.g. /H/router/S/3299")
    ap.add_argument("--debug", action="store_true",
                    help="hexdump raw MS replies (diagnose rejected logins)")
    args = ap.parse_args()

    res = query_app_servers(args.host, inst_nr=args.nr, port=args.port,
                            timeout=args.timeout, saprouter=args.saprouter,
                            debug=args.debug)
    if args.debug:
        for blk in res.get("debug", []):
            print(f"[debug] {blk}")
    if not res["success"]:
        print(f"[-] {args.host}:{res['port']}  {res['error']}")
        raise SystemExit(1)

    print(f"[+] {args.host}:{res['port']}  MS={res['server_string']}  "
          f"(via {res['strategy']}, record v{res['record_version']})  "
          f"{res['count']} application server(s):")
    for s in res["servers"]:
        wp = ",".join(s["wp_types"]) or "-"
        print(f"    {s['name']:<32} {s['host']:<24} {s['ip']:<15} "
              f"svc={s['service']:<10} wp={wp:<20} [{s['status']}]")
