"""
Diagnostic: capture raw bytes from DIAG TERM_INI and V2/Chipik F_SAP_INIT
responses through the SAProuter, so we can see exactly where the SID
hides for W74 (kernel 742).  Prints hex + ASCII dumps + parsed items.

Target:  192.168.2.29:3240 (DIAG) and 192.168.2.29:3340 (GW)
Router:  80.56.140.21:3299
"""
import socket, struct, sys, re, time
sys.path.insert(0, "/home/joris/Desktop/CLAUDE/SAPMAP")

from sap_rfc_system_info import (
    connect_via_saprouter, build_diag_term_ini,
    build_gw_normal_client_v2, build_f_sap_init_v2, build_chipik_p2,
    parse_diag_response, parse_gateway_error, ni_recv,
)

ROUTER = ("80.56.140.21", 3299)
TARGET = "192.168.2.29"
GW_PORT = 3340
DIAG_PORT = 3240

def dump(label, data, limit=2048):
    print(f"--- {label} ({len(data)} bytes) ---")
    if not data:
        print("(empty)")
        return
    data = data[:limit]
    for i in range(0, len(data), 32):
        chunk = data[i:i+32]
        hx  = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in chunk)
        print(f"  {i:04x}  {hx:<95}  |{asc}|")

def grep_strings(label, data, minlen=4):
    # Print every printable run of length >= minlen, both ASCII and UTF-16LE.
    print(f"--- {label} strings ---")
    # ASCII
    current = b""
    runs = []
    for b in data:
        if 0x20 <= b < 0x7f:
            current += bytes([b])
        else:
            if len(current) >= minlen:
                runs.append(current.decode("ascii", "replace"))
            current = b""
    if len(current) >= minlen:
        runs.append(current.decode("ascii", "replace"))
    for r in runs:
        print(f"  ASC: {r}")
    # UTF-16LE
    if len(data) >= minlen * 2:
        try:
            u = data.decode("utf-16-le", "replace")
            for m in re.findall(r"[\x20-\x7e]{%d,}" % minlen, u):
                print(f"  U16: {m}")
        except Exception:
            pass

def test_diag():
    print("\n===== DIAG TERM_INI on 3240 via SAProuter =====")
    sock = connect_via_saprouter(ROUTER[0], ROUTER[1], TARGET, DIAG_PORT,
                                  timeout=10, verbose=True)
    pkt = build_diag_term_ini()
    print(f"Sending TERM_INI ({len(pkt)} bytes)")
    sock.sendall(pkt)
    resp = b""
    start = time.time()
    sock.settimeout(6)
    try:
        while time.time() - start < 10:
            chunk = sock.recv(16384)
            if not chunk:
                break
            resp += chunk
            if len(resp) >= 4:
                nl = struct.unpack(">I", resp[:4])[0]
                if nl > 0 and len(resp) >= 4 + nl:
                    break
    except socket.timeout:
        pass
    sock.close()
    print(f"Received: {len(resp)} bytes")
    dump("DIAG head (first 512B)", resp[:512])
    dump("DIAG tail (last 512B)", resp[-512:] if len(resp) > 512 else b"")
    grep_strings("DIAG full", resp)
    info = parse_diag_response(resp)
    print(f"parse_diag_response: {info}")

def test_v2():
    print("\n===== V2 F_SAP_INIT on 3340 via SAProuter =====")
    sock = connect_via_saprouter(ROUTER[0], ROUTER[1], TARGET, GW_PORT,
                                  timeout=10, verbose=True)
    pkt1 = build_gw_normal_client_v2("172.20.10.2", 40)
    print(f"P1 ({len(pkt1)} bytes)")
    sock.sendall(pkt1)
    r1 = sock.recv(8192)
    print(f"P1 resp: {len(r1)} bytes")

    pkt2 = build_f_sap_init_v2("172.20.10.2", TARGET, 40)
    print(f"P2 ({len(pkt2)} bytes)")
    sock.sendall(pkt2)
    r2 = ni_recv(sock, timeout=5)
    print(f"P2 resp: {len(r2)} bytes")
    sock.close()
    dump("V2 P2 head", r2[:512])
    grep_strings("V2 P2", r2)
    err = parse_gateway_error(r2)
    print(f"parse_gateway_error: {err}")

def test_chipik():
    print("\n===== Chipik F_SAP_INIT on 3340 via SAProuter =====")
    sock = connect_via_saprouter(ROUTER[0], ROUTER[1], TARGET, GW_PORT,
                                  timeout=10, verbose=True)
    pkt1 = build_gw_normal_client_v2("172.20.10.2", 40)
    sock.sendall(pkt1)
    _ = sock.recv(8192)
    pkt2 = build_chipik_p2("172.20.10.2", TARGET, 40)
    sock.sendall(pkt2)
    r2 = ni_recv(sock, timeout=5)
    sock.close()
    print(f"Chipik P2 resp: {len(r2)} bytes")
    dump("Chipik P2", r2[:1024])
    grep_strings("Chipik P2", r2)
    err = parse_gateway_error(r2)
    print(f"parse_gateway_error: {err}")

if __name__ == "__main__":
    for fn in (test_v2, test_chipik, test_diag):
        try:
            fn()
        except Exception as e:
            print(f"{fn.__name__} failed: {e}")
