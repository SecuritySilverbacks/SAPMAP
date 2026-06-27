"""Test SAPControl GetInstanceProperties on 192.168.2.29:54013 via SAProuter."""
import socket, sys, time, re as _re
sys.path.insert(0, "/home/joris/Desktop/CLAUDE/SAPMAP")
from sap_saprouter import connect_through_saprouter

ROUTER = "/H/80.56.140.21/S/3299"
TARGETS = [("192.168.2.29", 54013), ("192.168.2.29", 54113)]

def try_sapcontrol(host, port):
    print(f"\n===== SAPControl {host}:{port} via SAProuter =====")
    route = ROUTER + f"/H/{host}/S/{port}"
    print(f"Route: {route}")
    t0 = time.time()
    try:
        sock = connect_through_saprouter(route, timeout=10, talk_mode=1)
    except Exception as e:
        print(f"  tunnel setup failed: {e}")
        return
    print(f"  tunnel up in {time.time()-t0:.1f}s")

    body = (
        '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
        '<SOAP-ENV:Body><ns1:GetInstanceProperties xmlns:ns1="urn:SAPControl">'
        '</ns1:GetInstanceProperties></SOAP-ENV:Body></SOAP-ENV:Envelope>'
    )
    req = (
        f"POST / HTTP/1.0\r\n"
        f"Host: {host}:{port}\r\n"
        f"Content-Type: text/xml; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"SOAPAction: \"\"\r\n\r\n{body}"
    ).encode("utf-8")

    print(f"  sending {len(req)} bytes SOAP request ...")
    sock.sendall(req)

    sock.settimeout(10)
    resp = b""
    try:
        while True:
            chunk = sock.recv(16384)
            if not chunk:
                break
            resp += chunk
            if len(resp) > 500_000:
                break
    except socket.timeout:
        print("  (recv timeout)")
    sock.close()
    print(f"  received {len(resp)} bytes in {time.time()-t0:.1f}s total")
    print("--- first 1024 bytes ---")
    head = resp[:1024]
    try:
        print(head.decode("utf-8", "replace"))
    except Exception:
        print(head)
    # Look for SAPSYSTEMNAME in the response
    m = _re.search(rb"<property>\s*<property>SAPSYSTEMNAME</property>\s*"
                    rb"<propertytype>\w+</propertytype>\s*<value>(\w+)</value>",
                    resp, _re.IGNORECASE)
    if m:
        print(f"  SID (via <property>): {m.group(1).decode()}")
    # Simpler fallback
    m = _re.search(rb"<value>(\w{3})</value>", resp)
    if m:
        print(f"  first 3-char <value>: {m.group(1).decode()}")
    m = _re.search(rb"SAPSYSTEMNAME[^<>]*<[^>]+>(\w+)", resp)
    if m:
        print(f"  SID (SAPSYSTEMNAME neighbour): {m.group(1).decode()}")

for h, p in TARGETS:
    try:
        try_sapcontrol(h, p)
    except Exception as e:
        print(f"fail: {e}")
