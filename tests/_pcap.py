"""Tiny pcap writer for tests: Ethernet/IPv4 with UDP or TCP (no dependencies)."""
import struct, socket

def ip_hdr(src, dst, proto, payload_len):
    tot = 20 + payload_len
    h = struct.pack(">BBHHHBBH4s4s", 0x45, 0, tot, 1, 0, 64, proto, 0, socket.inet_aton(src), socket.inet_aton(dst))
    return h

def udp(src, dst, sport, dport, payload):
    u = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    return ip_hdr(src, dst, 17, len(u)) + u

def tcp(src, dst, sport, dport, flags, payload=b""):
    t = struct.pack(">HHIIBBHHH", sport, dport, 1, 0, 5 << 4, flags, 1000, 0, 0) + payload
    return ip_hdr(src, dst, 6, len(t)) + t

def dns_query(name, qtype=1, edns=False, rd=True, txid=0x1234):
    flags = 0x0100 if rd else 0
    h = struct.pack(">HHHHHH", txid, flags, 1, 0, 0, 1 if edns else 0)
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0" + struct.pack(">HH", qtype, 1)
    opt = b"\0" + struct.pack(">HHIH", 41, 1232, 0, 0) if edns else b""
    return h + q + opt

def write_pcap(path, packets):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, ip in enumerate(packets):
            eth = b"\x02" * 6 + b"\x04" * 6 + b"\x08\x00"
            fr = eth + ip
            f.write(struct.pack("<IIII", 1700000000 + i, 0, len(fr), len(fr)) + fr)


def client_hello(sni="example.com", ech=False, no_sni=False, pad_before=0, version=0x0303):
    """A TLS ClientHello record. `pad_before` = bytes of filler extension placed BEFORE the SNI
    (Chrome randomises extension order, so the name can sit late in a large hello)."""
    exts = b""
    if pad_before:
        exts += struct.pack(">HH", 0x0015, pad_before) + b"\x00" * pad_before       # padding ext
    if not no_sni:
        name = sni.encode()
        lst = b"\x00" + struct.pack(">H", len(name)) + name
        exts += struct.pack(">HH", 0x0000, len(lst) + 2) + struct.pack(">H", len(lst)) + lst
    if ech:
        exts += struct.pack(">HH", 0xFE0D, 4) + b"\x00\x00\x00\x00"
    exts += struct.pack(">HH", 0x002B, 3) + b"\x02\x03\x04"                          # supported_versions
    body = struct.pack(">H", version) + b"\x11" * 32 + b"\x20" + b"\x22" * 32 \
        + struct.pack(">H", 4) + b"\x13\x01\x13\x02" + b"\x01\x00" + struct.pack(">H", len(exts)) + exts
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def tcpdump_x_lines(ip_bytes, header="12:00:03.1 IP 1.2.3.4.5 > 5.6.7.8.443: Flags [P.], seq 1, length 0"):
    """What `tcpdump -x` prints for one packet: a header line, then indented hex lines."""
    lines = [header]
    for off in range(0, len(ip_bytes), 16):
        chunk = ip_bytes[off:off + 16]
        groups = [chunk[i:i + 2].hex() for i in range(0, len(chunk), 2)]
        lines.append("\t0x%04x:  %s" % (off, " ".join(groups)))
    return lines
