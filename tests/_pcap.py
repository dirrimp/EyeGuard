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
