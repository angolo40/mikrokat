#!/usr/bin/env python3
"""Send a fake HTTP session over TZSP that matches the classic 'id check returned root' rule.

Usage: send-test-alert.py [host] [port]. Use it to check the path from TZSP to the notification.
"""
import socket
import struct
import sys
import time

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 37008
CLIENT, SERVER = "192.168.50.10", "198.51.100.7"
CMAC, SMAC = bytes.fromhex("02000000000a"), bytes.fromhex("020000000014")


def checksum(data):
    data += b"\0" * (len(data) % 2)
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def frame(src, dst, smac, dmac, sport, dport, seq, ack, flags, payload=b""):
    s, d = socket.inet_aton(src), socket.inet_aton(dst)
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)
    pseudo = s + d + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp + payload)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp) + len(payload), 1, 0x4000, 64, 6, 0, s, d)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return dmac + smac + b"\x08\x00" + ip + tcp + payload


def main():
    request = b"GET /uid HTTP/1.1\r\nHost: test.example\r\nUser-Agent: curl/8\r\nAccept: */*\r\n\r\n"
    body = b"uid=0(root) gid=0(root) groups=0(root)\n"
    response = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
                + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
    sport = int(time.time()) % 20000 + 30000
    c, s = 1000, 5000
    packets = [
        frame(CLIENT, SERVER, CMAC, SMAC, sport, 80, c, 0, 0x02),
        frame(SERVER, CLIENT, SMAC, CMAC, 80, sport, s, c + 1, 0x12),
        frame(CLIENT, SERVER, CMAC, SMAC, sport, 80, c + 1, s + 1, 0x10),
        frame(CLIENT, SERVER, CMAC, SMAC, sport, 80, c + 1, s + 1, 0x18, request),
        frame(SERVER, CLIENT, SMAC, CMAC, 80, sport, s + 1, c + 1 + len(request), 0x18, response),
        frame(CLIENT, SERVER, CMAC, SMAC, sport, 80, c + 1 + len(request), s + 1 + len(response), 0x10),
        frame(SERVER, CLIENT, SMAC, CMAC, 80, sport, s + 1 + len(response), c + 1 + len(request), 0x11),
        frame(CLIENT, SERVER, CMAC, SMAC, sport, 80, c + 1 + len(request), s + 2 + len(response), 0x11),
        frame(SERVER, CLIENT, SMAC, CMAC, 80, sport, s + 2 + len(response), c + 2 + len(request), 0x10),
    ]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for packet in packets:
        sock.sendto(b"\x01\x00\x00\x01\x01" + packet, (HOST, PORT))
        time.sleep(0.02)
    print(f"sent {len(packets)} frames to {HOST}:{PORT}")


if __name__ == "__main__":
    main()
