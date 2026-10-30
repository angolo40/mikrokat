#!/usr/bin/env python3
"""Receive TZSP frames from a MikroTik sniffer and inject them into a TAP device for Suricata."""
import fcntl
import os
import socket
import struct
import time

TUNSETIFF = 0x400454CA
TUNSETPERSIST = 0x400454CB
SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914
SIOCSIFMTU = 0x8922
IFF_UP = 0x1
IFF_PROMISC = 0x100
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000
TAG_PADDING = 0
TAG_END = 1
PROTO_ETHERNET = 1

IFACE = os.environ.get("TZSP_INTERFACE", "tzsp0")
PORT = int(os.environ.get("TZSP_PORT", "37008"))
SOURCE = os.environ.get("TZSP_SOURCE", "")


def open_tap(name):
    fd = os.open("/dev/net/tun", os.O_RDWR)
    fcntl.ioctl(fd, TUNSETIFF, struct.pack("16sH", name.encode(), IFF_TAP | IFF_NO_PI))
    # Keep the interface when this process restarts: Suricata spins on the CPU if it disappears.
    fcntl.ioctl(fd, TUNSETPERSIST, 1)
    ctl = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    fcntl.ioctl(ctl, SIOCSIFMTU, struct.pack("16si", name.encode(), 9000))
    flags = struct.unpack("16sh", fcntl.ioctl(ctl, SIOCGIFFLAGS, struct.pack("16sh", name.encode(), 0)))[1]
    fcntl.ioctl(ctl, SIOCSIFFLAGS, struct.pack("16sh", name.encode(), flags | IFF_UP | IFF_PROMISC))
    ctl.close()
    return fd


def decapsulate(packet):
    """Return the Ethernet frame inside a TZSP packet, or None if it is not one."""
    if len(packet) < 5 or packet[0] != 1:
        return None
    if struct.unpack("!H", packet[2:4])[0] != PROTO_ETHERNET:
        return None
    pos = 4
    while pos < len(packet):
        tag = packet[pos]
        pos += 1
        if tag == TAG_END:
            return packet[pos:] or None
        if tag == TAG_PADDING:
            continue
        if pos >= len(packet):
            return None
        pos += 1 + packet[pos]
    return None


def main():
    tap = open_tap(IFACE)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 * 1024 * 1024)
    sock.bind(("0.0.0.0", PORT))
    print(f"[tzsp] listening on udp/{PORT}, writing to {IFACE}, source filter: {SOURCE or 'none'}", flush=True)
    frames = rejected = errors = 0
    last = time.monotonic()
    while True:
        packet, addr = sock.recvfrom(65535)
        if SOURCE and addr[0] != SOURCE:
            rejected += 1
            continue
        frame = decapsulate(packet)
        if frame is None:
            errors += 1
            continue
        try:
            os.write(tap, frame)
            frames += 1
        except OSError:
            errors += 1
        now = time.monotonic()
        if now - last >= 60:
            print(f"[tzsp] frames={frames} rejected={rejected} errors={errors}", flush=True)
            last = now


if __name__ == "__main__":
    main()
