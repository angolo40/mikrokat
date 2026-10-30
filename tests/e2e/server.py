#!/usr/bin/env python3
"""The HTTPS server behind tests/e2e/run.sh, on port 443.

Usage: server.py <address> <certificate> <key>

/bytes/<n> returns n bytes with TAIL_MARKER near the end of the first MiB, so a rule can show
that the whole copy reached Suricata. Anything else returns BODY, and POST also reads the body.
"""
import http.server
import random
import ssl
import sys

BODY = b"mikrokat-e2e-ok\n"
TAIL_MARKER = b"mikrokat-e2e-tail"
TAIL_AT = 2**20 - 4096
BLOCK = random.Random(1).randbytes(2**16)


def first_mib():
    data = bytearray(BLOCK * (2**20 // len(BLOCK)))
    data[TAIL_AT:TAIL_AT + len(TAIL_MARKER)] = TAIL_MARKER
    return bytes(data)


FIRST = first_mib()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def answer(self, length):
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(length))
        self.end_headers()

    def do_GET(self):
        if self.path.startswith("/bytes/"):
            left = int(self.path.split("/")[2])
            self.answer(left)
            self.wfile.write(FIRST[:left])
            left -= min(left, len(FIRST))
            while left:
                self.wfile.write(BLOCK[:left])
                left -= min(left, len(BLOCK))
            return
        self.answer(len(BODY))
        self.wfile.write(BODY)

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.answer(len(BODY))
        self.wfile.write(BODY)


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        """A client that rejects the certificate is part of the test."""


def main():
    address, certificate, key = sys.argv[1:4]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)
    server = Server((address, 443), Handler)
    # The handshake runs in the thread of the connection, so a silent client holds up nothing.
    server.socket = context.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
    server.serve_forever()


if __name__ == "__main__":
    main()
