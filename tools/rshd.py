"""A small rshd (RFC-less BSD rsh protocol) for testing a guest's rsh: it
runs nothing, it answers with what it was asked. Listens on the PC's
loopback only (slirp hands the guests' connections to 10.0.3.2 there).

    python -I tools/rshd.py [port]     (default 514)

Protocol: the client sends "<stderr port>\\0<local user>\\0<remote user>\\0
<command>\\0"; the server answers "\\0" and then the command's output. A
non-zero stderr port asks for a second connection back to the client,
which a PC behind slirp cannot make: such requests get the output and a
note on the main connection instead. Every request is logged to stdout.
"""
import socket
import sys
import threading

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 514


def field(conn):
    b = b""
    while True:
        c = conn.recv(1)
        if not c or c == b"\0":
            return b.decode("latin-1")
        b += c


def handle(conn, peer):
    try:
        errport = field(conn)
        local, remote, command = field(conn), field(conn), field(conn)
        print(peer, "stderr port", repr(errport), "local", repr(local), "remote", repr(remote), "command", repr(command), flush=True)
        conn.sendall(b"\0")
        out = "rshd test: user %s (local %s) ran \"%s\"\n" % (remote, local, command)
        if errport not in ("", "0"):
            out += "rshd test: no stderr connection back (port %s)\n" % errport
        conn.sendall(out.encode("latin-1"))
    finally:
        conn.close()


def main():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", PORT))
    s.listen(4)
    print("rshd test server on 127.0.0.1 port", PORT, flush=True)
    while True:
        c, a = s.accept()
        threading.Thread(target=handle, args=(c, a), daemon=True).start()


if __name__ == "__main__":
    main()
