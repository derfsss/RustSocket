"""A small FTP server for testing a guest's ftp client (passive mode only:
the guest reaches the PC through QEMU's slirp at 10.0.3.2, and the PC
cannot reach the guest for active-mode data connections). It listens on
127.0.0.1 only: slirp hands the guests' connections to 10.0.3.2 to the
PC's loopback, so nothing is exposed to the network.

    python -I tools/ftpserver.py ROOT [port]     (default port 2121)

Any user name and password are accepted. Commands: USER PASS SYST PWD CWD
TYPE MODE STRU PASV LIST NLST RETR STOR SIZE NOOP QUIT; others get 502.
Every command is logged to stdout.
"""
import os
import socket
import sys
import threading

ROOT = os.path.abspath(sys.argv[1])
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 2121
GUEST_SIDE_HOST = (10, 0, 3, 2)


def handle(conn, peer):
    f = conn.makefile("rwb", buffering=0)
    data_listener = None

    def say(line):
        f.write((line + "\r\n").encode("latin-1"))
        print(peer, "<", line, flush=True)

    def data_conn():
        nonlocal data_listener
        if data_listener is None:
            return None
        d, _ = data_listener.accept()
        data_listener.close()
        data_listener = None
        return d

    say("220 test ftp server ready")
    cwd = ROOT
    while True:
        raw = f.readline()
        if not raw:
            break
        line = raw.decode("latin-1").rstrip("\r\n")
        print(peer, ">", line, flush=True)
        cmd, _, arg = line.partition(" ")
        cmd = cmd.upper()
        if cmd == "USER":
            say("331 password please")
        elif cmd == "PASS":
            say("230 logged in")
        elif cmd == "SYST":
            say("215 UNIX Type: L8")
        elif cmd == "PWD":
            say('257 "/%s" is the directory' % os.path.relpath(cwd, ROOT).replace("\\", "/").lstrip("."))
        elif cmd == "CWD":
            nd = os.path.abspath(os.path.join(cwd, arg))
            if nd.startswith(ROOT) and os.path.isdir(nd):
                cwd = nd
                say("250 ok")
            else:
                say("550 no such directory")
        elif cmd in ("TYPE", "MODE", "STRU", "NOOP"):
            say("200 ok")
        elif cmd == "PASV":
            data_listener = socket.socket()
            data_listener.bind(("127.0.0.1", 0))
            data_listener.listen(1)
            p = data_listener.getsockname()[1]
            say("227 Entering Passive Mode (%d,%d,%d,%d,%d,%d)" % (GUEST_SIDE_HOST + (p >> 8, p & 255)))
        elif cmd in ("LIST", "NLST"):
            if data_listener is None:
                say("425 use PASV first")
                continue
            say("150 listing")
            d = data_conn()
            names = sorted(os.listdir(cwd))
            if cmd == "LIST":
                out = "".join("-rw-r--r-- 1 ftp ftp %10d Nov 07 00:00 %s\r\n" % (os.path.getsize(os.path.join(cwd, n)), n) for n in names)
            else:
                out = "".join(n + "\r\n" for n in names)
            d.sendall(out.encode("latin-1"))
            d.close()
            say("226 done")
        elif cmd == "SIZE":
            p = os.path.join(cwd, arg)
            say("213 %d" % os.path.getsize(p) if os.path.isfile(p) else "550 no such file")
        elif cmd == "RETR":
            p = os.path.join(cwd, arg)
            if data_listener is None or not os.path.isfile(p):
                say("550 no such file" if data_listener else "425 use PASV first")
                continue
            say("150 sending %s" % arg)
            d = data_conn()
            with open(p, "rb") as src:
                d.sendall(src.read())
            d.close()
            say("226 done")
        elif cmd == "STOR":
            if data_listener is None:
                say("425 use PASV first")
                continue
            say("150 receiving %s" % arg)
            d = data_conn()
            with open(os.path.join(cwd, os.path.basename(arg)), "wb") as dst:
                while True:
                    b = d.recv(65536)
                    if not b:
                        break
                    dst.write(b)
            d.close()
            say("226 done")
        elif cmd == "QUIT":
            say("221 bye")
            break
        else:
            say("502 not done")
    conn.close()


def main():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", PORT))
    s.listen(4)
    print("ftp test server on", PORT, "serving", ROOT, flush=True)
    while True:
        c, a = s.accept()
        threading.Thread(target=handle, args=(c, a), daemon=True).start()


if __name__ == "__main__":
    main()
