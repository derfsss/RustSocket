"""Send one UDP datagram of N bytes (byte o is o % 251) to 127.0.0.1:PORT,
which QEMU's user network forwards to a guest (e.g. hostfwd=udp::4511-:4511),
after DELAY seconds.

    python -I tools/udpsend.py PORT N [DELAY]
"""
import socket
import sys
import time

port, n = int(sys.argv[1]), int(sys.argv[2])
delay = float(sys.argv[3]) if len(sys.argv) > 3 else 0.0
time.sleep(delay)
data = bytes(o % 251 for o in range(n))
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(data, ("127.0.0.1", port))
print("sent", n, "bytes to", port)
