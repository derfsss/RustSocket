"""Count UDP datagrams per port on the PC's loopback (the guests reach it as
10.0.3.2 through slirp): udpcount.py SECONDS PORT [PORT ...]

Prints each datagram as it arrives and a count per port at the end. Binds
127.0.0.1 only, so nothing is exposed to the network."""
import select
import socket
import sys
import time


def main():
    secs = float(sys.argv[1])
    socks = {}
    for p in sys.argv[2:]:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(('127.0.0.1', int(p)))
        socks[s] = int(p)
    counts = {p: 0 for p in socks.values()}
    end = time.time() + secs
    while True:
        left = end - time.time()
        if left <= 0:
            break
        ready, _, _ = select.select(list(socks), [], [], left)
        for s in ready:
            data, addr = s.recvfrom(2048)
            counts[socks[s]] += 1
            print(f'{time.strftime("%H:%M:%S")} port {socks[s]} from {addr[0]}:{addr[1]} {data!r}', flush=True)
    for p in sorted(counts):
        print(f'port {p}: {counts[p]} datagrams', flush=True)


if __name__ == '__main__':
    main()
