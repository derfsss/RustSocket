# rustsocket settings

rustsocket uses Roadshow's settings: the same names, the same tools, the
same places. It adds a few options of its own, marked **rustsocket** below.

## Changing a setting

| How | Example |
|---|---|
| Show every setting | `RoadshowControl` |
| Show one | `RoadshowControl GET tcp.sendspace` |
| Change it until the next reboot | `RoadshowControl SET tcp.sendspace=131072` |
| Change it for good | put the value in a file `ENVARC:Roadshow/<area>/<name>`, for example `ENVARC:Roadshow/if/txcsum` holding `0` |

Programs can also read and change settings through the RoadshowData API
(ObtainRoadshowData, ChangeRoadshowData), as on Roadshow. A value outside
an option's range is refused.

Most settings take effect at once, for new connections. The `if.txcsum`
and `if.rss.queues` options are read when an interface is added: remove
and add the interface again after changing them (or keep the value in
ENVARC and reboot).

## TCP and UDP buffers

| Option | Default | Meaning |
|---|---|---|
| `tcp.recvspace` | 64 KB | a TCP connection's receive buffer to start with |
| `tcp.recvspace.max` | 1 MB | **rustsocket.** How far the receive buffer may grow. Once per round trip the stack measures how fast the program reads and sizes the buffer to twice the data in flight; it shrinks back when the transfer slows down or the connection goes idle. On a local network (round trip under 2 ms) it stops at 512 KB, which keeps the data in the cache and was faster on an AmigaOne X5000 |
| `tcp.sendspace` | 64 KB | a TCP connection's send buffer to start with. Roadshow's default is 32 KB; with 64 KB an AmigaOne X5000 sends at gigabit line rate (115 MB/s instead of 85) |
| `tcp.sendspace.max` | 64 KB | **rustsocket.** How far the send buffer may grow, the same way, on paths with a round trip of 2 ms or more. The default (the same as `tcp.sendspace`) means no growth: internet uploads were no faster with more |
| `udp.recvspace` | 41600 | a UDP socket's receive buffer |
| `udp.sendspace` | 9216 | the largest UDP datagram a socket sends |

## IP and ICMP

| Option | Default | Meaning |
|---|---|---|
| `ip.defttl` | 64 | the time-to-live of new sockets' packets |
| `ip.forwarding` | 0 | 1 routes packets between interfaces (the machine acts as a router) |
| `ip.sendredirects` | 1 | while forwarding, tell senders about a better route (ICMP redirects) |
| `icmp.procesststamp` | 0 | time stamp requests: 0 answered, 1 or 2 not answered |

## Network cards (SANA-II extensions)

These apply only to interfaces whose driver offers the matching feature
of the SANA-II extensions; see [sana2-extensions.md](sana2-extensions.md).
Any other driver ignores them.

| Option | Default | Meaning |
|---|---|---|
| `if.txcsum` | 3 | **rustsocket.** Send checksums left to the card: 1 the IPv4 header, 2 TCP, add them together; 0 none. TCP segmentation by the card needs both (3). Read when an interface is added |
| `if.rss.queues` | 1 | **rustsocket.** Receive queues to ask the card for (receive-side scaling); 1 is off. Read when an interface is added |
| `if.moderation.rx`, `if.moderation.tx` | -1 | **rustsocket.** Microseconds between the card's interrupts for receive and send (0: off); -1 leaves the driver's own. A driver that cannot set send apart uses the receive value for both |
| `if.flowcontrol` | -1 | **rustsocket.** Ethernet pause frames: 1 obey them, 2 send them, 4 negotiate with the other end, add them together; 0 off; -1 leaves the driver's own |

These settings belong to the network card, so when an interface is
removed rustsocket puts back the card's values it found when the
interface was added (unless something else changed them in between).

## The stack's task

| Option | Default | Meaning |
|---|---|---|
| `task.controller.priority` | 0 | the priority of the stack's own task ("TCP/IP Control") |

## Fixed values

rustsocket always works one way for these. Other values are refused.

| Option | Value | What it means |
|---|---|---|
| `udp.cksum` | 1 | UDP checksums are always computed |
| `icmp.processecho` | 0 | pings are always answered |
| `icmp.maskrepl` | 0 | address mask requests are never answered |

## Stored only

RoadshowControl lists these and they can be set, so that Roadshow's tools
and scripts work unchanged, but rustsocket does not act on them:

`bpf.bufsize`, `ip.subnetsarelocal`, `tcp.do_rfc1323`,
`tcp.do_timestamps`, `tcp.do_win_scale`, `tcp.mssdflt`, `tcp.rttdflt`,
`tcp.use_mssdflt_for_remote`, `tcp.random`, `if.receive.useclusters`,
`if.minclustersize`.
