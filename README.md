# rustsocket.library

A TCP/IP stack for AmigaOS 4.1 Final Edition, written in Rust on
[smoltcp](https://github.com/smoltcp-rs/smoltcp), that replaces Roadshow's
bsdsocket.library. It runs over any SANA-II network driver and is
configured exactly as Roadshow is: Roadshow's own S:Network-Startup,
AddNetInterface, the DEVS:NetInterfaces and DEVS:Internet files,
RoadshowControl and the other tools work unchanged on it, and so do the
programs that use bsdsocket.library, PPC and 68k alike.

Status: beta. Every bsdsocket.library call that Roadshow 1.15 offers is
implemented (a few with documented gaps), and Roadshow's tools run on it.
[docs/roadshow-compat.md](docs/roadshow-compat.md) lists, call by call and
tool by tool, what works, what is partial, and where rustsocket differs
from Roadshow on purpose.

## What is in it

- Sockets: TCP and UDP over IPv4, raw sockets, routing sockets (PF_ROUTE),
  WaitSelect, non-blocking I/O, socket events and signals, descriptor
  passing between tasks.
- Name resolution: a DNS client of its own (A, CNAME, PTR), the hosts file,
  the DEVS:Internet databases, getaddrinfo/getnameinfo.
- Interfaces configured at run time (AddInterfaceTagList and the rest of
  Roadshow's interface API), DHCP, static addresses, aliases, routes, name
  servers, several interfaces at once, IP forwarding with ICMP errors and
  redirects.
- Roadshow's extra APIs: RoadshowData (RoadshowControl), network
  statistics, monitoring hooks, the server API, kernel memory (mbufs), the
  packet filter (bpf, so tcpdump runs), and IP Filter 3.4's kernel side
  (rules, state, NAT, logging, auth), so Roadshow's ipf, ipfstat, ipmon
  and ipnat work.
- The Internet superserver (DEVS:Internet/servers, including DOS servers),
  the TCP: handler, and the "TCP/IP Control" port NetShutdown uses.
- A 68k jump table, so 68k programs run on it too.
- Receive and send buffers that size themselves to the connection
  (see [docs/settings.md](docs/settings.md)).
- The unofficial SANA-II extensions (sana2ext, version 1), with a driver
  that offers them (such as [igb.device](https://github.com/derfsss/igb)
  for Intel I210/I350 cards): frames read and written in batches,
  checksums checked and computed by the card, large TCP sends cut into
  segments by the card, jumbo frames, interrupt moderation, flow control
  and several receive queues. Any other driver is used through plain
  SANA-II. See [docs/sana2-extensions.md](docs/sana2-extensions.md).

## Speed

AmigaOne X5000 (P5020, 2 GHz) on gigabit Ethernet to a PC, measured with
netprof (256 MB each way, every byte checked), each stack with its default
settings, all on the same day:

| Card and driver | | Roadshow 1.15 | rustsocket |
|---|---|---|---|
| Intel I210, igb.device (with the SANA-II extensions) | receive | 100-101 MB/s, 93% CPU | 94-96 MB/s, 96-98% CPU |
| | send | 85 MB/s, 67-71% CPU | 100-106 MB/s, 75-84% CPU |
| On-board, p50x0_eth.device (plain SANA-II) | receive | not measured that day | 67.5 MB/s |
| | send | not measured that day | 100.6 MB/s, 96% CPU |

- Roadshow sends with a 32 KB buffer by default, rustsocket with 64 KB;
  that is most of the send difference.
- Roadshow still receives a little faster, with less CPU. Receive cost per
  frame is the main open work.
- With the I210, the SANA-II extensions take rustsocket's receive from
  69 to 94-96 MB/s and cut the CPU used for sending by about 20 points
  (details in [docs/sana2-extensions.md](docs/sana2-extensions.md)).

## Layout

| Path | What |
|---|---|
| `rsnet-core/` | the stack: the SANA-II link, smoltcp on it, the stack process, sockets, routes, DNS, the IP filter, NAT, bpf, statistics |
| `rustsocket/` | the shared library: the bsdsocket.library interface (PPC and 68k), its glue, the superserver, the TCP: handler |
| `docs/roadshow-compat.md` | compatibility with Roadshow, item by item |
| `docs/settings.md` | every setting (RoadshowControl options), Roadshow's and rustsocket's own |
| `docs/sana2-extensions.md` | the SANA-II extensions: what they do for users, and what rustsocket asks of a driver |
| `release/ReadMe` | the end-user ReadMe that goes into the release archive |
| `testprogs/` | AmigaOS test programs: `rstcp` (the library's checks, with C probes in `rstcp/c/`), `netprof` (network profiler), `rsnet` and `rsprobe` (the stack core and the library's openers) |
| `tools/` | `build-package.sh`, `build-all.sh`, `netprof-host` (netprof's peer on a PC), the generators of the PPC and 68k jump tables, small host-side servers the tests use |
| `amigaos4/` | the [amigaos4](https://github.com/derfsss/rust-amigaos4-crate) crate (AmigaOS 4 bindings for Rust), a git submodule |
| `third_party/smoltcp-0.14.0/` | smoltcp 0.14.0, vendored with small patches (each marked "VirtioRust patch" or "rustsocket patch"): buffer resizing for auto-tuning, the window-scale choice, neighbour-cache access for the ARP table, route selection, TCP loss counters |

The stack runs in its own process; a program's socket calls run in the
program's task where they can (TCP send and receive copy under the stack's
lock) and are sent to the stack process otherwise.

## Building

The library builds with the `amigaos` Rust toolchain of the `amigaos4`
crate (a submodule of this repository: `git submodule update --init`, then
`amigaos4/tools/build-toolchain.sh`) and links inside the
`walkero/amigagccondocker:os4-gcc15-3.6.1` Docker image. On Linux or WSL:

```
git submodule update --init
MAKE_ARGS=DROPIN=1 tools/build-package.sh rustsocket
tools/build-all.sh          # the library under both names and every test program
```

gives `rustsocket/dropin/bsdsocket.library`, the library to install
in place of Roadshow's. Without `MAKE_ARGS=DROPIN=1` the same code is
built as `rustsocket.library` (`rustsocket/rustsocket.library`),
which programs can open by that name beside Roadshow for testing; Roadshow's
tools do not configure it, so a test program adds its interfaces through
the interface API (as `rstcp` does).

Adding `--features perf` (`tools/build-package.sh rustsocket
--features perf`) times the stack's phases and prints them on the debug
output every 10 s.

## Installing

See [release/ReadMe](release/ReadMe): back up LIBS:bsdsocket.library, copy
rustsocket's in its place and reboot. Nothing else changes; putting
Roadshow's file back returns to Roadshow.

## Testing

- `testprogs/rstcp`: the library's test program. With no arguments it runs
  the main suite (TCP client and server, UDP, WaitSelect, non-blocking
  sockets, DNS, base tags, options, RoadshowData; netprof-host must be
  running on the peer); `rstcp iface`, `multi`, `monitor`, `server`,
  `servers`, `ipf`, `bpf` and others test one area each.
  `testprogs/rstcp/c/` holds small C probes that print what a call does, run
  on Roadshow first and then on rustsocket.
- `testprogs/netprof`: the network profiler (throughput, CPU, round trips,
  the stack's and driver's counters) against `tools/netprof-host` on a PC.
- smoltcp's own unit tests, on the host:
  `cargo test --lib --features socket-tcp-reno` in
  `third_party/smoltcp-0.14.0`.
- The stack's device-free logic (the SANA-II extensions' bookkeeping), on
  the host: `cargo test` in `rsnet-core/host-tests`.

## Credits

- [smoltcp-rs/smoltcp](https://github.com/smoltcp-rs/smoltcp): the TCP/IP
  library the stack is built on, vendored in `third_party/` with small
  patches (0BSD).
- [derfsss/rust-amigaos4-crate](https://github.com/derfsss/rust-amigaos4-crate):
  the `amigaos4` crate (AmigaOS 4 bindings for Rust), the `amigaos4/`
  submodule.
- [AmigaLabs/rust](https://github.com/AmigaLabs/rust) (branch `amigaos-port`):
  the Rust fork with the `powerpc-unknown-amigaos` target.
- [walkero-gr/amigagccondocker](https://github.com/walkero-gr/amigagccondocker):
  the cross-compiler Docker image (gcc and the AmigaOS SDK) the library is
  linked in.
- [derfsss/VirtioRust](https://github.com/derfsss/VirtioRust): where
  netprof and netprof-host come from, and the QEMU test machines.
- Roadshow, by Olaf Barthel: the bsdsocket.library this one is compatible
  with; its documentation and behaviour are the reference
  (`docs/roadshow-compat.md`).
- IP Filter 3.4.21, by Darren Reed: the rule engine, state, NAT, logging
  and auth that `rsnet-core/src/ipfil.rs` and `ipnat.rs` reimplement in Rust
  from its public source, so that Roadshow's ipf tools work unchanged.

## Licence

MIT (LICENSE). smoltcp is under the 0BSD licence
(`third_party/smoltcp-0.14.0/LICENSE-0BSD.txt`).

---

Richard Gibbs — rich_gibbs@hotmail.com
