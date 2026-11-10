# s2xtest

A conformance test for AmigaOS 4 SANA-II network drivers that offer the
unofficial SANA-II extensions ("sana2ext", version 1: the amigaos4 crate's
`docs/devices/sana2ext.md`, header `include/devices/sana2ext.h`). Any
driver that lists `S2X_QUERY` is checked with it; a driver that does not is
reported as plain SANA-II and nothing is checked.

It needs **two units of the driver joined by one link**: unit A sends and
unit B receives, so every check sees what really went over the wire. On
real hardware that is a cable between two ports (or two cards); on QEMU,
two cards linked to each other (see below). No TCP/IP stack may use
either unit while it runs. With only one port, give the same unit twice:
the checks that need a frame to come back are then skipped by name.

## Use

```
s2xtest <device> <unit A> <unit B> [only=name,...] [need=name,...] [echo=U,MYIP,GWIP[,PORT]]
```

- `device`: as for OpenDevice, e.g. `networks/igb.device`.
- `only=`: run only the checks whose names start with these (e.g.
  `only=batch,dispatch`). Discovery always runs.
- `need=`: capabilities the driver must offer (`batch`, `rxcsum`,
  `txcsum`, `segment`, `mtu`, `moderation`, `flow`, `rss`); a missing one
  is a failure instead of a skip.

Every check prints `PASS`, `FAIL`, `SKIP` (not offered) or `INFO` (the spec
leaves the answer open, or the driver claims nothing that makes it a
requirement), and the same line goes to the serial console. The return
code is 0 when nothing failed, 20 otherwise. Every check needs a positive
count of what it received: a check that receives nothing fails by name.

Both units are configured with their factory addresses and brought
online; the test waits for each link (S2EVENT_CONNECT, 8 s).

## Checks

| Name | What it checks |
|---|---|
| `open` | Both units open, configure and report a link. |
| `query.answer` | `S2X_QUERY` succeeds with `S2X_MAGIC`, version >= 1 and a capability list. |
| `query.items` | The list has items, each at least as large as its type's structure. |
| `query.features` | `s2xq_Features` has exactly one bit per listed type (1-31). |
| `query.cmdlist` | `NSCMD_DEVICEQUERY` lists `S2X_READBATCH`/`S2X_WRITEBATCH` with `S2XCAP_BATCH`, and `S2X_CONFIGURE` with any setting capability. |
| `query.depends` | Frame offloads come with `S2XCAP_BATCH`; segmentation with TX checksums for its protocols; MaxFrames >= 1. |
| `query.short` | `s2xq_Size` 8: only the magic is written, nothing after it. |
| `query.stable` | A second query returns the same list and features. |
| `batch.write` | A write batch of 8 frames: no error, `s2xb_Done` 8, every frame arrives once, in order, byte for byte. |
| `batch.read` | A read batch of 16 takes the 5 frames of a write batch: each frame's request filled as by CMD_READ (type, addresses, length, data, no BCAST/MCAST, io_Error 0). |
| `batch.raw` | `SANA2IOF_RAW` on a read batch: every frame with its Ethernet header. |
| `batch.full` | A read batch of 4 never reports more than 4; 10 frames come through it (reposted), in order. |
| `dispatch.order` | CMD_READ, read batch, CMD_READ posted in that order receive three frames sent one at a time in that order (the oldest waiting request gets the frame). |
| `dispatch.batchfirst` | A read batch posted before a CMD_READ gets the first frame. |
| `dispatch.openers` | Two openers (a read batch, a CMD_READ) each get a copy of a frame. |
| `abort.read` | An idle read batch aborted: IOERR_ABORTED, `s2xb_Done` 0. |
| `abort.write` | A write batch of MaxFrames (at most 64), aborted at once: either it was all taken (no error, `s2xb_Done` = Count) or IOERR_ABORTED part-way; B receives exactly `s2xb_Done` frames. The line says which happened. |
| `write.refuse` | The fourth of six frames is longer than the MTU: the batch and that frame have the error, `s2xb_Done` 3, frames 5 and 6 are untouched, B receives exactly three frames. |
| `bad.*` | Refused at once: `ios2_StatData` NULL (read and write), `s2xb_Count` 0, a queue that does not exist, `s2xb_Size` too small. `bad.overmax` (more frames than MaxFrames) is INFO: the spec does not say. |
| `rxcsum.*` | With `S2XCAP_RXCHECKSUM`: IPv4 UDP/TCP and IPv6 UDP/TCP frames with right and wrong transport checksums, an IPv4 header with a wrong checksum: the results must match for each protocol the driver claims. A private (unknown) frame item after the checksum item must be left untouched. `rxcsum.v4.udp.zero` (UDP without a checksum) passes with "not checked" or "good"; `rxcsum.v4.frag` (an IPv4 first fragment) must have no L4 result; `rxcsum.noitem` and `rxcsum.nonip`: a frame without items arrives, a non-IP frame has no result. |

| `txcsum.*` | With `S2XCAP_TXCHECKSUM`, for each protocol claimed: write batch frames with `FILL_IP` and/or `FILL_L4` (the IPv4 header checksum zeroed, the transport field holding the pseudo-header sum); B checks every checksum in software and the rest of the packet byte for byte. UDP and TCP over IPv4 and IPv6, the IPv4 header alone, TCP alone, a RAW frame (offsets from the Ethernet header), and ICMP (Start at the ICMP header, Offset 2: a sum a TCP/UDP-only card cannot place, so the driver must compute it). `txcsum.outside` (a result past the frame's end) is INFO. |
| `txcsum.*.raw` (short) | RAW frames under the 60-byte minimum, as stacks send them: a 54-byte TCP ACK with `FILL_IP` + `FILL_L4`, `FILL_L4` only, `FILL_IP` only; a small UDP frame; ICMP echo with `FILL_IP` only; an IPv6 ACK. The packet must arrive byte for byte, IP total length included (padding must never become part of the packet). |
| `tso.*` | With `S2XCAP_SEGMENT`: one large TCP send (IPv4 20000 bytes, IPv6 12000, RAW 8000, one segment, the largest send offered) carrying the pseudo-header sum with a length of 0; every segment's IP and TCP checksums, payload length and sequence number are checked, IP ids must differ, and the payload put back together must equal what was sent. `tso.overmtu` is INFO. |
| `rss.*` | With `S2XCAP_RSS` (two queues): the tool's own Toeplitz hash against the datasheet vector; `S2XSET_RSS` with a key and an even table, read back; 32 UDP/TCP flows read through one read batch per queue, each frame's queue, hash and hash type checked against the hash computed here; both queues used; `S2ERR_BAD_STATE` when turning RSS off with a batch posted on queue 1; off again (a batch on queue 1 refused). |
| `echo.*` | With `echo=U,MYIP,GWIP[,PORT]` and `S2XCAP_TXCHECKSUM`: against a real IP stack on unit U (QEMU's slirp, or a router). ARP for the gateway, ICMP echo with `FILL_IP` only (56 and 1400 bytes), a 54-byte TCP SYN with each checksum request and with none (the baseline) to PORT (default 4530; use a port something listens on, since QEMU's slirp is slow to refuse a closed one): each must be answered. |
| `conf.*` | With a setting capability: `S2XCF_READ` fills every item (the MTU equals S2_DEVICEQUERY's); unknown and private types are refused with `S2ERR_NOT_SUPPORTED`, `s2xc_Failed` set and nothing changed; values above the capability are refused with `S2ERR_BAD_ARGUMENT` (an MTU out of range may get `S2ERR_BAD_STATE` instead while another opener has reads posted); `S2XSET_MTU` with a CMD_READ posted gets `S2ERR_BAD_STATE`; moderation is written back, read back the same and sends `S2EVENT_CONFIGCHANGED`; flow control forced and read back; MTU 9000 on both units (with `S2XCAP_MTU` reaching it): S2_DEVICEQUERY says 9000, a read posted during the link reset stays queued and receives a 9000-byte frame, 9001 bytes are refused, then 1500 again; skipped when the change gets `S2ERR_BAD_STATE` because another opener (a stack) has reads posted. Settings are put back afterwards. |

Test frames use EtherType 0x88B5 (IEEE 802 local experimental) with a
payload of "S2X", a test id, a sequence number and a pattern, so frames
left over from one check are never counted for another.

## QEMU

Three igb cards on one AmigaOne: one on QEMU's user network (slirp) for
the echo checks, two linked to each other by `dgram` netdevs that send to
each other, like a cable between two ports:

```
-netdev user,id=n3,net=10.0.5.0/24,dhcpstart=10.0.5.15 -device igb,netdev=n3,addr=0x0a
-netdev dgram,id=a,local.type=inet,local.host=127.0.0.1,local.port=12360,remote.type=inet,remote.host=127.0.0.1,remote.port=12362
-device igb,netdev=a,addr=0x0c
-netdev dgram,id=b,local.type=inet,local.host=127.0.0.1,local.port=12362,remote.type=inet,remote.host=127.0.0.1,remote.port=12360
-device igb,netdev=b,addr=0x0e
```

The cards then are units 0 (slot 0x0a), 1 (0x0c) and 2 (0x0e):
`s2xtest networks/igb_diag.device 1 2 echo=0,10.0.5.15,10.0.5.2,PORT`. QEMU's
igb needs a small patch to start on these machines, and puts its virtual
functions at slot + 0x10 (slots 0x0a, 0x0c and 0x0e do not collide; 0x0b
and 0x0c would): see igb.device's
[docs/testing.md](https://github.com/derfsss/igb/blob/main/docs/testing.md).

What QEMU's igb (QEMU 11) cannot show:

- Its RSS takes the queue from bit 7 of a redirection table entry, not
  from bits 2:0 as the chips do: only queues 0 and 1 can be reached, so
  `rss.*` uses two queues (a driver may have to set bit 7 for QEMU).
- It does not throttle interrupts or send pause frames: moderation and
  flow control are checked as settings only.
- It inserts transmit checksums itself (in software), so it shows that a
  driver asked for the right thing, not what a real card would compute.
- Its transmit is synchronous: a write batch is always taken whole before
  an AbortIO can reach it, so `abort.write` takes the "all taken" branch.
- It checks receive checksums in software for frames from a peer card;
  real cards are checked on real hardware only.

## Build

Linux (WSL works), the "amigaos" Rust toolchain from the amigaos4 crate
(`tools/build-toolchain.sh`), Docker with the
`walkero/amigagccondocker:os4-gcc15-3.6.1` image:

```
tools/build-package.sh testprogs/s2xtest
```

(from the repository's top folder; `tools/build-all.sh` builds it with
the rest). It builds against this repository's amigaos4 submodule; the
driver under test must implement the same sana2ext version (1). The
output is `testprogs/s2xtest/s2xtest`, an AmigaOS Shell command with no C
library.

## Licence

MIT. Richard Gibbs <rich_gibbs@hotmail.com>
