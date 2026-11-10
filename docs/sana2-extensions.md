# SANA-II extensions in rustsocket

SANA-II, the AmigaOS network driver interface, moves one frame per
request and leaves all checksum work to the CPU. Modern network cards can
do much more: take many frames at once, check and fill in checksums, cut
large TCP sends into packets, and spread received traffic over several
queues.

The **SANA-II extensions** (sana2ext, version 1) are an unofficial,
optional addition to SANA-II that lets a driver offer those features. A
driver that has them still works as a plain SANA-II driver, so Roadshow
and every other program use it as before. rustsocket finds them by itself
and uses whatever the driver offers.

The full specification, for driver writers, is in the amigaos4 crate:
[docs/devices/sana2ext.md](https://github.com/derfsss/rust-amigaos4-crate/blob/main/docs/devices/sana2ext.md),
with the C header `include/devices/sana2ext.h`.

Contents:

- [For users](#for-users)
  - [Which drivers have them](#which-drivers-have-them)
  - [What rustsocket does with them](#what-rustsocket-does-with-them)
  - [What it gains](#what-it-gains)
  - [Is it on?](#is-it-on)
  - [Settings](#settings)
  - [Things to know](#things-to-know)
- [For driver writers](#for-driver-writers)
  - [How rustsocket finds the extensions](#how-rustsocket-finds-the-extensions)
  - [What rustsocket asks of each feature](#what-rustsocket-asks-of-each-feature)
  - [When something is refused](#when-something-is-refused)
  - [Testing a driver](#testing-a-driver)

---

## For users

### Which drivers have them

| Driver | Cards | Extensions |
|---|---|---|
| [igb.device](https://github.com/derfsss/igb) | Intel I210, I211, I350, 82576 (gigabit) | all of them |

Any other driver is used through plain SANA-II, as before. Nothing needs
to be set up: rustsocket asks each driver when an interface is added.

### What rustsocket does with them

| Feature | What it means | What rustsocket does |
|---|---|---|
| **Batches** | many frames in one request, both ways | reads received frames up to 32 at a time, and sends up to 64 at a time. Fewer requests means less work per frame |
| **Receive checksums** | the card checks IP, TCP and UDP checksums | does not check them again. Frames the card found bad are dropped and counted as input errors |
| **Send checksums** | the card fills in checksums | leaves the IPv4 header and TCP checksums to the card (option `if.txcsum`) |
| **TCP segmentation** | the card cuts one large send into packets | hands the card TCP sends of up to 64 KB at once, instead of one packet at a time |
| **MTU** | the card's packet size can be changed | an MTU above 1500 (jumbo frames) in an interface file or with ConfigureNetInterface really changes the card's MTU |
| **Interrupt moderation** | how often the card interrupts the CPU | set with `if.moderation.rx` / `if.moderation.tx` |
| **Flow control** | Ethernet pause frames | set with `if.flowcontrol` |
| **Receive-side scaling (RSS)** | received traffic spread over several queues by connection | asks for `if.rss.queues` queues. It helps only once AmigaOS can use more than one CPU, so it is off by default |

### What it gains

AmigaOne X5000 (P5020, 2 GHz) with an Intel I210 card and igb.device,
gigabit Ethernet to a PC, measured with netprof (every byte checked):

| | Receive | Send | CPU while sending |
|---|---|---|---|
| Plain SANA-II (rustsocket before the extensions) | 69 MB/s | 99 MB/s | not measured |
| Batches and receive checksums only (`if.txcsum=0`) | 86-88 MB/s | 90-96 MB/s | 92-97% |
| Everything on (the default) | 94-96 MB/s | 100-106 MB/s | 75-84% |

The last row was measured with a later igb.device whose own receive path
had also become cheaper, so part of its receive gain is the driver's.

Where the gain comes from:

- **Receive:** batches and the card's checksum checks make each received
  frame cheaper. TCP's own checksum work fell from about 1.6 µs to
  0.16 µs per frame.
- **Send:** the line was already full, so the gain is CPU time. With send
  checksums and segmentation the card does the work: in one test 102,715
  large sends left the card as 1,545,226 packets.

### Is it on?

When an interface is added, rustsocket writes a line to the debug output
(`DumpDebugBuffer` or NetLogViewer shows it) saying what the driver
offers, for example:

```
rsnet: networks/igb.device unit 0: SANA-II extensions version 1 revision 1:
batches of 64 frames, rx checksums 0x1f, tx checksums 0x1f, segmentation ...
```

No such line means the driver is used through plain SANA-II.

`ShowNetStatus INTERFACE <name>` also shows it: with the extensions the
read and write request counts are the frames in rustsocket's batches
(128 IPv4 and 8 ARP read frames, 64 write frames), instead of 36 reads
and 1 write.

### Settings

These options apply only to interfaces whose driver offers the matching
feature. Change them with RoadshowControl, for example
`RoadshowControl SET if.txcsum=0`. The `if.txcsum` and `if.rss.queues`
options are read when an interface is added, so remove and add the
interface again after changing them. A value set with RoadshowControl
lasts until the next reboot; to keep it, put it in a file such as
`ENVARC:Roadshow/if/txcsum`.

| Option | Default | Meaning |
|---|---|---|
| `if.txcsum` | 3 | send checksums left to the card: 1 the IPv4 header, 2 TCP, add them together; 0 none. TCP segmentation needs both (3) |
| `if.rss.queues` | 1 | receive queues to ask for; 1 is off |
| `if.moderation.rx`, `if.moderation.tx` | -1 | microseconds between interrupts for receive and send (0: off); -1 leaves the driver's own |
| `if.flowcontrol` | -1 | pause frames: 1 obey, 2 send, 4 negotiate, add them together; 0 off; -1 leaves the driver's own |

All of rustsocket's options are in [settings.md](settings.md).

**Settings are put back.** Moderation, flow control, the MTU and the
receive queues belong to the network card, not to the interface. When an
interface is removed, rustsocket sets back everything it changed to what
it found when the interface was added, unless something else changed it
in between.

### Things to know

- **tcpdump and monitoring hooks** see sent frames before the card fills
  in the checksums, so tcpdump may report them as wrong. A large TCP send
  that the card will cut up is seen as one large frame. Both are normal.
- **The IP filter** (ipf) and the filter hook can change frames, so while
  either is active rustsocket checks every received checksum itself.
- **Jumbo frames** need every machine and switch on the network to be set
  for them. Set the MTU in the interface file (`MTU=9000`) on both ends.
- **To rule the extensions out** when looking for a problem: set
  `RoadshowControl SET if.txcsum=0` and add the interface again. That
  turns off send checksums and segmentation, which are the features that
  change what goes on the wire. Batches and receive checksums stay on.

---

## For driver writers

The specification says what a driver must do; this part says what
rustsocket actually uses, so a driver can be tested against a real stack.

### How rustsocket finds the extensions

At OpenDevice, rustsocket sends `S2X_QUERY` (0xC100) and accepts the
answer only if `s2xq_Magic` is `S2X_MAGIC` ('S2XT') and the version is 1.
It then reads the capability items and also checks `NSCMD_DEVICEQUERY`'s
command list for `S2X_READBATCH`, `S2X_WRITEBATCH` and `S2X_CONFIGURE`.

It drops anything the spec says cannot stand alone: every offload needs
batches, and segmentation needs send checksums for its protocols. A
driver that offers only part of the set still gets the parts that stand.

If the driver offers `S2X_CONFIGURE`, rustsocket reads the current
settings with `S2XCF_READ` straight after opening, and remembers them so
it can put them back at close.

### What rustsocket asks of each feature

| Feature | rustsocket's use |
|---|---|
| `S2XCAP_BATCH` | IPv4: 128 read frames in batches of 32 (smaller if `s2xcb_MaxFrames` is smaller); ARP: 8 frames in batches of 4; one write batch of up to 64 frames. Read frames are `SANA2IOF_RAW`. With RSS, each queue gets its share of both |
| `S2XCAP_RXCHECKSUM` | an `S2XFRAME_CHECKSUM` item on every read frame. `S2XCS_IP_GOOD` / `S2XCS_L4_GOOD` skip the software check; `_BAD` drops the frame |
| `S2XCAP_TXCHECKSUM` | IPv4 header (`S2XCS_FILL_IP`) and TCP over IPv4 (`S2XCS_FILL_L4`) only, within `if.txcsum`. The pseudo-header sum is computed after NAT. A frame sent with a plain `CMD_WRITE` gets its checksums in software |
| `S2XCAP_SEGMENT` | TCP over IPv4 only, needing both send checksums. Sends up to `s2xcs_MaxSize` (at most 64 KB plus the Ethernet header) with the pseudo-header sum computed for length 0, as the spec says. A send past the card's segment limits is cut by rustsocket itself |
| `S2XCAP_MTU` | `S2XSET_MTU` when an interface file or ConfigureNetInterface asks for more than the driver's MTU. rustsocket first aborts its own reads (the spec refuses an MTU change while reads are posted), changes the MTU, reads it back with `S2_DEVICEQUERY`, resizes its buffers and posts its reads again. Up to 16000 bytes |
| `S2XCAP_MODERATION`, `S2XCAP_FLOWCONTROL` | set from the options at open, only when the option is not -1 |
| `S2XCAP_RSS` | `S2XSET_RSS` with the queue count and the IPv4 hash types (IPv4, TCP, UDP), up to 8 queues. The key and table are left to the driver (NULL), so the driver's own defaults must spread connections well. One stack task serves every queue |

### When something is refused

- **A batch refused as malformed** (`S2ERR_BAD_ARGUMENT`, `IOERR_BADLENGTH`
  on the batch itself): rustsocket stops using batches of that kind and
  falls back to plain `CMD_READ` / `CMD_WRITE`, with a line on the debug
  output. A driver that refuses well-formed batches therefore still works,
  only slower.
- **A refused frame in a write batch:** the frame at `s2xb_Done` carries
  the error; rustsocket counts it as an output error and sends the frames
  after it again.
- **A refused setting:** logged with the item type; the interface works
  with the driver's own value.
- **Closing:** settings are put back with one `S2X_CONFIGURE`. A refusal
  there is logged and ignored.

### Testing a driver

- **s2xtest**, the conformance test written with igb.device (not yet
  published), checks a driver against the specification item by item:
  query, batches, checksums both ways, segmentation, settings, RSS, and
  the refusal rules. It needs two ports on one link, or one port plus a
  router to talk to.
- **netprof** (`testprogs/netprof`, with `tools/netprof-host` on a PC)
  measures throughput and CPU through rustsocket and prints the driver's
  own counters, so a driver can be compared with and without the
  extensions (`if.txcsum=0`).
- Check the debug output after adding the interface: the
  "SANA-II extensions" line shows what rustsocket understood the driver
  to offer.
