# rustsocket.library and Roadshow: compatibility

rustsocket.library is meant to replace Roadshow's bsdsocket.library on
AmigaOS 4.1 Final Edition without programs, tools or configuration files
noticing. This file lists, call by call and tool by tool, what works, what
works with a gap, and where rustsocket behaves differently from Roadshow
on purpose.

The reference is Roadshow 1.15 (bsdsocket.library 4.370), its
documentation (SYS:Documentation/Roadshow), the SDK 54.25 autodoc
(bsdsocket.doc) and netinclude/libraries/bsdsocket.h. Where Roadshow and
its own autodoc disagree, the row says which one rustsocket follows.
Behaviour marked "as Roadshow" was measured on Roadshow first (mostly with
the probes in testprogs/rstcp/c/) and then on rustsocket.

States: **done** (works as Roadshow documents), **partial** (works, with
the gap named), **missing** (stub: ENOSYS, or the tag or option refused).

Every Roadshow tool first asks SocketBaseTagList what the library offers
(SBTC_HAVE_*_API) and stops with "does not support the ... method used by
this program" when the answer is no, so rustsocket answers TRUE for an API
only once all of its calls work. A call that is still a stub logs its name
and the calling task once per opener on the debug output ("... is not done
yet: ENOSYS").

## Library calls

| Group | Calls | State |
|---|---|---|
| Sockets | socket, bind, listen, accept, connect, send/recv, sendto/recvfrom, sendmsg/recvmsg, shutdown, CloseSocket, getsockname/getpeername, WaitSelect, IoctlSocket (FIONBIO, FIONREAD, FIOASYNC) | done for TCP and UDP over IPv4. Ephemeral ports are handed out as 4.4BSD's in_pcbbind and Roadshow do: 1024 first after start-up, counting up to 5000 and round again, TCP and UDP each on their own, for connect, a UDP send, bind to port 0 and listen on an unbound socket |
| UDP datagrams over the MTU | sendto up to udp.sendspace (9216), receiving fragmented datagrams | done: IPv4 fragmentation and reassembly (16 KB buffers, two reassemblies at once); datagrams leave in the same fragments as Roadshow's. Datagrams still queued when a UDP socket is closed are sent first (5 s at most) |
| Raw sockets | socket(SOCK_RAW, any protocol), IP_HDRINCL, IP_TTL | done: the IP header is added on send (or given with IP_HDRINCL; IPPROTO_RAW always); received packets arrive whole with their sender; the stack still answers pings itself. IP_TTL sets the TTL of TCP, UDP and raw sockets; a raw socket without it sends with 255 (4.4BSD rip_output, as Roadshow). Differs: every IPv4 header leaves with ID 0 and DF set, where Roadshow counts IDs and leaves DF clear (allowed by RFC 6864, as Linux does; invisible to programs) |
| Routing sockets | socket(PF_ROUTE), RTM_GET/ADD/DELETE/CHANGE | done: routes and the ARP table (RTF_LLINFO, link-level gateways); answers carry rtm_pid of the writer. Not yet: messages copied to other routing sockets, RTM_MISS and RTM_REDIRECT announcements |
| Interface ioctls | SIOCGIFCONF, SIOCGIF{ADDR,NETMASK,BRDADDR,FLAGS,METRIC,DSTADDR}, SIOCSIF{ADDR,NETMASK,FLAGS}, SIOCAIFADDR, SIOCDIFADDR, SIOCATMARK, process group, water marks | done, through the stack's interface configuration: one address per interface (an alias replaces it); SIOCGIFDSTADDR gives EINVAL (no point-to-point); SIOCADDMULTI/DELMULTI give EOPNOTSUPP (no multicast); SIOCGARP/SARP/DARP are not in this SDK (arp uses routing sockets) |
| Socket options | SO_RCVTIMEO/SNDTIMEO, SO_KEEPALIVE, TCP_NODELAY, SO_LINGER, SO_EVENTMASK, flag options | done |
| | SO_SNDBUF / SO_RCVBUF | partial: new sockets take tcp.recvspace/sendspace and udp.recvspace/sendspace (RoadshowControl), and getsockopt reports the real sizes; setsockopt does not resize a socket. Differs: tcp.sendspace defaults to 64 KB, not 32 KB (gigabit sends at line rate on an AmigaOne X5000 with it: 115 MB/s instead of 85), and TCP buffers are auto-tuned (see Settings) |
| | IP_TTL, IP_TOS | partial: IP_TTL as above; IP_TOS accepted with no effect |
| Descriptors | Dup2Socket, ReleaseSocket, ReleaseCopyOfSocket, ObtainSocket, getdtablesize, SetSocketSignals, GetSocketEvents | done |
| Base tags | SocketBaseTagList, every SBTC code | done, see below |
| Errors | Errno, SetErrnoPtr, h_errno | done |
| syslog | vsyslog / syslog | done: SBTC_LOGMASK, LOGTAGPTR and LOG_HOOK honoured; without a hook the line goes to the debug output (and NetLogViewer shows it), not to a log file |
| Name resolution | gethostbyname(_r), gethostbyaddr(_r), getaddrinfo, getnameinfo, gai_strerror | done, with the stack's own DNS client: A queries following CNAMEs, PTR queries for reverse lookups, the name servers in turn (2 s each, twice round). NXDOMAIN gives HOST_NOT_FOUND, an answer without the record NO_DATA, a server failure or silence TRY_AGAIN. gethostbyname gives every address and the canonical name with the asked one as an alias, as Roadshow; a hosts-file answer has no aliases. Reverse lookups try the hosts file, then DNS; as Roadshow, a successful gethostbyaddr leaves h_errno as it was. Search list: see name_resolution below |
| Databases | getserv*, getproto*, getnet*, the *ent walks (DEVS:Internet files) | done |
| IP forwarding | ip.forwarding (RoadshowControl, SBTC_IP_FORWARDING, RoadshowData) | done: off by default (datagrams for other hosts dropped silently); on, they go through the routing table with the TTL one lower, through the outgoing interface's filter and NAT. TTL expired: ICMP time exceeded; no route: ICMP host unreachable; too big with DF: fragmentation needed (without DF they are dropped: a router fragments nothing, as Roadshow). A missing next-hop ARP entry is asked for each second and the datagram held up to 5 s. ICMP redirects are sent as Roadshow sends them while ip.sendredirects is 1. As a host, an ICMP redirect from the current gateway changes or adds a host route (4.4BSD rtredirect) |
| Address helpers | inet_*, Inet_*, In_LocalAddr, In_CanForward, gethostid, gethostname, Get/SetDefaultDomainName | done |
| Interface queries | ObtainInterfaceList, ReleaseInterfaceList, QueryInterfaceTagList | done: lo0 is left out of the list as Roadshow does, and answers queries |
| Statistics | GetNetworkStatistics | done: ip, tcp, udp and icmp counters from every frame's headers (packets and bytes each way, TCP data/ACK/control segments, ICMP types), connection events, and the TCP stack's own retransmissions, retransmission timeouts and duplicate ACKs. Still 0: duplicate and out-of-order data, checksum failures; igmp, mb, mrt and rt (nothing of the kind here). TCP and UDP socket lists |
| Interface API | AddInterfaceTagList, ConfigureInterfaceTagList, RemoveInterface, BeginInterfaceConfig, AbortInterfaceConfig, CreateAddrAllocMessageA, DeleteAddrAllocMessage | partial: interfaces are added, configured (address, mask, up/down, release, MTU, metric, broadcast address, aliases) and removed at run time; DHCP runs through the address allocation message, which the stack fills in and replies (address, mask, server, routers, DNS servers, host and domain names, lease expiry). Not yet: BOOTP and the link-local protocols (AAMR_Ignored), requesting a particular address, static routes from DHCP, point-to-point interfaces |
| Routing API | AddRouteTagList, DeleteRouteTagList, ChangeRouteTagList, GetRouteInfo, FreeRouteInfo | done: one table, most specific match, gateways reached through the interface whose subnet holds them; EEXIST / ESRCH / EHOSTUNREACH; GetRouteInfo in Roadshow's rt_msghdr layout and order. Not yet: a destination with no gateway (point-to-point) |
| DNS API | AddDomainNameServer, RemoveDomainNameServer, ObtainDomainNameServerList, ReleaseDomainNameServerList | done: static servers with use counts, DHCP's as dynamic, listed as Roadshow lists them |
| RoadshowData | ObtainRoadshowData, ReleaseRoadshowData, ChangeRoadshowData | done: Roadshow's 23 options plus two of rustsocket's own (see Settings). ip.defttl, ip.forwarding, ip.sendredirects, icmp.procesststamp, tcp/udp recvspace/sendspace and task.controller.priority take effect; options the stack cannot honour refuse other values (EINVAL); the rest are kept. One writer at a time (EBUSY), with exec semaphore rules as Roadshow's |
| Monitoring | AddNetMonitorHookTagList, RemoveNetMonitorHook | done: MHT_Connect/Bind/Send in the caller's task (a positive result fails the call with that errno), MHT_Packet/ICMP/UDP/TCP_Connect in the stack on each frame. MA_Ignore and MA_DropWithReset drop like MA_Drop (no reset is sent) |
| Server API | ProcessIsServer, ObtainServerSocket | done: the superserver records each program it starts before the program runs; ObtainServerSocket hands the socket out once |
| Kernel memory + IP filter hook | mbuf_* (11 calls), SBTC_IP_FILTER_HOOK, SBTC_IPF_API_VERSION | done: the hook sees every IPv4 datagram in (before the stack) and out, with IPFilterMsg as Roadshow's; it can drop or replace a datagram. mbufs follow the SDK's sys/mbuf.h and the 4.4BSD routines. Roadshow differs from its own autodoc in two calls (its mbuf_copym shares the data, its mbuf_cat leaves the chain as it was); rustsocket does what the autodoc says |
| Packet filter | bpf_* (8 calls) | done: 8 channels, received and sent frames tapped, the classic filter machine checked as BSD checks it, read timeout/immediate/interrupt mask, notify mask, bpf_write through the interface. tcpdump prints the same as on Roadshow. BIOCPROMISC is accepted with no effect |
| IP filter | ipf_* (7 calls) | done, as Roadshow's IP Filter 3.4.21 kernel side: the rule engine on every IPv4 datagram in and out (lo0 too), groups, accounting, skip/quick, keep state (TCP/UDP flows, ICMP queries and errors; no TCP window check), keep frags, statistics; the log device (records byte for byte as Roadshow's but for the times); return-rst and return-icmp; blocked sends fail at once with EHOSTUNREACH, as Roadshow's; NAT (rdr, map with portmap ranges and auto, map-block, bimap, round-robin rdr, NAT logging, NAT on lo0); auth and preauth rules; to / dup-to / fastroute. Roadshow's own ipf, ipfstat, ipmon and ipnat show the same rules, sessions and counters on both stacks. Differs: a minor is never left refused after a program read its log (Roadshow's stays busy until the next boot); a program already waiting in SIOCAUTHW is woken when a datagram is held (Roadshow's sleeps until a break); ipf -D empties the auth queue. Not yet: the FTP proxy's address rewriting and its state block, headers quoted in ICMP errors |

### SocketBaseTagList

Every code in bsdsocket.h is handled, by value and by reference.

- Per opener: BREAKMASK, SIGIOMASK, SIGURGMASK, SIGEVENTMASK, ERRNO,
  HERRNO, the ERRNO*PTR tags, HERRNOLONGPTR, DTABLESIZE (256 by default as
  Roadshow, up to 4096, never below the descriptors in use), LOGSTAT,
  LOGTAGPTR, LOGFACILITY, LOGMASK, ERROR_HOOK (called on every errno and
  h_errno change), IDN_DEFAULT_CHARACTER_SET, CAN_SHARE_LIBRARY_BASES.
- Answers: ERRNOSTRPTR, HERRNOSTRPTR, IOERRNOSTRPTR, S2ERRNOSTRPTR,
  S2WERRNOSTRPTR (every string as Roadshow's), RELEASESTRPTR,
  SYSTEM_STATUS (from the interfaces' addresses, routers and DNS servers),
  GET_BYTES_RECEIVED / GET_BYTES_SENT (SBQUAD_T, Ethernet bytes),
  NUM_PACKET_FILTER_CHANNELS (8).
- Stack-wide: IP_DEFAULT_TTL (new sockets), ICMP_SEND_REDIRECTS,
  ICMP_PROCESS_TSTAMP (IR_Process by default as Roadshow: time stamp
  requests are answered; IR_Ignore and IR_Drop leave them unanswered). The
  settings the stack cannot honour keep the value that says what it does
  and refuse others: UDP_CHECKSUM 1, ICMP_MASK_REPLY 0, ICMP_PROCESS_ECHO
  IR_Process.
- Shared: LOG_FILE_NAME (kept; messages do not go to a file yet),
  LOG_HOOK.
- Kept, not acted on: SIG_ADDRESS_CHANGE_MASK, FDCALLBACK (deprecated).
- HAVE_*: TRUE for every API: INTERFACE, STATUS, LOCAL_DATABASE,
  ADDRESS_CONVERSION, GETHOSTADDR_R, ROUTING, DNS, ROADSHOWDATA,
  MONITORING, SERVER, KERNEL_MEMORY.

## Settings

The stack-wide options are Roadshow's, read and changed with
RoadshowControl, ChangeRoadshowData or ENV:Roadshow/<area>/<name>, with
additions of rustsocket's own:

| Option | Default | Meaning |
|---|---|---|
| tcp.recvspace | 64 KB | a TCP connection's receive buffer to start with |
| tcp.recvspace.max | 1 MB | the size the receive buffer may grow to. Once per round trip the stack measures how fast the program reads and sizes the buffer to twice the data in flight; it shrinks back when the transfer slows down or the connection goes idle. On a LAN (round trip under 2 ms) it stops at 512 KB, which kept the data in the cache and was faster on an AmigaOne X5000 |
| tcp.sendspace | 64 KB | a TCP connection's send buffer to start with (Roadshow: 32 KB) |
| tcp.sendspace.max | 64 KB | the size the send buffer may grow to, in the same way, on paths with a round trip of 2 ms or more. The default (equal to tcp.sendspace) means no growth: internet uploads measured from an X5000 were no faster with a larger ceiling |
| if.moderation.rx, if.moderation.tx | -1 | interrupt moderation, in microseconds between interrupts (0: off), for receive and send, on every interface whose driver can set it (SANA-II extensions, below); -1 leaves the driver's own. A driver that cannot set send apart uses the receive value for both |
| if.flowcontrol | -1 | Ethernet flow control (pause frames) on those interfaces: 1 receive, 2 send, 4 negotiated, added together; 0 off; -1 leaves the driver's own |

## SANA-II extensions

rustsocket uses the unofficial SANA-II extensions (sana2ext, version 1:
docs/devices/sana2ext.md of the amigaos4 crate) when a driver offers them,
and plain SANA-II otherwise:

- frames read and written several per request (S2X_READBATCH,
  S2X_WRITEBATCH);
- receive checksums checked by the card are not checked again, and frames
  the card found bad are dropped (counted as input errors). While the IP
  filter runs or a filter hook is installed every frame is checked, since
  those may change it;
- the IPv4 header and TCP checksums of frames sent are computed by the
  card. Monitoring hooks, bpf (tcpdump) and the filter hook see those
  frames before the card has filled the fields in;
- MTU: an MTU larger than the driver's (the MTU option of
  DEVS:NetInterfaces, ConfigureNetInterface MTU) changes the driver's MTU,
  within what it allows (jumbo frames). Roadshow, like rustsocket with
  any other driver, only lowers it;
- interrupt moderation and flow control from the if.* options above.

## Roadshow's tools on rustsocket

| Tool | Result |
|---|---|
| GetNetStatus, CheckRoadshowConfig, ManageNetInterfaces | work |
| AddNetInterface | works from Roadshow's own S:Network-Startup: the interface is added, DHCP runs through the allocation message, the default route and name servers are added |
| ConfigureNetInterface | works: MTU (the stack's MTU from then on, used for new connections; at most the driver's, or larger with the SANA-II extensions), METRIC, BROADCASTADDR, ALIASADDR/DELETEADDR (aliases survive DHCP renewals), DEBUG, RELEASE. Not yet: point-to-point (DESTINATION), ONLINE/OFFLINE |
| RemoveNetInterface | works: removes an interface that no connection uses; FORCE always. Differs: Roadshow refuses ("Device busy") every non-forced removal once the interface was configured; rustsocket follows the autodoc (refuse only while in use) |
| AddNetRoute, DeleteNetRoute | work (the blank addresses in their messages are the tools' own, also on Roadshow) |
| ShowNetStatus | works: summary, INTERFACES, ROUTES and DNS print as on Roadshow but for the traffic counters and I/O request figures (rustsocket keeps 36 reads and 1 write per interface, or with the SANA-II extensions the frames of its read batches and of one write batch) |
| RoadshowControl | works: lists, GET and SET |
| ping, traceroute | work as on Roadshow |
| arp | works: -a, a host, -s and -d (on Roadshow 1.15 itself arp -s and -d hang on QEMU) |
| NetShutdown | works: the network goes down under running programs as on Roadshow. The stack keeps running after the last CloseLibrary while it has interfaces (as Roadshow); it stops at the expunge or the last close once NetShutdown has taken them away |
| tcpdump | works; headers differ from Roadshow's only in IP ID and DF (see Raw sockets) |
| ipf, ipfstat, ipmon, ipnat | work as on Roadshow (see IP filter). Not yet: the FTP proxy's address rewriting and its state block in ipnat -l |
| Online, Offline | run the same on both stacks: the unit goes offline and back, and both tools report a timeout. That is the tools' own defect: they wait on the wrong message port for the driver's event |
| NetLogViewer, SampleNetSpeed | work |
| rsh, ftp | work as on Roadshow (ftp tested in passive mode) |
| SYS:Prefs/Internet | opens and lists the same as on Roadshow |

## Configuration and start-up

| Item | State |
|---|---|
| S:Network-Startup (`AddNetInterface QUIET DEVS:NetInterfaces/~(#?.info)`) | done: the library starts with lo0 only and Roadshow's start-up configures it, as it configures Roadshow |
| DEVS:NetInterfaces/* | done for device, unit, configure=dhcp, address, netmask and the options AddNetInterface passes: HARDWAREADDRESS, MTU (the stack's MTU, at most the driver's unless the driver has the SANA-II extensions' MTU setting), DOWNGOESOFFLINE (S2_OFFLINE when taken down, S2_ONLINE when brought up). ShowNetStatus INTERFACE shows the address binding (Dynamic with the lease's end, Static) and link status as on Roadshow. Taken and not acted on: the request counts, COPYMODE, FILTER, REQUIRESINITDELAY, MULTICAST, REPORTOFFLINE; IPTYPE/ARPTYPE other than IP and ARP and POINTTOPOINT=YES are refused. Differs: Roadshow prints the lease end eight years late, and after DOWNGOESOFFLINE's down and up its interface passes no traffic; rustsocket's does |
| DEVS:Internet/routes | done: read at the first IFC_Complete |
| DEVS:Internet/name_resolution | done: read at start and again within a second of a change; the last `domain` or `search` line is the search list (a `domain` searches only itself, as Roadshow), used as BSD's res_search with ndots 1; `nameserver` lines are asked after the listed servers and are listed nowhere, as on Roadshow. Not yet: `sortlist`, and the domain taken from the host name when the file has neither keyword |
| DEVS:Internet/hosts, services, protocols, networks | done |
| DEVS:Internet/servers (superserver) | done: changes are taken up within a second; internal echo, discard, chargen, daytime and time on TCP and UDP in Roadshow's formats; programs from C: or PATH as CLI processes; DOS servers (Input() and Output() on the connection); WAIT, PRI, STACK, MAXHITS (1500 a minute by default), INACTIVE, PATH |
| TCP: (tcp-handler.doc) | done: mounted when the library starts unless a TCP: is already there; TCP:host/port, HOST=/PORT=/SERVICE=, TCP:port (one incoming connection), TCP:OBTAIN=n; READ, WRITE, WAIT_CHAR, STACK, END, IS_FILESYSTEM; failed opens give IoErr 205, as Roadshow. The handler keeps open files working past the last CloseLibrary until their END |
| ENV:Roadshow/<area>/<name> | done: read when the stack starts, for every option |

## Beyond bsdsocket.library

- usergroup.library: Roadshow's own works unchanged over rustsocket (ids,
  users and groups, crypt, getlogin).
- 68k programs: done. The library has its own 68k jump table (generated
  from the SDK's bsdsocket_pragmas.h: 121 calls), so 68k programs such as
  IBrowse 2 run on it. (LIBS:bsdsocket.l.main is not a 68k bridge: it is a
  PPC interface onto a 68k bsdsocket.library.)
- The "TCP/IP Control" port that NetShutdown uses: done.
