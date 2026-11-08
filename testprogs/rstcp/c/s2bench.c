/* s2bench: what a SANA-II driver can deliver with no TCP/IP stack on top:
   the ceiling that the driver (p50x0_eth.device, for example) and
   SANA-II's buffer management set for any stack. Raw reads and writes with 68k
   EmuTrap copy functions, as Roadshow and rustsocket pass them.

     s2bench DEVICE UNIT rx MYIP SECONDS [reads=N] [nocopy]
       Answers ARP for MYIP (an address no stack uses), keeps N raw IPv4
       reads posted (default 32) and counts the frames for SECONDS.
       nocopy: the copy function copies nothing (its call cost alone).
     s2bench DEVICE UNIT tx MYIP SECONDS DSTMAC DSTIP [writes=N] [size=N]
       Sends raw UDP/IPv4 frames of SIZE bytes (default 1514) from MYIP to
       DSTIP:9 as fast as the driver takes them, N writes in flight
       (default 16), for SECONDS.

   Prints frames, bytes and rates. Run netprof watch alongside for the CPU.

   Build (from the repository root):
     docker run --rm -v "$PWD":/w -w /w walkero/amigagccondocker:os4-gcc11 \
       ppc-amigaos-gcc -O2 -Wall -o testprogs/rstcp/c/s2bench testprogs/rstcp/c/s2bench.c */

#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/timer.h>
#include <devices/sana2.h>
#include <exec/emulation.h>
#include <exec/lists.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXREQ 256
#define FRAME 1600

struct TimerIFace *ITimer;

struct Buf {
	ULONG len;
	UBYTE data[FRAME];
};

static BOOL nocopy;
static volatile ULONG copies_to, copies_from;

static uint32 trap_to(uint32 *regs)
{
	struct Buf *b = (struct Buf *)regs[REG68K_A0 / 4];
	ULONG n = regs[REG68K_D0 / 4];

	copies_to++;
	if (n > FRAME)
		return FALSE;
	if (!nocopy)
		memcpy(b->data, (APTR)regs[REG68K_A1 / 4], n);
	b->len = n;
	return TRUE;
}

static uint32 trap_from(uint32 *regs)
{
	struct Buf *b = (struct Buf *)regs[REG68K_A1 / 4];
	ULONG n = regs[REG68K_D0 / 4];

	copies_from++;
	if (n > FRAME)
		return FALSE;
	memcpy((APTR)regs[REG68K_A0 / 4], b->data, n);
	return TRUE;
}

static struct EmuTrap trap_to_stub = { TRAPINST, TRAPTYPE, trap_to };
static struct EmuTrap trap_from_stub = { TRAPINST, TRAPTYPE, trap_from };

static uint64 now_us(void)
{
	struct TimeVal t;

	ITimer->GetUpTime(&t);
	return (uint64)t.Seconds * 1000000ULL + t.Microseconds;
}

static void ip4(const char *s, UBYTE *o)
{
	unsigned a, b, c, d;

	if (sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
		o[0] = a; o[1] = b; o[2] = c; o[3] = d;
	}
}

static void mac6(const char *s, UBYTE *o)
{
	unsigned m[6];
	int k;

	if (sscanf(s, "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6 ||
	    sscanf(s, "%x-%x-%x-%x-%x-%x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6)
		for (k = 0; k < 6; k++)
			o[k] = m[k];
}

static ULONG opt(int argc, char **argv, const char *name, ULONG def)
{
	int k;
	size_t n = strlen(name);

	for (k = 1; k < argc; k++)
		if (strncmp(argv[k], name, n) == 0 && argv[k][n] == '=')
			return strtoul(argv[k] + n + 1, NULL, 10);
	return def;
}

/* The idle meter (as netprof's): a task at priority -127 counts loops;
   the share of its quiet rate it loses while the test runs is the CPU
   the test used. */
static volatile uint64 idle_count;
static volatile BOOL idle_stop;

static void idle_task(void)
{
	while (!idle_stop)
		idle_count++;
}

static UWORD csum(const UBYTE *p, int n)
{
	ULONG s = 0;
	int k;

	for (k = 0; k + 1 < n; k += 2)
		s += (p[k] << 8) | p[k + 1];
	while (s >> 16)
		s = (s & 0xffff) + (s >> 16);
	return (UWORD)~s;
}

int main(int argc, char **argv)
{
	struct TagItem tags[] = {
		{ S2_CopyToBuff, (ULONG)&trap_to_stub },
		{ S2_CopyFromBuff, (ULONG)&trap_from_stub },
		{ TAG_DONE, 0 }
	};
	struct TimeRequest tr, *tick;
	struct Task *idle_task_ptr = NULL;
	double quiet_rate = 0, busy = -1;
	uint64 idle0 = 0;
	struct MsgPort *tport;
	struct MsgPort *port;
	struct IOSana2Req *base, *req[MAXREQ], *arpr[4];
	struct Buf *buf[MAXREQ], *arpb[4], *arpout;
	struct IOSana2Req *arpw;
	UBYTE mac[6], myip[4] = { 0 }, dstip[4] = { 0 }, dstmac[6] = { 0 };
	BOOL tx;
	ULONG secs, nreq, size, k;
	uint64 t0, t1, frames = 0, bytes = 0, arps = 0, errs = 0;
	int e;

	if (argc < 6) {
		printf("s2bench DEVICE UNIT rx|tx MYIP SECONDS [DSTMAC DSTIP] [reads=N|writes=N] [size=N] [nocopy]\n");
		return 5;
	}
	tx = strcmp(argv[3], "tx") == 0;
	ip4(argv[4], myip);
	secs = strtoul(argv[5], NULL, 10);
	for (k = 6; k < (ULONG)argc; k++)
		nocopy |= strcmp(argv[k], "nocopy") == 0;
	if (tx) {
		if (argc < 8)
			return 5;
		mac6(argv[6], dstmac);
		ip4(argv[7], dstip);
	}
	nreq = opt(argc, argv, tx ? "writes" : "reads", tx ? 16 : 32);
	if (nreq < 1 || nreq > MAXREQ)
		nreq = 32;
	size = opt(argc, argv, "size", 1514);
	if (size < 60 || size > 1514)
		size = 1514;

	memset(&tr, 0, sizeof(tr));
	if (IExec->OpenDevice("timer.device", UNIT_MICROHZ, (struct IORequest *)&tr, 0) != 0)
		return 20;
	ITimer = (struct TimerIFace *)IExec->GetInterface((struct Library *)tr.Request.io_Device, "main", 1, NULL);
	port = IExec->AllocSysObjectTags(ASOT_PORT, TAG_END);
	base = IExec->AllocSysObjectTags(ASOT_IOREQUEST, ASOIOR_Size, sizeof(struct IOSana2Req), ASOIOR_ReplyPort, port, TAG_END);
	if (ITimer == NULL || port == NULL || base == NULL)
		return 20;
	base->ios2_BufferManagement = tags;
	e = IExec->OpenDevice(argv[1], strtoul(argv[2], NULL, 10), (struct IORequest *)base, 0);
	if (e != 0) {
		printf("OpenDevice %s: %d\n", argv[1], e);
		return 10;
	}
	base->ios2_Req.io_Command = S2_GETSTATIONADDRESS;
	IExec->DoIO((struct IORequest *)base);
	memcpy(mac, base->ios2_SrcAddr, 6);
	/* Configure the unit (a stack does this first; with no stack loaded
	   the driver took no frames and failed every write until it was):
	   "already configured" is fine. Then online. */
	memcpy(base->ios2_SrcAddr, mac, 6);
	base->ios2_Req.io_Command = S2_CONFIGINTERFACE;
	IExec->DoIO((struct IORequest *)base);
	printf("S2_CONFIGINTERFACE: error %d wire %lu\n", base->ios2_Req.io_Error, (unsigned long)base->ios2_WireError);
	base->ios2_Req.io_Command = S2_ONLINE;
	IExec->DoIO((struct IORequest *)base);

	/* ARP: answer requests for MYIP, so the PC can send to it. */
	arpout = IExec->AllocVecTags(sizeof(struct Buf), AVT_Type, MEMF_SHARED, AVT_ClearWithValue, 0, TAG_END);
	arpw = IExec->AllocSysObjectTags(ASOT_IOREQUEST, ASOIOR_Duplicate, base, TAG_END);
	for (k = 0; k < 4; k++) {
		arpb[k] = IExec->AllocVecTags(sizeof(struct Buf), AVT_Type, MEMF_SHARED, TAG_END);
		arpr[k] = IExec->AllocSysObjectTags(ASOT_IOREQUEST, ASOIOR_Duplicate, base, TAG_END);
		arpr[k]->ios2_Req.io_Command = CMD_READ;
		arpr[k]->ios2_Req.io_Flags = SANA2IOF_RAW;
		arpr[k]->ios2_PacketType = 0x0806;
		arpr[k]->ios2_Data = arpb[k];
		IExec->BeginIO((struct IORequest *)arpr[k]);
	}

	for (k = 0; k < nreq; k++) {
		buf[k] = IExec->AllocVecTags(sizeof(struct Buf), AVT_Type, MEMF_SHARED, AVT_ClearWithValue, 0, TAG_END);
		req[k] = IExec->AllocSysObjectTags(ASOT_IOREQUEST, ASOIOR_Duplicate, base, TAG_END);
		req[k]->ios2_Data = buf[k];
		if (tx) {
			/* One raw UDP frame, the same for every write. */
			UBYTE *f = buf[k]->data, *ip = f + 14, *udp = ip + 20;
			ULONG iplen = size - 14;

			memcpy(f, dstmac, 6);
			memcpy(f + 6, mac, 6);
			f[12] = 0x08; f[13] = 0x00;
			ip[0] = 0x45; ip[2] = iplen >> 8; ip[3] = iplen; ip[6] = 0x40; ip[8] = 64; ip[9] = 17;
			memcpy(ip + 12, myip, 4);
			memcpy(ip + 16, dstip, 4);
			ip[10] = 0; ip[11] = 0;
			{
				UWORD c = csum(ip, 20);
				ip[10] = c >> 8; ip[11] = c;
			}
			udp[0] = 0x30; udp[1] = 0x39; udp[2] = 0; udp[3] = 9;
			udp[4] = (iplen - 20) >> 8; udp[5] = iplen - 20;
			buf[k]->len = size;
			req[k]->ios2_Req.io_Command = CMD_WRITE;
			req[k]->ios2_Req.io_Flags = SANA2IOF_RAW;
			req[k]->ios2_PacketType = 0x0800;
			req[k]->ios2_DataLength = size;
			memcpy(req[k]->ios2_DstAddr, dstmac, 6);
		} else {
			req[k]->ios2_Req.io_Command = CMD_READ;
			req[k]->ios2_Req.io_Flags = SANA2IOF_RAW;
			req[k]->ios2_PacketType = 0x0800;
		}
	}
	printf("s2bench %s: %s unit %s, %s %lu, %s, %lu s\n", tx ? "tx" : "rx", argv[1], argv[2],
		tx ? "writes" : "reads", (unsigned long)nreq, nocopy ? "no copy" : "copy", (unsigned long)secs);
	fflush(stdout);

	/* A tick every 100 ms bounds every wait: with no traffic the loop
	   still ends (the first version waited in WaitPort for ever). */
	tport = IExec->AllocSysObjectTags(ASOT_PORT, TAG_END);
	tick = IExec->AllocSysObjectTags(ASOT_IOREQUEST, ASOIOR_Size, sizeof(struct TimeRequest), ASOIOR_ReplyPort, tport, TAG_END);
	if (tick != NULL) {
		tick->Request.io_Device = tr.Request.io_Device;
		tick->Request.io_Unit = tr.Request.io_Unit;
	}
	if (tport == NULL || tick == NULL)
		return 20;
	tick->Request.io_Command = TR_ADDREQUEST;
	tick->Time.Seconds = 0;
	tick->Time.Microseconds = 100000;
	IExec->SendIO((struct IORequest *)tick);

	/* Calibrate the idle meter for 1 s before the test starts. */
	idle_task_ptr = IExec->CreateTaskTags("s2bench idle", -127, (APTR)idle_task, 8192, TAG_END);
	if (idle_task_ptr != NULL) {
		uint64 c0, q0;

		IDOS->Delay(10);
		c0 = idle_count;
		q0 = now_us();
		IDOS->Delay(50);
		quiet_rate = (idle_count - c0) / ((now_us() - q0) / 1e6);
	}

	for (k = 0; k < nreq; k++)
		IExec->BeginIO((struct IORequest *)req[k]);
	idle0 = idle_count;
	t0 = now_us();
	t1 = t0 + (uint64)secs * 1000000ULL;
	while (now_us() < t1) {
		struct Message *m;
		/* Wait only with nothing queued: a pass that stopped at its limit
		   left replies behind, and their signal is already taken. */
		ULONG got = IsListEmpty(&port->mp_MsgList)
			? IExec->Wait((1UL << port->mp_SigBit) | (1UL << tport->mp_SigBit) | SIGBREAKF_CTRL_C)
			: IExec->SetSignal(0, SIGBREAKF_CTRL_C);

		if (got & SIGBREAKF_CTRL_C)
			break;
		if (IExec->CheckIO((struct IORequest *)tick)) {
			IExec->WaitIO((struct IORequest *)tick);
			tick->Request.io_Command = TR_ADDREQUEST;
			tick->Time.Seconds = 0;
			tick->Time.Microseconds = 100000;
			IExec->SendIO((struct IORequest *)tick);
		}
		/* At most 256 replies per pass: completed writes come back as fast
		   as they are re-issued, and a drain loop with no limit never saw
		   the clock again (it blasted the link until a power cycle). */
		ULONG drained = 0;
		while (drained++ < 256 && (m = IExec->GetMsg(port)) != NULL) {
			struct IOSana2Req *r = (struct IOSana2Req *)m;

			if (r->ios2_PacketType == 0x0806 && r->ios2_Req.io_Command == CMD_READ) {
				struct Buf *b = (struct Buf *)r->ios2_Data;
				UBYTE *a = b->data + 14;

				/* An ARP request (op 1) for MYIP: answer it. */
				if (r->ios2_Req.io_Error == 0 && a[7] == 1 && memcmp(a + 24, myip, 4) == 0) {
					UBYTE *o = arpout->data;

					memcpy(o, a + 8, 6);
					memcpy(o + 6, mac, 6);
					o[12] = 0x08; o[13] = 0x06;
					memcpy(o + 14, a, 8);
					o[21] = 2;
					memcpy(o + 22, mac, 6);
					memcpy(o + 28, myip, 4);
					memcpy(o + 32, a + 8, 10);
					/* Padded to the 60-byte Ethernet minimum: a 42-byte frame got no
					   answer (the driver may not pad). */
					memset(o + 42, 0, 18);
					arpout->len = 60;
					arpw->ios2_Req.io_Command = CMD_WRITE;
					arpw->ios2_Req.io_Flags = SANA2IOF_RAW;
					arpw->ios2_PacketType = 0x0806;
					arpw->ios2_DataLength = 60;
					arpw->ios2_Data = arpout;
					memcpy(arpw->ios2_DstAddr, a + 8, 6);
					/* BeginIO: DoIO would clear io_Flags and SANA2IOF_RAW with it. */
					IExec->BeginIO((struct IORequest *)arpw);
					IExec->WaitIO((struct IORequest *)arpw);
					arps++;
				}
				r->ios2_Req.io_Flags = SANA2IOF_RAW;
				IExec->BeginIO((struct IORequest *)r);
				continue;
			}
			if (r->ios2_Req.io_Error == 0) {
				frames++;
				bytes += tx ? size : r->ios2_DataLength;
			} else {
				errs++;
			}
			if (!tx) {
				r->ios2_Req.io_Command = CMD_READ;
				r->ios2_PacketType = 0x0800;
			}
			r->ios2_Req.io_Flags = SANA2IOF_RAW;
			if (tx)
				r->ios2_DataLength = size;
			IExec->BeginIO((struct IORequest *)r);
		}
	}
	t1 = now_us() - t0;
	if (idle_task_ptr != NULL && quiet_rate > 0) {
		busy = 100.0 * (1.0 - (idle_count - idle0) / (t1 / 1e6) / quiet_rate);
		/* The idle task ends itself; wait until it has gone. */
		idle_stop = TRUE;
		while (IExec->FindTask("s2bench idle") != NULL)
			IDOS->Delay(1);
	}
	IExec->AbortIO((struct IORequest *)tick);
	IExec->WaitIO((struct IORequest *)tick);
	for (k = 0; k < nreq; k++) {
		IExec->AbortIO((struct IORequest *)req[k]);
		IExec->WaitIO((struct IORequest *)req[k]);
	}
	for (k = 0; k < 4; k++) {
		IExec->AbortIO((struct IORequest *)arpr[k]);
		IExec->WaitIO((struct IORequest *)arpr[k]);
	}
	printf("%llu frames, %llu bytes in %.2f s: %.0f frames/s, %.2f MB/s; %llu errors, %llu ARP answers, copies to %lu from %lu\n",
		frames, bytes, t1 / 1e6, frames / (t1 / 1e6), bytes / (double)t1, errs, arps,
		(unsigned long)copies_to, (unsigned long)copies_from);
	if (busy >= 0 && frames > 0)
		printf("CPU busy %.1f%%: %.2f us of CPU per frame\n", busy, busy / 100.0 * t1 / (double)frames);
	IExec->CloseDevice((struct IORequest *)base);
	return 0;
}
