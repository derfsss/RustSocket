/* s2probe: rsnet-core link.rs's SANA-II steps, one line each (flushed), to
   find the step a real driver does not answer: OpenDevice with the copy
   tags, S2_DEVICEQUERY, S2_GETSTATIONADDRESS, S2_CONFIGINTERFACE, a read
   posted per type (raw), then a raw CMD_WRITE of a broadcast ARP request
   and, if asked, the same as S2_BROADCAST and a cooked CMD_WRITE.

     s2probe DEVICE UNIT MYIP TARGETIP [cooked] [bcast] [noread] [c32|both]

   c32: S2_CopyToBuff32/S2_CopyFromBuff32 instead of the plain tags;
   both: the plain and the 32 tags together.

   Every wait is bounded (3 s): a request the driver does not reply to is
   reported and aborted.

   Build (from the repository root):
     docker run --rm -v "$PWD":/w -w /w walkero/amigagccondocker:os4-gcc11 \
       ppc-amigaos-gcc -O2 -Wall -o testprogs/rstcp/c/s2probe testprogs/rstcp/c/s2probe.c */

#include <proto/exec.h>
#include <proto/dos.h>
#include <devices/sana2.h>
#include <exec/emulation.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct MsgPort *port;
static UBYTE rxbuf[1600], txbuf[64];
static ULONG rxlen;
static volatile ULONG from_calls, to_calls, first_to, first_from, first_n;

static volatile ULONG first_a4, first_a5;

/* p50x0_eth.device calls the copy functions through IExec->EmulateTags
   (A0 to, A1 from, D0 length; seen in its disassembly). The question is
   what a PPC function then gets: r3 is read as the 68k register array
   (uint32 regs[16], D0 at 0, A0 at 8, A1 at 9) when regs[A1] is our
   cookie, else the call is taken as (to, from, n). */
static int32 copy_to(uint32 *r3, APTR from, uint32 n)
{
	to_calls++;
	if (((ULONG)r3 & 3) == 0 && r3[9] == (ULONG)rxbuf && r3[0] <= sizeof(rxbuf)) {
		memcpy(rxbuf, (APTR)r3[8], r3[0]);
		rxlen = r3[0];
		return TRUE;
	}
	if (n > sizeof(rxbuf))
		return FALSE;
	memcpy(rxbuf, from, n);
	rxlen = n;
	return TRUE;
}

static int32 copy_from(uint32 *r3, APTR from, uint32 n, uint32 a4, uint32 a5)
{
	BOOL regs = ((ULONG)r3 & 3) == 0 && r3[9] == (ULONG)txbuf;

	if (from_calls++ == 0) {
		first_to = (ULONG)r3;
		first_from = (ULONG)from;
		first_n = n;
		first_a4 = regs ? r3[0] : a4;
		first_a5 = regs ? 0x52656773 : a5;
	}
	if (regs && r3[0] <= sizeof(txbuf)) {
		memcpy((APTR)r3[8], txbuf, r3[0]);
		return TRUE;
	}
	if (from == txbuf && n <= sizeof(txbuf)) {
		memcpy(r3, txbuf, n);
		return TRUE;
	}
	return FALSE;
}

static void say(const char *s)
{
	printf("%s\n", s);
	fflush(stdout);
}

/* Wait up to 3 s for req; abort it if it does not come back. */
static BOOL waitfor(struct IOSana2Req *req, const char *what)
{
	int k;

	for (k = 0; k < 150; k++) {
		if (IExec->CheckIO((struct IORequest *)req)) {
			IExec->WaitIO((struct IORequest *)req);
			printf("%s: error %d wire %lu\n", what, req->ios2_Req.io_Error, (unsigned long)req->ios2_WireError);
			fflush(stdout);
			return TRUE;
		}
		IDOS->Delay(1);
	}
	printf("%s: NO REPLY after 3 s, aborting\n", what);
	fflush(stdout);
	IExec->AbortIO((struct IORequest *)req);
	IExec->WaitIO((struct IORequest *)req);
	return FALSE;
}

/* trap mode: 68k-callable copy functions, as Roadshow passes them (its
   wrapper reads D0, A1, A0 from the 68k register array): an EmuTrap whose
   PPC function gets uint32 Reg68K[]. */
static uint32 trap_to(uint32 *regs)
{
	to_calls++;
	if (regs[REG68K_D0 / 4] > sizeof(rxbuf))
		return FALSE;
	memcpy(rxbuf, (APTR)regs[REG68K_A1 / 4], regs[REG68K_D0 / 4]);
	rxlen = regs[REG68K_D0 / 4];
	return TRUE;
}

static uint32 trap_from(uint32 *regs)
{
	if (from_calls++ == 0) {
		first_to = regs[REG68K_A0 / 4];
		first_from = regs[REG68K_A1 / 4];
		first_n = regs[REG68K_D0 / 4];
	}
	if (regs[REG68K_D0 / 4] > sizeof(txbuf))
		return FALSE;
	memcpy((APTR)regs[REG68K_A0 / 4], txbuf, regs[REG68K_D0 / 4]);
	return TRUE;
}

static struct EmuTrap trap_to_stub = { TRAPINST, TRAPTYPE, trap_to };
static struct EmuTrap trap_from_stub = { TRAPINST, TRAPTYPE, trap_from };

static void ip4(const char *s, UBYTE *o)
{
	unsigned a, b, c, d;

	if (sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
		o[0] = a; o[1] = b; o[2] = c; o[3] = d;
	}
}

int main(int argc, char **argv)
{
	struct TagItem tags[] = {
		{ S2_CopyToBuff, (ULONG)copy_to },
		{ S2_CopyFromBuff, (ULONG)copy_from },
		{ TAG_DONE, 0 }
	};
	struct TagItem tags5[] = {
		{ S2_CopyToBuff, (ULONG)copy_to },
		{ S2_CopyFromBuff, (ULONG)copy_from },
		{ S2_CopyToBuff32, (ULONG)copy_to },
		{ S2_CopyFromBuff32, (ULONG)copy_from },
		{ TAG_DONE, 0 }
	};
	struct IOSana2Req *base, *rd = NULL, *wr;
	struct Sana2DeviceQuery q;
	UBYTE mac[6], myip[4] = { 0 }, target[4] = { 0 };
	struct TagItem trapt[] = {
		{ S2_CopyToBuff, (ULONG)&trap_to_stub },
		{ S2_CopyFromBuff, (ULONG)&trap_from_stub },
		{ TAG_DONE, 0 }
	};
	BOOL cooked = FALSE, bcast = FALSE, noread = FALSE, c32 = FALSE, both = FALSE, trap = FALSE;
	int k, e;

	if (argc < 5) {
		say("s2probe DEVICE UNIT MYIP TARGETIP [cooked] [bcast] [noread]");
		return 5;
	}
	for (k = 5; k < argc; k++) {
		cooked |= strcmp(argv[k], "cooked") == 0;
		bcast |= strcmp(argv[k], "bcast") == 0;
		noread |= strcmp(argv[k], "noread") == 0;
		c32 |= strcmp(argv[k], "c32") == 0;
		both |= strcmp(argv[k], "both") == 0;
		trap |= strcmp(argv[k], "trap") == 0;
	}
	ip4(argv[3], myip);
	ip4(argv[4], target);
	port = IExec->AllocSysObjectTags(ASOT_PORT, TAG_END);
	base = IExec->AllocSysObjectTags(ASOT_IOREQUEST, ASOIOR_Size, sizeof(struct IOSana2Req), ASOIOR_ReplyPort, port, TAG_END);
	if (port == NULL || base == NULL)
		return 20;
	if (c32) {
		tags[0].ti_Tag = S2_CopyToBuff32;
		tags[1].ti_Tag = S2_CopyFromBuff32;
	}
	base->ios2_BufferManagement = trap ? (APTR)trapt : both ? (APTR)tags5 : (APTR)tags;
	printf("copy tags: %s\n", trap ? "68k EmuTrap" : both ? "plain + 32" : c32 ? "32" : "plain");
	say("OpenDevice...");
	e = IExec->OpenDevice(argv[1], atoi(argv[2]), (struct IORequest *)base, 0);
	printf("OpenDevice: %d\n", e);
	fflush(stdout);
	if (e != 0)
		return 10;

	memset(&q, 0, sizeof(q));
	q.SizeAvailable = sizeof(q);
	base->ios2_Req.io_Command = S2_DEVICEQUERY;
	base->ios2_StatData = &q;
	IExec->SendIO((struct IORequest *)base);
	if (waitfor(base, "S2_DEVICEQUERY")) {
		printf("  hw type %lu, addr bits %lu, mtu %lu, bps %lu\n", (unsigned long)q.HardwareType,
			(unsigned long)q.AddrFieldSize, (unsigned long)q.MTU, (unsigned long)q.BPS);
		fflush(stdout);
	}

	base->ios2_Req.io_Command = S2_GETSTATIONADDRESS;
	IExec->SendIO((struct IORequest *)base);
	waitfor(base, "S2_GETSTATIONADDRESS");
	memcpy(mac, base->ios2_SrcAddr, 6);
	printf("  station %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	fflush(stdout);

	base->ios2_Req.io_Command = S2_CONFIGINTERFACE;
	IExec->SendIO((struct IORequest *)base);
	waitfor(base, "S2_CONFIGINTERFACE");

	if (!noread) {
		rd = IExec->AllocSysObjectTags(ASOT_IOREQUEST, ASOIOR_Duplicate, base, TAG_END);
		rd->ios2_Req.io_Command = CMD_READ;
		rd->ios2_Req.io_Flags = SANA2IOF_RAW;
		rd->ios2_PacketType = 0x0806;
		rd->ios2_Data = rxbuf;
		IExec->BeginIO((struct IORequest *)rd);
		say("raw ARP read posted");
	}

	/* A broadcast ARP request for TARGETIP: raw = the whole frame. */
	wr = IExec->AllocSysObjectTags(ASOT_IOREQUEST, ASOIOR_Duplicate, base, TAG_END);
	{
		UBYTE *p = txbuf;
		UBYTE *arp;

		memset(txbuf, 0, sizeof(txbuf));
		memset(p, 0xff, 6);
		memcpy(p + 6, mac, 6);
		p[12] = 0x08; p[13] = 0x06;
		arp = cooked ? txbuf : p + 14;
		if (cooked)
			memset(txbuf, 0, sizeof(txbuf));
		arp[0] = 0; arp[1] = 1; arp[2] = 8; arp[3] = 0; arp[4] = 6; arp[5] = 4; arp[6] = 0; arp[7] = 1;
		memcpy(arp + 8, mac, 6);
		memcpy(arp + 14, myip, 4);
		memcpy(arp + 24, target, 4);
	}
	wr->ios2_Req.io_Command = bcast ? S2_BROADCAST : CMD_WRITE;
	wr->ios2_Req.io_Flags = cooked ? 0 : SANA2IOF_RAW;
	wr->ios2_PacketType = 0x0806;
	wr->ios2_DataLength = cooked ? 28 : 42;
	memset(wr->ios2_DstAddr, 0xff, 6);
	wr->ios2_Data = txbuf;
	printf("%s %s ARP request...\n", cooked ? "cooked" : "raw", bcast ? "S2_BROADCAST" : "CMD_WRITE");
	fflush(stdout);
	IExec->BeginIO((struct IORequest *)wr);
	waitfor(wr, "write");

	if (rd != NULL) {
		for (k = 0; k < 150 && !IExec->CheckIO((struct IORequest *)rd); k++)
			IDOS->Delay(1);
		if (IExec->CheckIO((struct IORequest *)rd)) {
			IExec->WaitIO((struct IORequest *)rd);
			printf("read: error %d, %lu bytes, from %02x:%02x:%02x:%02x:%02x:%02x\n", rd->ios2_Req.io_Error,
				(unsigned long)rd->ios2_DataLength, rd->ios2_SrcAddr[0], rd->ios2_SrcAddr[1], rd->ios2_SrcAddr[2],
				rd->ios2_SrcAddr[3], rd->ios2_SrcAddr[4], rd->ios2_SrcAddr[5]);
		} else {
			say("read: nothing in 3 s, aborting");
			IExec->AbortIO((struct IORequest *)rd);
			IExec->WaitIO((struct IORequest *)rd);
		}
		fflush(stdout);
		IExec->FreeSysObject(ASOT_IOREQUEST, rd);
	}
	IExec->FreeSysObject(ASOT_IOREQUEST, wr);
	IExec->CloseDevice((struct IORequest *)base);
	printf("copy calls: from %lu (first args: %08lx %08lx %08lx %08lx %08lx; txbuf %08lx), to %lu\n", (unsigned long)from_calls, (unsigned long)first_to, (unsigned long)first_from, (unsigned long)first_n, (unsigned long)first_a4, (unsigned long)first_a5, (unsigned long)txbuf, (unsigned long)to_calls);
	say("closed");
	IExec->FreeSysObject(ASOT_IOREQUEST, base);
	IExec->FreeSysObject(ASOT_PORT, port);
	return 0;
}
