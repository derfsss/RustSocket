/* offprobe: one unit of a SANA-II driver taken offline and back online the
   way Roadshow's Offline and Online 4.4 do it, with what each step sees.

   The tools (disassembled) open the device on a command request with reply
   port A, copy it into an S2_ONEVENT request whose reply port is a second
   port B, SendIO the event request, DoIO S2_OFFLINE (or S2_ONLINE) on the
   command request, and then Wait for port A's signal, the timer's or
   Ctrl-C, looking at the event request (CheckIO) only when port A's signal
   comes. Port B is never waited on, so after the DoIO nothing signals
   them: they time out with any driver. "tools" mode does exactly that;
   "events" mode waits on port B as a correct client would.

     offprobe DEVICE UNIT [tools]

   Build (from the repository root):
     docker run --rm -v "$PWD":/w -w /w walkero/amigagccondocker:os4-gcc11 \
       ppc-amigaos-gcc -O2 -Wall -o testprogs/rstcp/c/offprobe testprogs/rstcp/c/offprobe.c */

#include <proto/exec.h>
#include <proto/dos.h>
#include <devices/sana2.h>
#include <devices/timer.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct MsgPort *porta, *portb, *tport;
static struct IOSana2Req *ev, *cmd;
static struct TimeRequest *tmr;
static int tools;

static int step(const char *name, UWORD command, ULONG event)
{
	ULONG abit = 1UL << porta->mp_SigBit, bbit = 1UL << portb->mp_SigBit;
	ULONG tbit = 1UL << tport->mp_SigBit;
	ULONG wait = tbit | (tools ? abit : bbit);
	ULONG got;
	int done = 0;

	ev->ios2_Req.io_Command = S2_ONEVENT;
	ev->ios2_WireError = event;
	IExec->SendIO((struct IORequest *)ev);
	tmr->Request.io_Command = TR_ADDREQUEST;
	tmr->Time.Seconds = 5;
	tmr->Time.Microseconds = 0;
	IExec->SendIO((struct IORequest *)tmr);
	cmd->ios2_Req.io_Command = command;
	IExec->DoIO((struct IORequest *)cmd);
	printf("offprobe: %s: io_Error %d; event back %d, port A signal %s\n", name, cmd->ios2_Req.io_Error,
		IExec->CheckIO((struct IORequest *)ev) != NULL, (IExec->SetSignal(0, 0) & abit) ? "set" : "clear");
	while (!done) {
		got = IExec->Wait(wait);
		if ((got & (tools ? abit : bbit)) && IExec->CheckIO((struct IORequest *)ev) != NULL)
			done = 1;
		else if (got & tbit)
			break;
	}
	if (!IExec->CheckIO((struct IORequest *)tmr))
		IExec->AbortIO((struct IORequest *)tmr);
	IExec->WaitIO((struct IORequest *)tmr);
	if (!done) {
		if (IExec->CheckIO((struct IORequest *)ev) == NULL)
			IExec->AbortIO((struct IORequest *)ev);
		IExec->WaitIO((struct IORequest *)ev);
		printf("offprobe: %s: timeout (event io_Error %d, events 0x%lx)\n", name,
			ev->ios2_Req.io_Error, (unsigned long)ev->ios2_WireError);
		return 0;
	}
	IExec->WaitIO((struct IORequest *)ev);
	printf("offprobe: %s: event io_Error %d, events 0x%lx\n", name,
		ev->ios2_Req.io_Error, (unsigned long)ev->ios2_WireError);
	return ev->ios2_Req.io_Error == 0 && (ev->ios2_WireError & event) != 0;
}

int main(int argc, char **argv)
{
	int ok;

	if (argc < 3) {
		printf("usage: offprobe DEVICE UNIT [tools]\n");
		return 20;
	}
	tools = argc > 3 && strcmp(argv[3], "tools") == 0;
	porta = IExec->AllocSysObjectTags(ASOT_PORT, TAG_END);
	portb = IExec->AllocSysObjectTags(ASOT_PORT, TAG_END);
	tport = IExec->AllocSysObjectTags(ASOT_PORT, TAG_END);
	cmd = IExec->AllocSysObjectTags(ASOT_IOREQUEST, ASOIOR_Size, sizeof(*cmd), ASOIOR_ReplyPort, porta, TAG_END);
	ev = IExec->AllocSysObjectTags(ASOT_IOREQUEST, ASOIOR_Size, sizeof(*ev), ASOIOR_ReplyPort, portb, TAG_END);
	tmr = IExec->AllocSysObjectTags(ASOT_IOREQUEST, ASOIOR_Size, sizeof(*tmr), ASOIOR_ReplyPort, tport, TAG_END);
	if (porta == NULL || portb == NULL || tport == NULL || ev == NULL || cmd == NULL || tmr == NULL)
		return 20;
	if (IExec->OpenDevice(TIMERNAME, UNIT_VBLANK, (struct IORequest *)tmr, 0) != 0)
		return 20;
	if (IExec->OpenDevice(argv[1], atol(argv[2]), (struct IORequest *)cmd, 0) != 0) {
		printf("offprobe: cannot open %s unit %s\n", argv[1], argv[2]);
		IExec->CloseDevice((struct IORequest *)tmr);
		return 20;
	}
	memcpy(ev, cmd, sizeof(*ev));
	ev->ios2_Req.io_Message.mn_ReplyPort = portb;
	/* A unit nobody configured is offline already: configure it first. */
	cmd->ios2_Req.io_Command = S2_GETSTATIONADDRESS;
	IExec->DoIO((struct IORequest *)cmd);
	memcpy(cmd->ios2_SrcAddr, cmd->ios2_DstAddr, SANA2_MAX_ADDR_BYTES);
	cmd->ios2_Req.io_Command = S2_CONFIGINTERFACE;
	IExec->DoIO((struct IORequest *)cmd);
	printf("offprobe: waiting on %s\n", tools ? "port A, as Offline/Online 4.4 do" : "the event's own port");
	ok = step("offline", S2_OFFLINE, S2EVENT_OFFLINE);
	ok &= step("online", S2_ONLINE, S2EVENT_ONLINE);
	IExec->CloseDevice((struct IORequest *)cmd);
	IExec->CloseDevice((struct IORequest *)tmr);
	IExec->FreeSysObject(ASOT_IOREQUEST, tmr);
	IExec->FreeSysObject(ASOT_IOREQUEST, ev);
	IExec->FreeSysObject(ASOT_IOREQUEST, cmd);
	IExec->FreeSysObject(ASOT_PORT, tport);
	IExec->FreeSysObject(ASOT_PORT, portb);
	IExec->FreeSysObject(ASOT_PORT, porta);
	return ok ? 0 : 5;
}
