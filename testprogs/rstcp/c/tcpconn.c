/* tcpconn: one blocking TCP connect to ADDR:PORT; prints what connect
   answers, errno and how long it took (the IP filter's blocked-SYN test:
   run it with an "out" rule that blocks the SYN, then with the filter
   off, on each stack).

     tcpconn ADDR PORT

   Build (from the repository root):
     docker run --rm -v "$PWD":/w -w /w walkero/amigagccondocker:os4-gcc11 \
       ppc-amigaos-gcc -O2 -Wall -o testprogs/rstcp/c/tcpconn testprogs/rstcp/c/tcpconn.c */

#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/bsdsocket.h>
#include <proto/timer.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct Library *SocketBase;
struct SocketIFace *ISocket;
struct TimerIFace *ITimer;

static unsigned long ms_since(const struct TimeVal *t0)
{
	struct TimeVal t;

	ITimer->GetUpTime(&t);
	return (t.Seconds - t0->Seconds) * 1000 + ((long)t.Microseconds - (long)t0->Microseconds) / 1000;
}

int main(int argc, char **argv)
{
	struct sockaddr_in to;
	struct TimeVal t0;
	struct TimeRequest tr;
	LONG s, r, e;

	if (argc < 3) {
		printf("usage: tcpconn ADDR PORT\n");
		return 10;
	}
	memset(&tr, 0, sizeof(tr));
	if (IExec->OpenDevice("timer.device", UNIT_MICROHZ, (struct IORequest *)&tr, 0) != 0)
		return 20;
	ITimer = (struct TimerIFace *)IExec->GetInterface((struct Library *)tr.Request.io_Device, "main", 1, NULL);
	SocketBase = IExec->OpenLibrary("bsdsocket.library", 4);
	if (SocketBase == NULL || ITimer == NULL)
		return 20;
	ISocket = (struct SocketIFace *)IExec->GetInterface(SocketBase, "main", 1, NULL);
	if (ISocket == NULL)
		return 20;
	s = ISocket->socket(AF_INET, SOCK_STREAM, 0);
	memset(&to, 0, sizeof(to));
	to.sin_len = sizeof(to);
	to.sin_family = AF_INET;
	to.sin_port = htons(atoi(argv[2]));
	to.sin_addr.s_addr = ISocket->inet_addr(argv[1]);
	ITimer->GetUpTime(&t0);
	r = ISocket->connect(s, (struct sockaddr *)&to, sizeof(to));
	e = r < 0 ? ISocket->Errno() : 0;
	{
		unsigned long ms = ms_since(&t0);

		printf("tcpconn %s:%s: connect = %ld errno %ld after %s (%lu ms)\n", argv[1], argv[2], (long)r, (long)e,
			ms < 1000 ? "under 1 s" : "1 s or more", ms);
	}
	ISocket->CloseSocket(s);
	IExec->DropInterface((struct Interface *)ISocket);
	IExec->CloseLibrary(SocketBase);
	IExec->DropInterface((struct Interface *)ITimer);
	IExec->CloseDevice((struct IORequest *)&tr);
	return 0;
}
