/* revprobe: what a stack's reverse name lookups answer (gethostbyaddr and
   getnameinfo), so two stacks can be compared line by line.

     revprobe [ADDR ...]     (default 8.8.8.8 1.1.1.1 10.0.3.2 10.0.3.3
                              127.0.0.1 192.0.2.1)

   Build (from the repository root):
     docker run --rm -v "$PWD":/w -w /w walkero/amigagccondocker:os4-gcc11 \
       ppc-amigaos-gcc -O2 -Wall -o testprogs/rstcp/c/revprobe testprogs/rstcp/c/revprobe.c */

#include <proto/exec.h>
#include <proto/bsdsocket.h>
#include <proto/timer.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
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

static void one(const char *ip)
{
	struct sockaddr_in a;
	struct hostent *h;
	struct TimeVal t0;
	char host[256], serv[32];
	ULONG in;
	LONG herr = 0, r;
	int k;

	in = ISocket->inet_addr((STRPTR)ip);
	ITimer->GetUpTime(&t0);
	h = ISocket->gethostbyaddr((STRPTR)&in, 4, AF_INET);
	ISocket->SocketBaseTags(SBTM_GETREF(SBTC_HERRNO), &herr, TAG_END);
	printf("gethostbyaddr(%s): %s, h_errno %ld, %s\n", ip, h ? "found" : "NULL", (long)herr,
		ms_since(&t0) < 1000 ? "under 1 s" : "1 s or more");
	if (h != NULL) {
		printf("  h_name '%s' h_addrtype %ld h_length %ld\n", h->h_name, (long)h->h_addrtype, (long)h->h_length);
		for (k = 0; h->h_aliases && h->h_aliases[k]; k++)
			printf("  alias '%s'\n", h->h_aliases[k]);
		for (k = 0; h->h_addr_list && h->h_addr_list[k]; k++)
			printf("  addr %s\n", ISocket->Inet_NtoA(*(ULONG *)h->h_addr_list[k]));
	}
	memset(&a, 0, sizeof(a));
	a.sin_len = sizeof(a);
	a.sin_family = AF_INET;
	a.sin_port = htons(80);
	a.sin_addr.s_addr = in;
	r = ISocket->getnameinfo((struct sockaddr *)&a, sizeof(a), host, sizeof(host), serv, sizeof(serv), 0);
	printf("  getnameinfo: %ld host '%s' serv '%s'\n", (long)r, r == 0 ? host : "", r == 0 ? serv : "");
	r = ISocket->getnameinfo((struct sockaddr *)&a, sizeof(a), host, sizeof(host), NULL, 0, NI_NAMEREQD);
	printf("  getnameinfo NI_NAMEREQD: %ld host '%s'\n", (long)r, r == 0 ? host : "");
}

int main(int argc, char **argv)
{
	static const char *dflt[] = { "8.8.8.8", "1.1.1.1", "10.0.3.2", "10.0.3.3", "127.0.0.1", "192.0.2.1" };
	struct TimeRequest tr;
	int k;

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
	if (argc > 1)
		for (k = 1; k < argc; k++)
			one(argv[k]);
	else
		for (k = 0; k < (int)(sizeof(dflt) / sizeof(dflt[0])); k++)
			one(dflt[k]);
	IExec->DropInterface((struct Interface *)ISocket);
	IExec->CloseLibrary(SocketBase);
	IExec->DropInterface((struct Interface *)ITimer);
	IExec->CloseDevice((struct IORequest *)&tr);
	return 0;
}
