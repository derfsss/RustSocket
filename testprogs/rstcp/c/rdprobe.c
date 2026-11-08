/* rdprobe: does ObtainRoadshowData(write) wait or refuse while another
   program holds the write list?  Prints before and after each call.

     rdprobe [read|write|twice|seq|rw]   (default write)

   twice: this program asks for the write list two times itself.
   seq: the RoadshowData steps of rstcp's SocketBaseTagList checks,
        printed one by one.
   rw: the read list first, then write access while holding it.

   Build (from the repository root):
     docker run --rm -v "$PWD":/w -w /w walkero/amigagccondocker:os4-gcc11 \
       ppc-amigaos-gcc -O2 -Wall -o testprogs/rstcp/c/rdprobe testprogs/rstcp/c/rdprobe.c */

#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/bsdsocket.h>
#include <stdio.h>
#include <string.h>

struct Library *SocketBase;
struct SocketIFace *ISocket;

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "write";
	struct List *a, *b = NULL;
	ULONG access = strcmp(mode, "read") == 0 || strcmp(mode, "rw") == 0 ? 0 : 1;

	SocketBase = IExec->OpenLibrary("bsdsocket.library", 4);
	if (SocketBase == NULL)
		return 20;
	ISocket = (struct SocketIFace *)IExec->GetInterface(SocketBase, "main", 1, NULL);
	if (ISocket == NULL)
		return 20;
	printf("asking for the %s list\n", access ? "write" : "read");
	fflush(stdout);
	a = ISocket->ObtainRoadshowData(access);
	printf("first: %p errno %ld\n", (void *)a, (long)ISocket->Errno());
	fflush(stdout);
	if (strcmp(mode, "seq") == 0) {
		/* rstcp's RoadshowData steps (stage7.rs), one line each. */
		struct List *rl = ISocket->ObtainRoadshowData(0);
		LONG v = 32, on = 1, back = 64, off = 0, r;
		struct List *again;

		printf("read list %p\n", (void *)rl); fflush(stdout);
		r = ISocket->ChangeRoadshowData(rl, "ip.defttl", 4, &v);
		printf("change on the read list: %ld errno %ld\n", (long)r, (long)ISocket->Errno()); fflush(stdout);
		r = ISocket->ChangeRoadshowData(a, "IP.DefTTL", 4, &v);
		printf("IP.DefTTL 32 on the write list: %ld errno %ld\n", (long)r, (long)ISocket->Errno()); fflush(stdout);
		r = ISocket->ChangeRoadshowData(a, "no.such", 4, &v);
		printf("no.such: %ld errno %ld\n", (long)r, (long)ISocket->Errno()); fflush(stdout);
		r = ISocket->ChangeRoadshowData(a, "ip.defttl", 2, &v);
		printf("2 bytes: %ld errno %ld\n", (long)r, (long)ISocket->Errno()); fflush(stdout);
		r = ISocket->ChangeRoadshowData(a, "ip.forwarding", 4, &on);
		printf("ip.forwarding 1: %ld errno %ld\n", (long)r, (long)ISocket->Errno()); fflush(stdout);
		r = ISocket->ChangeRoadshowData(a, "ip.defttl", 4, &back);
		printf("ip.defttl 64: %ld\n", (long)r); fflush(stdout);
		r = ISocket->ChangeRoadshowData(a, "ip.forwarding", 4, &off);
		printf("ip.forwarding 0: %ld\n", (long)r); fflush(stdout);
		ISocket->ReleaseRoadshowData(rl);
		printf("read list released\n"); fflush(stdout);
		ISocket->ReleaseRoadshowData(a);
		a = NULL;
		printf("write list released\n"); fflush(stdout);
		again = ISocket->ObtainRoadshowData(1);
		printf("write list again: %p\n", (void *)again); fflush(stdout);
		if (again != NULL)
			ISocket->ReleaseRoadshowData(again);
	}
	if (strcmp(mode, "rw") == 0) {
		/* a is the read list here: ask for write access while holding it. */
		b = ISocket->ObtainRoadshowData(1);
		printf("write while holding read: %p errno %ld\n", (void *)b, (long)ISocket->Errno());
		fflush(stdout);
	}
	if (strcmp(mode, "twice") == 0) {
		b = ISocket->ObtainRoadshowData(1);
		printf("second: %p errno %ld\n", (void *)b, (long)ISocket->Errno());
		fflush(stdout);
	}
	if (b != NULL)
		ISocket->ReleaseRoadshowData(b);
	if (a != NULL)
		ISocket->ReleaseRoadshowData(a);
	IExec->DropInterface((struct Interface *)ISocket);
	IExec->CloseLibrary(SocketBase);
	return 0;
}
