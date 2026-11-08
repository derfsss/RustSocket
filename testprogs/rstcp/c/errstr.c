/* errstr: the library's errno and h_errno strings (SBTC_ERRNOSTRPTR,
   SBTC_HERRNOSTRPTR), one line each, to diff between the stacks.

   Build (from the repository root):
     docker run --rm -v "$PWD":/w -w /w walkero/amigagccondocker:os4-gcc11 \
       ppc-amigaos-gcc -O2 -Wall -o testprogs/rstcp/c/errstr testprogs/rstcp/c/errstr.c */

#include <proto/exec.h>
#include <proto/bsdsocket.h>
#include <libraries/bsdsocket.h>
#include <stdio.h>

struct Library *SocketBase;
struct SocketIFace *ISocket;

static void dump(ULONG code, const char *what, int first, int last)
{
	int e;
	for (e = first; e <= last; e++) {
		struct TagItem t[] = { { SBTM_GETVAL(code), (ULONG)e }, { TAG_END, 0 } };
		/* SBTM_GETVAL with the number in ti_Data: the string pointer comes
		   back in ti_Data (GETREF would write through the number). */
		LONG r = ISocket->SocketBaseTagList(t);
		printf("%s %2d: %s\n", what, e, r == 0 && t[0].ti_Data ? (char *)t[0].ti_Data : "(none)");
	}
}

int main(void)
{
	SocketBase = IExec->OpenLibrary("bsdsocket.library", 4);
	if (SocketBase == NULL)
		return 20;
	ISocket = (struct SocketIFace *)IExec->GetInterface(SocketBase, "main", 1, NULL);
	if (ISocket == NULL) {
		IExec->CloseLibrary(SocketBase);
		return 20;
	}
	dump(SBTC_ERRNOSTRPTR, "errno", 0, 90);
	dump(SBTC_HERRNOSTRPTR, "h_errno", -1, 5);
	dump(SBTC_IOERRNOSTRPTR, "ioerr", -8, 10);
	dump(SBTC_S2ERRNOSTRPTR, "s2err", 0, 20);
	dump(SBTC_S2WERRNOSTRPTR, "s2werr", 0, 25);
	IExec->DropInterface((struct Interface *)ISocket);
	IExec->CloseLibrary(SocketBase);
	return 0;
}
