/* logmsg: send one syslog() message through bsdsocket.library (its
   varargs form), for NetLogViewer and the serial log.

   Build (from the repository root):
     docker run --rm -v "$PWD":/w -w /w walkero/amigagccondocker:os4-gcc11 \
       ppc-amigaos-gcc -O2 -Wall -o testprogs/rstcp/c/logmsg testprogs/rstcp/c/logmsg.c
   Run: logmsg [text] */

#include <proto/exec.h>
#include <proto/bsdsocket.h>
#include <stdio.h>

struct Library *SocketBase;
struct SocketIFace *ISocket;

int main(int argc, char **argv)
{
	const char *text = argc > 1 ? argv[1] : "hello";
	SocketBase = IExec->OpenLibrary("bsdsocket.library", 4);
	if (SocketBase == NULL)
		return 20;
	ISocket = (struct SocketIFace *)IExec->GetInterface(SocketBase, "main", 1, NULL);
	if (ISocket == NULL) {
		IExec->CloseLibrary(SocketBase);
		return 20;
	}
	ISocket->syslog(3 /* LOG_ERR */, "logmsg: %s (%ld)", text, 42L);
	printf("logmsg: sent\n");
	IExec->DropInterface((struct Interface *)ISocket);
	IExec->CloseLibrary(SocketBase);
	return 0;
}
