/* canfwd: what In_CanForward answers for a few addresses (run it with
   ip.forwarding 0 and 1 to compare stacks).

   Build (from the repository root):
     docker run --rm -v "$PWD":/w -w /w walkero/amigagccondocker:os4-gcc11 \
       ppc-amigaos-gcc -O2 -Wall -o testprogs/rstcp/c/canfwd testprogs/rstcp/c/canfwd.c */

#include <proto/exec.h>
#include <proto/bsdsocket.h>
#include <stdio.h>

struct Library *SocketBase;
struct SocketIFace *ISocket;

int main(void)
{
	static const char *addrs[] = { "8.8.8.8", "10.0.3.2", "10.0.6.2", "127.0.0.1", "224.0.0.1", "0.0.0.1", "240.0.0.1", "255.255.255.255" };
	int k;

	SocketBase = IExec->OpenLibrary("bsdsocket.library", 4);
	if (SocketBase == NULL)
		return 20;
	ISocket = (struct SocketIFace *)IExec->GetInterface(SocketBase, "main", 1, NULL);
	if (ISocket == NULL)
		return 20;
	for (k = 0; k < (int)(sizeof(addrs) / sizeof(addrs[0])); k++)
		printf("In_CanForward(%s) = %ld\n", addrs[k], (long)ISocket->In_CanForward(ISocket->inet_addr((STRPTR)addrs[k])));
	IExec->DropInterface((struct Interface *)ISocket);
	IExec->CloseLibrary(SocketBase);
	return 0;
}
