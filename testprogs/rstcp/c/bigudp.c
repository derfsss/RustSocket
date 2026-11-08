/* bigudp: send UDP datagrams larger than the MTU (1500) to the PC's side
   of the network (10.0.3.2, port 9) and print what sendto says; run
   tcpdump beside it to see the fragments.

   Build (from the repository root):
     docker run --rm -v "$PWD":/w -w /w walkero/amigagccondocker:os4-gcc11 \
       ppc-amigaos-gcc -O2 -Wall -o testprogs/rstcp/c/bigudp testprogs/rstcp/c/bigudp.c */

#include <proto/exec.h>
#include <proto/bsdsocket.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>

struct Library *SocketBase;
struct SocketIFace *ISocket;

int main(void)
{
	static char buf[9000];
	int sizes[] = { 1472, 1473, 3000, 8000 };
	struct sockaddr_in to;
	int s, k;

	SocketBase = IExec->OpenLibrary("bsdsocket.library", 4);
	if (SocketBase == NULL)
		return 20;
	ISocket = (struct SocketIFace *)IExec->GetInterface(SocketBase, "main", 1, NULL);
	if (ISocket == NULL) {
		IExec->CloseLibrary(SocketBase);
		return 20;
	}
	memset(buf, 'u', sizeof(buf));
	memset(&to, 0, sizeof(to));
	to.sin_len = sizeof(to);
	to.sin_family = AF_INET;
	to.sin_port = 9;
	to.sin_addr.s_addr = (10 << 24) | (0 << 16) | (3 << 8) | 2;
	s = ISocket->socket(AF_INET, SOCK_DGRAM, 0);
	for (k = 0; k < 4; k++) {
		LONG n = ISocket->sendto(s, buf, sizes[k], 0, (struct sockaddr *)&to, sizeof(to));
		printf("bigudp: sendto %d bytes = %ld (errno %ld)\n", sizes[k], (long)n, (long)(n < 0 ? ISocket->Errno() : 0));
	}
	ISocket->CloseSocket(s);
	IExec->DropInterface((struct Interface *)ISocket);
	IExec->CloseLibrary(SocketBase);
	return 0;
}
