/* udpto: send N small UDP datagrams ("udpto <seq>") to ADDR:PORT, one
   every 100 ms, and print what each sendto answers. With
   tools/udpcount.py on the PC it shows what IP filter "to" / "dup-to"
   rules do with them.

     udpto ADDR PORT [N]

   Build (from the repository root):
     docker run --rm -v "$PWD":/w -w /w walkero/amigagccondocker:os4-gcc11 \
       ppc-amigaos-gcc -O2 -Wall -o testprogs/rstcp/c/udpto testprogs/rstcp/c/udpto.c */

#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/bsdsocket.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct Library *SocketBase;
struct SocketIFace *ISocket;

int main(int argc, char **argv)
{
	struct sockaddr_in to;
	char msg[32];
	LONG s, r;
	int k, n;

	if (argc < 3) {
		printf("usage: udpto ADDR PORT [N]\n");
		return 10;
	}
	n = argc > 3 ? atoi(argv[3]) : 1;
	SocketBase = IExec->OpenLibrary("bsdsocket.library", 4);
	if (SocketBase == NULL)
		return 20;
	ISocket = (struct SocketIFace *)IExec->GetInterface(SocketBase, "main", 1, NULL);
	if (ISocket == NULL)
		return 20;
	s = ISocket->socket(AF_INET, SOCK_DGRAM, 0);
	memset(&to, 0, sizeof(to));
	to.sin_len = sizeof(to);
	to.sin_family = AF_INET;
	to.sin_port = htons(atoi(argv[2]));
	to.sin_addr.s_addr = ISocket->inet_addr(argv[1]);
	for (k = 0; k < n; k++) {
		snprintf(msg, sizeof(msg), "udpto %d", k);
		r = ISocket->sendto(s, msg, strlen(msg), 0, (struct sockaddr *)&to, sizeof(to));
		printf("udpto %s:%s #%d: sendto = %ld errno %ld\n", argv[1], argv[2], k, (long)r,
			(long)(r < 0 ? ISocket->Errno() : 0));
		IDOS->Delay(5);
	}
	ISocket->CloseSocket(s);
	IExec->DropInterface((struct Interface *)ISocket);
	IExec->CloseLibrary(SocketBase);
	return 0;
}
