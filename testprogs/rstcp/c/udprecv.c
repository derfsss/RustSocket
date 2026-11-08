/* udprecv: wait up to 15 s for one UDP datagram on port 4511 (send it to
   the host port that QEMU's user network forwards to the guest's UDP
   4511) and print its size and a check of its bytes (byte o is o % 251):
   a test of reassembling a datagram that came in fragments.

   Build (from the repository root):
     docker run --rm -v "$PWD":/w -w /w walkero/amigagccondocker:os4-gcc11 \
       ppc-amigaos-gcc -O2 -Wall -o testprogs/rstcp/c/udprecv testprogs/rstcp/c/udprecv.c */

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
	static unsigned char buf[20000];
	struct sockaddr_in me;
	struct timeval tv = { 15, 0 };
	LONG n, k, wrong = 0;
	int s;

	SocketBase = IExec->OpenLibrary("bsdsocket.library", 4);
	if (SocketBase == NULL)
		return 20;
	ISocket = (struct SocketIFace *)IExec->GetInterface(SocketBase, "main", 1, NULL);
	if (ISocket == NULL) {
		IExec->CloseLibrary(SocketBase);
		return 20;
	}
	s = ISocket->socket(AF_INET, SOCK_DGRAM, 0);
	memset(&me, 0, sizeof(me));
	me.sin_len = sizeof(me);
	me.sin_family = AF_INET;
	me.sin_port = 4511;
	ISocket->bind(s, (struct sockaddr *)&me, sizeof(me));
	ISocket->setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	printf("udprecv: waiting on 4511\n");
	n = ISocket->recv(s, buf, sizeof(buf), 0);
	for (k = 0; k < n; k++)
		if (buf[k] != k % 251)
			wrong++;
	printf("udprecv: %ld bytes (errno %ld), %ld wrong\n", (long)n, (long)(n < 0 ? ISocket->Errno() : 0), (long)wrong);
	ISocket->CloseSocket(s);
	IExec->DropInterface((struct Interface *)ISocket);
	IExec->CloseLibrary(SocketBase);
	return n > 0 && wrong == 0 ? 0 : 10;
}
