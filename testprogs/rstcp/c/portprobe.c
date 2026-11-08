/* portprobe: which local ports a stack hands out (its ephemeral ports):
   getsockname after TCP connects, UDP sends and bind(port 0), interleaved,
   so two stacks can be compared line by line.

     portprobe [ADDR [TCPPORT]]     (default 10.0.3.2 8000; UDP goes to port 9)

   Build (from the repository root):
     docker run --rm -v "$PWD":/w -w /w walkero/amigagccondocker:os4-gcc11 \
       ppc-amigaos-gcc -O2 -Wall -o testprogs/rstcp/c/portprobe testprogs/rstcp/c/portprobe.c */

#include <proto/exec.h>
#include <proto/bsdsocket.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct Library *SocketBase;
struct SocketIFace *ISocket;

static int local_port(LONG s)
{
	struct sockaddr_in a;
	socklen_t len = sizeof(a);

	memset(&a, 0, sizeof(a));
	if (ISocket->getsockname(s, (struct sockaddr *)&a, &len) < 0)
		return -(int)ISocket->Errno();
	return ntohs(a.sin_port);
}

static void addr(struct sockaddr_in *a, const char *ip, int port)
{
	memset(a, 0, sizeof(*a));
	a->sin_len = sizeof(*a);
	a->sin_family = AF_INET;
	a->sin_port = htons(port);
	a->sin_addr.s_addr = ISocket->inet_addr((STRPTR)ip);
}

int main(int argc, char **argv)
{
	const char *ip = argc > 1 ? argv[1] : "10.0.3.2";
	int tport = argc > 2 ? atoi(argv[2]) : 8000;
	struct sockaddr_in to;
	LONG s, r;
	int k;

	SocketBase = IExec->OpenLibrary("bsdsocket.library", 4);
	if (SocketBase == NULL)
		return 20;
	ISocket = (struct SocketIFace *)IExec->GetInterface(SocketBase, "main", 1, NULL);
	if (ISocket == NULL)
		return 20;
	for (k = 0; k < 3; k++) {
		s = ISocket->socket(AF_INET, SOCK_STREAM, 0);
		addr(&to, ip, tport);
		r = ISocket->connect(s, (struct sockaddr *)&to, sizeof(to));
		printf("tcp connect %d: %ld, local port %d\n", k, (long)r, local_port(s));
		ISocket->CloseSocket(s);

		s = ISocket->socket(AF_INET, SOCK_DGRAM, 0);
		addr(&to, ip, 9);
		r = ISocket->sendto(s, "p", 1, 0, (struct sockaddr *)&to, sizeof(to));
		printf("udp sendto %d: %ld, local port %d\n", k, (long)r, local_port(s));
		ISocket->CloseSocket(s);
	}
	s = ISocket->socket(AF_INET, SOCK_STREAM, 0);
	addr(&to, "0.0.0.0", 0);
	r = ISocket->bind(s, (struct sockaddr *)&to, sizeof(to));
	printf("tcp bind 0: %ld, local port %d\n", (long)r, local_port(s));
	r = ISocket->listen(s, 1);
	printf("tcp listen: %ld, local port %d\n", (long)r, local_port(s));
	ISocket->CloseSocket(s);
	s = ISocket->socket(AF_INET, SOCK_DGRAM, 0);
	r = ISocket->bind(s, (struct sockaddr *)&to, sizeof(to));
	printf("udp bind 0: %ld, local port %d\n", (long)r, local_port(s));
	ISocket->CloseSocket(s);
	s = ISocket->socket(AF_INET, SOCK_STREAM, 0);
	r = ISocket->listen(s, 1);
	printf("tcp listen unbound: %ld, local port %d\n", (long)r, local_port(s));
	ISocket->CloseSocket(s);
	IExec->DropInterface((struct Interface *)ISocket);
	IExec->CloseLibrary(SocketBase);
	return 0;
}
