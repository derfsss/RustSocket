/* tsprobe: send an ICMP timestamp request (type 13) to ADDR over a raw
   socket and print the answer (type 14: the originate time echoed, and
   whether the receive and transmit times look like milliseconds since
   midnight UT), or that none came within 2 s; also RoadshowControl's
   icmp.procesststamp is printed by the caller.

     tsprobe ADDR

   Build (from the repository root):
     docker run --rm -v "$PWD":/w -w /w walkero/amigagccondocker:os4-gcc11 \
       ppc-amigaos-gcc -O2 -Wall -o testprogs/rstcp/c/tsprobe testprogs/rstcp/c/tsprobe.c */

#include <proto/exec.h>
#include <proto/bsdsocket.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>

struct Library *SocketBase;
struct SocketIFace *ISocket;

static unsigned short sum(const unsigned char *b, int n)
{
	unsigned long s = 0;
	int k;

	for (k = 0; k + 1 < n; k += 2)
		s += (b[k] << 8) | b[k + 1];
	if (n & 1)
		s += b[n - 1] << 8;
	while (s >> 16)
		s = (s & 0xffff) + (s >> 16);
	return (unsigned short)~s;
}

static unsigned long g32(const unsigned char *b)
{
	return ((unsigned long)b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
}

int main(int argc, char **argv)
{
	struct sockaddr_in to, from;
	unsigned char q[20], r[256];
	socklen_t fl = sizeof(from);
	struct timeval tv = { 2, 0 };
	LONG s, n;
	unsigned short c;
	int hl;

	if (argc < 2) {
		printf("usage: tsprobe ADDR\n");
		return 10;
	}
	SocketBase = IExec->OpenLibrary("bsdsocket.library", 4);
	if (SocketBase == NULL)
		return 20;
	ISocket = (struct SocketIFace *)IExec->GetInterface(SocketBase, "main", 1, NULL);
	if (ISocket == NULL)
		return 20;
	s = ISocket->socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (s < 0) {
		printf("socket: errno %ld\n", (long)ISocket->Errno());
		return 20;
	}
	ISocket->setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	memset(q, 0, sizeof(q));
	q[0] = 13;
	q[4] = 0x12; q[5] = 0x34;	/* id */
	q[6] = 0; q[7] = 1;		/* seq */
	q[8] = 0x01; q[9] = 0x02; q[10] = 0x03; q[11] = 0x04;	/* originate */
	c = sum(q, 20);
	q[2] = c >> 8; q[3] = c;
	memset(&to, 0, sizeof(to));
	to.sin_len = sizeof(to);
	to.sin_family = AF_INET;
	to.sin_addr.s_addr = ISocket->inet_addr((STRPTR)argv[1]);
	n = ISocket->sendto(s, q, 20, 0, (struct sockaddr *)&to, sizeof(to));
	printf("sendto = %ld\n", (long)n);
	for (;;) {
		n = ISocket->recvfrom(s, r, sizeof(r), 0, (struct sockaddr *)&from, &fl);
		if (n < 0) {
			printf("no answer (errno %ld)\n", (long)ISocket->Errno());
			break;
		}
		hl = (r[0] & 15) * 4;
		if (n < hl + 20 || r[hl] == 13)
			continue;
		printf("answer: type %d code %d id %02x%02x seq %d originate %08lx, receive %s, transmit %s, receive == transmit %s, ttl %d\n",
			r[hl], r[hl + 1], r[hl + 4], r[hl + 5], r[hl + 7], g32(r + hl + 8),
			g32(r + hl + 12) < 86400000UL ? "ms since midnight" : "other",
			g32(r + hl + 16) < 86400000UL ? "ms since midnight" : "other",
			g32(r + hl + 12) == g32(r + hl + 16) ? "yes" : "no", r[8]);
		break;
	}
	ISocket->CloseSocket(s);
	IExec->DropInterface((struct Interface *)ISocket);
	IExec->CloseLibrary(SocketBase);
	return 0;
}
