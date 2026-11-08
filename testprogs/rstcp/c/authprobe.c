/* authprobe: what a stack does with IP Filter's auth queue (channel
   IPL_LOGAUTH): SIOCATHST, SIOCAUTHW, SIOCAUTHR. The SDK has no ip_auth.h,
   so the buffers are filled with 0xAA first and dumped raw: the bytes the
   stack wrote are the ones that are no longer 0xAA.

     authprobe stat              SIOCATHST
     authprobe wait [pass|block] SIOCAUTHW (blocks until a datagram is held,
                                 or a break); then, with pass or block,
                                 answer it with SIOCAUTHR (fra_pass set to
                                 FR_PASS or FR_BLOCK, the rest as received)

   Output is unbuffered so a run stopped with Break shows how far it got.

   Build (from the repository root):
     docker run --rm -v "$PWD":/w -w /w walkero/amigagccondocker:os4-gcc11 \
       ppc-amigaos-gcc -O2 -Wall -o testprogs/rstcp/c/authprobe testprogs/rstcp/c/authprobe.c */

#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/bsdsocket.h>
#include <libraries/bsdsocket.h>
#include <netinet/ip_fil.h>
#include <stdio.h>
#include <string.h>

struct Library *SocketBase;
struct SocketIFace *ISocket;

#define SIOCATHST_ 0xc004724eUL	/* _IOWR('r', 78, struct fr_authstat *) */
#define SIOCAUTHW_ 0xc004724cUL	/* _IOWR('r', 76, struct frauth_t *) */
#define SIOCAUTHR_ 0xc004724dUL	/* _IOWR('r', 77, struct frauth_t *) */

static unsigned char buf[512];

/* The bytes that are not the 0xAA fill, as offset ranges, then the first
   `n` bytes in hex. */
static void show(const char *what, int n)
{
	int k, start = -1;

	printf("%s: written", what);
	for (k = 0; k <= (int)sizeof(buf); k++) {
		int w = k < (int)sizeof(buf) && buf[k] != 0xAA;
		if (w && start < 0)
			start = k;
		if (!w && start >= 0) {
			printf(" %d-%d", start, k - 1);
			start = -1;
		}
	}
	printf("\n");
	for (k = 0; k < n; k++)
		printf("%02x%s", buf[k], (k % 16) == 15 ? "\n" : " ");
	if (n % 16)
		printf("\n");
}

static LONG call(LONG ch, ULONG cmd, const char *name)
{
	void *p = buf;
	LONG r;

	ULONG sig;
	LONG e;

	printf("%s ...\n", name);
	r = ISocket->ipf_ioctl(ch, cmd, &p);
	e = r < 0 ? ISocket->Errno() : 0;
	/* Take a break signal away before clib's stdio sees it and exits. */
	sig = IExec->SetSignal(0, SIGBREAKF_CTRL_C | SIGBREAKF_CTRL_D);
	printf("ipf_ioctl(%s) = %ld errno %ld signals 0x%lx\n", name, (long)r, (long)e, (unsigned long)sig);
	return r;
}

int main(int argc, char **argv)
{
	LONG ch, r;
	ULONG pass = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	SocketBase = IExec->OpenLibrary("bsdsocket.library", 4);
	if (SocketBase == NULL)
		return 20;
	ISocket = (struct SocketIFace *)IExec->GetInterface(SocketBase, "main", 1, NULL);
	if (ISocket == NULL)
		return 20;
	ch = ISocket->ipf_open(IPL_LOGAUTH);
	printf("ipf_open(IPL_LOGAUTH) = %ld errno %ld\n", (long)ch, (long)(ch < 0 ? ISocket->Errno() : 0));
	if (argc > 1 && strcmp(argv[1], "wait") == 0) {
		if (argc > 2)
			pass = strcmp(argv[2], "pass") == 0 ? FR_PASS : FR_BLOCK;
		memset(buf, 0xAA, sizeof(buf));
		r = call(ch, SIOCAUTHW_, "SIOCAUTHW");
		show("  frauth", 128);
		if (r == 0 && pass != 0) {
			/* fra_age, fra_index, fra_pass, then fra_info. */
			buf[8] = pass >> 24;
			buf[9] = pass >> 16;
			buf[10] = pass >> 8;
			buf[11] = pass;
			call(ch, SIOCAUTHR_, pass == FR_PASS ? "SIOCAUTHR pass" : "SIOCAUTHR block");
		}
	}
	memset(buf, 0xAA, sizeof(buf));
	call(ch, SIOCATHST_, "SIOCATHST");
	show("  fr_authstat", 64);
	ISocket->ipf_close(ch);
	IExec->DropInterface((struct Interface *)ISocket);
	IExec->CloseLibrary(SocketBase);
	return 0;
}
