/* identq: one ident (RFC 1413) query to 127.0.0.1:113 through the TCP:
   device, for Roadshow's 68k C:identd (a test of the 68k bridge,
   LIBS:bsdsocket.l.main). Run identd first: Run >NIL: identd

   Build (from the repository root):
     docker run --rm -v "$PWD":/w -w /w walkero/amigagccondocker:os4-gcc11 \
       ppc-amigaos-gcc -O2 -Wall -o testprogs/rstcp/c/identq testprogs/rstcp/c/identq.c
   Run: identq [query]   (default "113, 4321") */

#include <proto/exec.h>
#include <proto/dos.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
	char q[64], buf[256];
	LONG n, got = 0;
	BPTR fh = IDOS->Open("TCP:127.0.0.1/113", MODE_NEWFILE);
	if (fh == 0) {
		printf("identq: cannot connect (IoErr %ld)\n", (long)IDOS->IoErr());
		return 10;
	}
	snprintf(q, sizeof(q), "%s\r\n", argc > 1 ? argv[1] : "113, 4321");
	IDOS->Write(fh, q, strlen(q));
	while (got < (LONG)sizeof(buf) - 1 && (n = IDOS->Read(fh, buf + got, sizeof(buf) - 1 - got)) > 0) {
		got += n;
		if (memchr(buf, '\n', got))
			break;
	}
	buf[got] = 0;
	printf("identq: \"%s\"\n", strtok(buf, "\r\n") ? buf : "");
	IDOS->Close(fh);
	return got > 0 ? 0 : 10;
}
