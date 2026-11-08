/* tcpdos: the TCP: device (Roadshow's tcp-handler.doc) as DOS programs use
   it, on whatever bsdsocket.library is installed. Needs a servers file
   (DEVS:Internet/servers) with daytime and echo internal and systat as a
   DOS server running "rstcp dosserver" (see rstcp's servers.rs).

   Build (from the repository root):
     docker run --rm -v "$PWD":/w -w /w walkero/amigagccondocker:os4-gcc11 \
       ppc-amigaos-gcc -O2 -Wall -o testprogs/rstcp/c/tcpdos testprogs/rstcp/c/tcpdos.c
   Run: tcpdos [host]   (default 127.0.0.1) */

#include <proto/exec.h>
#include <proto/dos.h>
#include <stdio.h>
#include <string.h>

static int fails;

static void check(int ok, const char *what)
{
	printf("%s %s\n", ok ? "PASS" : "FAIL", what);
	if (!ok)
		fails++;
}

/* Read until the end or `max` bytes. */
static LONG slurp(BPTR fh, char *buf, LONG max)
{
	LONG got = 0, n;
	while (got < max && (n = IDOS->Read(fh, buf + got, max - got)) > 0)
		got += n;
	buf[got < max ? got : max - 1] = 0;
	return got;
}

static void show(const char *what, const char *s)
{
	printf("%s: \"", what);
	for (; *s; s++) {
		if (*s == '\r') printf("\\r");
		else if (*s == '\n') printf("\\n");
		else putchar(*s);
	}
	printf("\"\n");
}

int main(int argc, char **argv)
{
	const char *host = argc > 1 ? argv[1] : "127.0.0.1";
	char name[128], buf[256];
	BPTR fh;
	LONG n, e;

	/* The doc's own example: Type TCP:localhost/daytime. */
	snprintf(name, sizeof(name), "TCP:%s/daytime", host);
	fh = IDOS->Open(name, MODE_OLDFILE);
	check(fh != 0, "open TCP:host/daytime");
	if (fh) {
		printf("interactive %ld\n", (long)IDOS->IsInteractive(fh));
		n = slurp(fh, buf, sizeof(buf));
		show("daytime", buf);
		check(n > 8, "daytime answered");
		IDOS->Close(fh);
	}

	/* HOST=/PORT= keywords and a number. */
	snprintf(name, sizeof(name), "TCP:HOST=%s/PORT=7", host);
	fh = IDOS->Open(name, MODE_NEWFILE);
	check(fh != 0, "open TCP:HOST=host/PORT=7 (echo)");
	if (fh) {
		n = IDOS->Write(fh, "line one\n", 9);
		check(n == 9, "write 9 bytes");
		printf("WaitForChar 1 s: %ld\n", (long)IDOS->WaitForChar(fh, 1000000));
		n = IDOS->Read(fh, buf, sizeof(buf) - 1);
		buf[n > 0 ? n : 0] = 0;
		show("echo", buf);
		check(n == 9 && memcmp(buf, "line one\n", 9) == 0, "echo came back");
		IDOS->Close(fh);
	}

	/* Errors: a closed port, an unknown host, an id never released. */
	snprintf(name, sizeof(name), "TCP:%s/4599", host);
	fh = IDOS->Open(name, MODE_OLDFILE);
	e = IDOS->IoErr();
	printf("closed port: %s, IoErr %ld\n", fh ? "opened" : "failed", (long)e);
	check(fh == 0, "a closed port fails");
	if (fh) IDOS->Close(fh);
	fh = IDOS->Open("TCP:no.such.host.invalid/80", MODE_OLDFILE);
	e = IDOS->IoErr();
	printf("unknown host: %s, IoErr %ld\n", fh ? "opened" : "failed", (long)e);
	check(fh == 0, "an unknown host fails");
	if (fh) IDOS->Close(fh);
	fh = IDOS->Open("TCP:OBTAIN=123456", MODE_OLDFILE);
	e = IDOS->IoErr();
	printf("obtain unknown id: %s, IoErr %ld\n", fh ? "opened" : "failed", (long)e);
	check(fh == 0, "OBTAIN of an unknown id fails");
	if (fh) IDOS->Close(fh);

	/* A DOS server: rstcp dosserver reads a line from Input() and
	   answers on Output(). */
	snprintf(name, sizeof(name), "TCP:%s/systat", host);
	fh = IDOS->Open(name, MODE_NEWFILE);
	check(fh != 0, "open TCP:host/systat (a DOS server)");
	if (fh) {
		IDOS->Write(fh, "from tcpdos\n", 12);
		n = slurp(fh, buf, sizeof(buf));
		show("dos server", buf);
		check(strstr(buf, "dos ok from tcpdos") != NULL, "the DOS server read our line and answered");
		IDOS->Close(fh);
	}

	printf("tcpdos: %s (%d failed)\n", fails == 0 ? "PASS" : "FAIL", fails);
	return fails == 0 ? 0 : 10;
}
