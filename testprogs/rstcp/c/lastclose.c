/* lastclose: what is left after the last CloseLibrary of a socket library
   that runs its own TCP: handler and superserver (rustsocket.library's dev
   build, loaded by path beside Roadshow): the TCP device, the stack's,
   superserver's and handler's tasks, before and after.

     lastclose LIBPATH [open]    "open": keep a TCP: file open across the
                                 last Close, read it after, then close it
     lastclose LIBPATH expunge   open it once more, RemLibrary, close: the
                                 library should leave memory (check the
                                 system's library list afterwards)

   Build (from the repository root):
     docker run --rm -v "$PWD":/w -w /w walkero/amigagccondocker:os4-gcc11 \
       ppc-amigaos-gcc -O2 -Wall -o testprogs/rstcp/c/lastclose testprogs/rstcp/c/lastclose.c */

#include <proto/exec.h>
#include <proto/dos.h>
#include <stdio.h>
#include <string.h>

static const char *tasks[] = { "rsnet stack", "rustsocket superserver", "rustsocket TCP-Handler" };

static int has_tcp(void)
{
	struct DosList *d;
	int found;

	d = IDOS->LockDosList(LDF_DEVICES | LDF_READ);
	found = IDOS->FindDosEntry(d, "TCP", LDF_DEVICES) != NULL;
	IDOS->UnLockDosList(LDF_DEVICES | LDF_READ);
	return found;
}

static void show(const char *when)
{
	int k;

	printf("%s: TCP device %s;", when, has_tcp() ? "there" : "gone");
	for (k = 0; k < 3; k++)
		printf(" '%s' %s;", tasks[k], IExec->FindTask(tasks[k]) ? "there" : "gone");
	printf("\n");
}

static void wait_ticks(int t)
{
	IDOS->Delay(t);
}

static void daytime(BPTR f, const char *what)
{
	char line[128];
	LONG n;

	n = IDOS->Read(f, line, sizeof(line) - 1);
	if (n > 0) {
		line[n] = 0;
		while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'))
			line[--n] = 0;
	}
	printf("%s: Read = %ld%s%s\n", what, (long)n, n > 0 ? ", daytime " : "", n > 0 ? "(a date)" : "");
}

int main(int argc, char **argv)
{
	struct Library *lib;
	BPTR f = 0;
	int keep = argc > 2 && strcmp(argv[2], "open") == 0;
	int expunge = argc > 2 && strcmp(argv[2], "expunge") == 0;
	int k;

	if (argc < 2) {
		printf("usage: lastclose LIBPATH [open|expunge]\n");
		return 10;
	}
	show("before");
	lib = IExec->OpenLibrary(argv[1], 4);
	printf("OpenLibrary(%s) = %s\n", argv[1], lib ? "ok" : "NULL");
	if (lib == NULL)
		return 20;
	for (k = 0; k < 50 && !has_tcp(); k++)
		wait_ticks(2);
	/* The superserver reads DEVS:Internet/servers once it runs. */
	wait_ticks(75);
	show("opened");
	if (expunge) {
		IExec->RemLibrary(lib);
		IExec->CloseLibrary(lib);
		wait_ticks(100);
		show("after RemLibrary + CloseLibrary");
		return 0;
	}
	f = IDOS->Open("TCP:localhost/daytime", MODE_OLDFILE);
	printf("Open(TCP:localhost/daytime) = %s, IoErr %ld\n", f ? "ok" : "0", (long)(f ? 0 : IDOS->IoErr()));
	if (f && !keep) {
		daytime(f, "before the last Close");
		IDOS->Close(f);
		f = 0;
	}
	IExec->CloseLibrary(lib);
	printf("CloseLibrary done\n");
	wait_ticks(50);
	show("closed");
	if (f) {
		daytime(f, "after the last Close");
		IDOS->Close(f);
		wait_ticks(50);
		show("file closed");
	}
	return 0;
}
