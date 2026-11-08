/* hostprobe: what gethostbyname answers for each name given (the official
   name, aliases, addresses, h_errno), so two stacks' resolvers can be
   compared line by line (name_resolution's domain and search lines).

     hostprobe NAME ...

   Build (from the repository root):
     docker run --rm -v "$PWD":/w -w /w walkero/amigagccondocker:os4-gcc11 \
       ppc-amigaos-gcc -O2 -Wall -o testprogs/rstcp/c/hostprobe testprogs/rstcp/c/hostprobe.c */

#include <proto/exec.h>
#include <proto/bsdsocket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>

struct Library *SocketBase;
struct SocketIFace *ISocket;

int main(int argc, char **argv)
{
	struct hostent *h;
	LONG herr;
	int k, j;

	SocketBase = IExec->OpenLibrary("bsdsocket.library", 4);
	if (SocketBase == NULL)
		return 20;
	ISocket = (struct SocketIFace *)IExec->GetInterface(SocketBase, "main", 1, NULL);
	if (ISocket == NULL)
		return 20;
	for (k = 1; k < argc; k++) {
		herr = 0;
		ISocket->SocketBaseTags(SBTM_SETVAL(SBTC_HERRNO), 0, TAG_END);
		h = ISocket->gethostbyname((STRPTR)argv[k]);
		ISocket->SocketBaseTags(SBTM_GETREF(SBTC_HERRNO), &herr, TAG_END);
		printf("gethostbyname(%s): %s, h_errno %ld\n", argv[k], h ? "found" : "NULL", (long)herr);
		if (h == NULL)
			continue;
		printf("  h_name '%s'\n", h->h_name);
		for (j = 0; h->h_aliases && h->h_aliases[j]; j++)
			printf("  alias '%s'\n", h->h_aliases[j]);
		printf("  addresses:");
		for (j = 0; h->h_addr_list && h->h_addr_list[j]; j++)
			printf(" %s", j < 1 ? "yes" : "");
		printf(" (%d)\n", j);
	}
	IExec->DropInterface((struct Interface *)ISocket);
	IExec->CloseLibrary(SocketBase);
	return 0;
}
