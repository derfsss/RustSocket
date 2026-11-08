/* aamvar: CreateAddrAllocMessage's varargs form (it can only be called
   from C: VARARGS68K) against CreateAddrAllocMessageA, on whatever
   bsdsocket.library is installed.

   Build (from the repository root):
     docker run --rm -v "$PWD":/w -w /w walkero/amigagccondocker:os4-gcc11 \
       ppc-amigaos-gcc -O2 -Wall -o testprogs/rstcp/c/aamvar testprogs/rstcp/c/aamvar.c
   Run: aamvar [interface]   (default VIRTIONET) */

#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/bsdsocket.h>
#include <libraries/bsdsocket.h>
#include <stdio.h>
#include <string.h>

struct Library *SocketBase;
struct SocketIFace *ISocket;

int main(int argc, char **argv)
{
	STRPTR name = (STRPTR)(argc > 1 ? argv[1] : "VIRTIONET");
	struct AddressAllocationMessage *a = NULL, *b = NULL;
	LONG ra, rb, fails = 0;

	SocketBase = IExec->OpenLibrary("bsdsocket.library", 4);
	if (SocketBase == NULL) {
		printf("aamvar: no bsdsocket.library\n");
		return 20;
	}
	ISocket = (struct SocketIFace *)IExec->GetInterface(SocketBase, "main", 1, NULL);
	if (ISocket == NULL) {
		IExec->CloseLibrary(SocketBase);
		return 20;
	}
	ra = ISocket->CreateAddrAllocMessage(AAM_VERSION, AAMP_DHCP, name, &a,
		CAAMTA_Timeout, 7,
		TAG_END);
	{
		struct TagItem tags[] = { { CAAMTA_Timeout, 7 }, { TAG_END, 0 } };
		rb = ISocket->CreateAddrAllocMessageA(AAM_VERSION, AAMP_DHCP, name, &b, tags);
	}
	printf("aamvar: varargs %ld (%s), tag list %ld (%s)\n", (long)ra, a ? "message" : "none", (long)rb, b ? "message" : "none");
	if (ra != rb || (a == NULL) != (b == NULL))
		fails++;
	if (a != NULL && b != NULL) {
		printf("aamvar: aam_Version %ld/%ld protocol %ld/%ld timeout %ld/%ld interface %s/%s\n",
			(long)a->aam_Version, (long)b->aam_Version, (long)a->aam_Protocol, (long)b->aam_Protocol,
			(long)a->aam_Timeout, (long)b->aam_Timeout, a->aam_InterfaceName, b->aam_InterfaceName);
		if (a->aam_Version != b->aam_Version || a->aam_Protocol != b->aam_Protocol || a->aam_Timeout != b->aam_Timeout
		 || strcmp(a->aam_InterfaceName, b->aam_InterfaceName) != 0 || a->aam_Timeout != 7)
			fails++;
	}
	if (a != NULL)
		ISocket->DeleteAddrAllocMessage(a);
	if (b != NULL)
		ISocket->DeleteAddrAllocMessage(b);
	printf("aamvar: %s\n", fails == 0 ? "PASS" : "FAIL");
	IExec->DropInterface((struct Interface *)ISocket);
	IExec->CloseLibrary(SocketBase);
	return fails == 0 ? 0 : 10;
}
