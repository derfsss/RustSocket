/* dmabench: where (if anywhere) fsldma.resource's DMA copies beat the CPU
   for the copies a socket library makes, on the machines that have it
   (X5000/20 p5020, X5000/40 p5040, A1222 p1022; kernel 54.41 or newer).
   For each size from one Ethernet frame up to 1 MB, between two ordinary
   MEMF_SHARED buffers (virtual memory, as a program's recv() buffer is):
   memcpy, IExec->CopyMemQuick, IfslDMA->CopyMemDMA (blocking; the
   resource does StartDMA/EndDMA itself), and CopyMemDMATags with
   FSLDMA_CM_DoNotWait plus a completion signal (start-to-signal time).
   Prints microseconds per copy and MB/s; every DMA copy is verified.
   Exits with a message where there is no fsldma.resource (QEMU, X1000,
   Sam460).

     dmabench [ROUNDS]         (default 200 copies per size)

   Build (from the repository root):
     docker run --rm -v "$PWD":/w -w /w walkero/amigagccondocker:os4-gcc11 \
       ppc-amigaos-gcc -O2 -Wall -o testprogs/rstcp/c/dmabench testprogs/rstcp/c/dmabench.c */

#include <proto/exec.h>
#include <proto/timer.h>
#include <proto/fsldma.h>
#include <resources/fsldma.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct fslDMAIFace *IfslDMA;
struct TimerIFace *ITimer;

static uint64 now_us(void)
{
	struct TimeVal t;

	ITimer->GetUpTime(&t);
	return (uint64)t.Seconds * 1000000ULL + t.Microseconds;
}

static void report(const char *what, uint32 size, int rounds, uint64 us, int ok)
{
	double per = (double)us / rounds;
	double mbs = per > 0 ? (double)size / per : 0;	/* bytes per us = MB/s */

	printf("  %-22s %9.2f us  %8.1f MB/s%s\n", what, per, mbs, ok ? "" : "  (FAILED or not verified)");
}

int main(int argc, char **argv)
{
	static const uint32 sizes[] = { 1514, 4096, 16384, 65536, 262144, 1048576 };
	struct Library *execLib = &((struct ExecBase *)SysBase)->LibNode;
	struct TimeRequest tr;
	int rounds = argc > 1 ? atoi(argv[1]) : 200;
	uint8 *src, *dst;
	int8 sig;
	unsigned k;
	int r, ok;
	uint64 t0;

	if (rounds < 1)
		rounds = 1;
	if (!LIB_IS_AT_LEAST(execLib, 54, 41)) {
		printf("dmabench: needs kernel 54.41 or newer (fsldma.resource)\n");
		return 5;
	}
	IfslDMA = IExec->OpenResource(FSLDMA_NAME);
	if (IfslDMA == NULL) {
		printf("dmabench: no fsldma.resource on this machine\n");
		return 5;
	}
	memset(&tr, 0, sizeof(tr));
	if (IExec->OpenDevice("timer.device", UNIT_MICROHZ, (struct IORequest *)&tr, 0) != 0)
		return 20;
	ITimer = (struct TimerIFace *)IExec->GetInterface((struct Library *)tr.Request.io_Device, "main", 1, NULL);
	src = IExec->AllocVecTags(1048576 + 64, AVT_Type, MEMF_SHARED, AVT_Alignment, 64, TAG_END);
	dst = IExec->AllocVecTags(1048576 + 64, AVT_Type, MEMF_SHARED, AVT_Alignment, 64, TAG_END);
	sig = IExec->AllocSignal(-1);
	if (ITimer == NULL || src == NULL || dst == NULL || sig < 0)
		return 20;
	for (k = 0; k < 1048576; k++)
		src[k] = (uint8)(k * 7 + 3);

	printf("dmabench: %d copies per size, MEMF_SHARED buffers, 64-byte aligned\n", rounds);
	for (k = 0; k < sizeof(sizes) / sizeof(sizes[0]); k++) {
		uint32 n = sizes[k];

		printf("%lu bytes:\n", (unsigned long)n);
		t0 = now_us();
		for (r = 0; r < rounds; r++)
			memcpy(dst, src, n);
		report("memcpy", n, rounds, now_us() - t0, memcmp(dst, src, n) == 0);

		memset(dst, 0, n);
		t0 = now_us();
		for (r = 0; r < rounds; r++)
			IExec->CopyMemQuick(src, dst, n);
		report("CopyMemQuick", n, rounds, now_us() - t0, memcmp(dst, src, n) == 0);

		memset(dst, 0, n);
		ok = 1;
		t0 = now_us();
		for (r = 0; r < rounds; r++)
			ok &= IfslDMA->CopyMemDMA(src, dst, n) != FALSE;
		report("CopyMemDMA", n, rounds, now_us() - t0, ok && memcmp(dst, src, n) == 0);

		/* Started without waiting, then Wait for the completion signal:
		   the time the CPU would be free while the engine copies. */
		memset(dst, 0, n);
		ok = 1;
		t0 = now_us();
		for (r = 0; r < rounds; r++) {
			uint32 rc = FSLDMA_RC_UNKNOWN;

			IExec->SetSignal(0, 1UL << sig);
			if (!IfslDMA->CopyMemDMATags(src, dst, n,
					FSLDMA_CM_NotifyTask, IExec->FindTask(NULL),
					FSLDMA_CM_NotifySignalNumber, sig,
					FSLDMA_CM_ResultCode, &rc, TAG_END) || rc != FSLDMA_RC_STARTED) {
				ok = 0;
				break;
			}
			IExec->Wait(1UL << sig);
		}
		report("CopyMemDMATags async", n, rounds, now_us() - t0, ok && memcmp(dst, src, n) == 0);
	}
	IExec->FreeSignal(sig);
	IExec->FreeVec(src);
	IExec->FreeVec(dst);
	IExec->DropInterface((struct Interface *)ITimer);
	IExec->CloseDevice((struct IORequest *)&tr);
	return 0;
}
