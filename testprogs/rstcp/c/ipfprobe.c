/* ipfprobe: what a stack answers to the IP filter calls (ipf_open,
   ipf_close, ipf_ioctl, ipf_log_read, ipf_log_data_waiting,
   ipf_set_notify_mask, ipf_set_interrupt_mask), printed in full so two
   stacks can be compared line by line: return values, errno, and the
   structures the ioctls fill (raw bytes where the SDK has no header).

     ipfprobe            the calls and the statistics
     ipfprobe list       also walk the loaded rule lists (load some with
                         ipf -f first) and dump each stored frentry
     ipfprobe log N      read the log of channel N for 10 s (ipmon's way)

   The ioctls whose argument is a struct pointer take a pointer TO that
   pointer, as Roadshow's ipf/ipfstat call them (disassembled).

   Build (from the repository root):
     docker run --rm -v "$PWD":/w -w /w walkero/amigagccondocker:os4-gcc11 \
       ppc-amigaos-gcc -O2 -Wall -o testprogs/rstcp/c/ipfprobe testprogs/rstcp/c/ipfprobe.c */

#include <proto/exec.h>
#include <proto/dos.h>
#include <proto/bsdsocket.h>
#include <libraries/bsdsocket.h>
#include <netinet/ip_fil.h>
#include <netinet/ip_nat.h>
#include <stdio.h>
#include <string.h>

struct Library *SocketBase;
struct SocketIFace *ISocket;

#define SIOCGNATS_ 0xc004723eUL	/* _IOWR('r', 62, struct natstat *) */
#define SIOCATHST_ 0xc004724eUL

static void dump(const char *what, const unsigned char *p, int n)
{
	int k, last = -1;

	for (k = 0; k < n; k++)
		if (p[k] != 0)
			last = k;
	printf("%s: %d bytes, nonzero up to %d\n", what, n, last + 1);
	for (k = 0; k <= last; k++)
		printf("%02x%s", p[k], (k % 16) == 15 ? "\n" : " ");
	if (last >= 0 && (last % 16) != 15)
		printf("\n");
}

static LONG err(void)
{
	return ISocket->Errno();
}

/* An ioctl whose argument is a pointer to `buf`. */
static LONG ioctl_ptr(LONG ch, ULONG cmd, void *buf, int n, const char *name)
{
	void *p = buf;
	LONG r;

	memset(buf, 0, n);
	r = ISocket->ipf_ioctl(ch, cmd, &p);
	printf("ipf_ioctl(%ld, %s) = %ld errno %ld\n", (long)ch, name, (long)r, (long)(r < 0 ? err() : 0));
	return r;
}

static void show_rule(const char *list, int k, frentry_t *f)
{
	unsigned char *b = (unsigned char *)f;

	printf("%s[%d] at %p: next %p grp %p ref %ld ifa %p oifa %p hits %lu bytes %lu flags 0x%lx group %lu head %lu cksum 0x%lx ifname '%.16s'\n",
		list, k, (void *)f, (void *)f->fr_next, (void *)f->fr_grp, (long)f->fr_ref, f->fr_ifa, f->fr_oifa,
		(unsigned long)f->fr_hits, (unsigned long)f->fr_bytes, (unsigned long)f->fr_flags,
		(unsigned long)f->fr_group, (unsigned long)f->fr_grhead, (unsigned long)f->fr_cksum, f->fr_ifname);
	dump("  frentry", b, sizeof(*f));
}

static void walk(const char *name, frentry_t *f)
{
	int k = 0;

	if (f == NULL) {
		printf("%s: empty\n", name);
		return;
	}
	for (; f != NULL && k < 64; f = f->fr_next, k++)
		show_rule(name, k, f);
}

int main(int argc, char **argv)
{
	static unsigned char buf[4096];
	friostat_t fio;
	ULONG v = 0, ff;
	LONG r, ch, fd;
	int list = argc > 1 && strcmp(argv[1], "list") == 0;
	int log = argc > 2 && strcmp(argv[1], "log") == 0;

	SocketBase = IExec->OpenLibrary("bsdsocket.library", 4);
	if (SocketBase == NULL)
		return 20;
	ISocket = (struct SocketIFace *)IExec->GetInterface(SocketBase, "main", 1, NULL);
	if (ISocket == NULL)
		return 20;
	r = ISocket->SocketBaseTags(SBTM_GETREF(SBTC_IPF_API_VERSION), &v, TAG_END);
	printf("ipfprobe: SBTC_IPF_API_VERSION = %ld (result %ld)\n", (long)v, (long)r);
	printf("ipfprobe: sizeof frentry %d friostat %d filterstats %d iplog %d ipflog %d\n",
		(int)sizeof(frentry_t), (int)sizeof(friostat_t), (int)sizeof(filterstats_t),
		(int)sizeof(iplog_t), (int)sizeof(ipflog_t));

	if (argc > 1 && strcmp(argv[1], "nat") == 0) {
		/* natstat, then the rules (ns_list, in_next) and the sessions
		   (ns_instances, nat_next) as raw records: ipnat -l walks them. */
		ULONG *ns = (ULONG *)buf;
		unsigned char *q;
		int k;
		fd = ISocket->ipf_open(IPL_LOGNAT);
		printf("ipf_open(IPL_LOGNAT) = %ld\n", (long)fd);
		printf("sizeof ipnat %d nat %d natstat %d\n", (int)sizeof(ipnat_t), (int)sizeof(nat_t), (int)sizeof(natstat_t));
		if (ioctl_ptr(fd, SIOCGNATS_, buf, sizeof(natstat_t), "SIOCGNATS") == 0) {
			dump("  natstat", buf, sizeof(natstat_t));
			q = (unsigned char *)((natstat_t *)buf)->ns_list;
			for (k = 0; q != NULL && k < 16; k++, q = (unsigned char *)((ipnat_t *)q)->in_next) {
				printf("ipnat[%d] at %p\n", k, (void *)q);
				dump("  ipnat", q, sizeof(ipnat_t));
			}
			q = (unsigned char *)((natstat_t *)buf)->ns_instances;
			for (k = 0; q != NULL && k < 16; k++, q = (unsigned char *)((nat_t *)q)->nat_next) {
				printf("nat[%d] at %p\n", k, (void *)q);
				dump("  nat", q, sizeof(nat_t));
			}
		}
		(void)ns;
		ISocket->ipf_close(fd);
		return 0;
	}
	if (log) {
		LONG n, total = 0, t;
		ch = 0;
		sscanf(argv[2], "%ld", &ch);
		fd = ISocket->ipf_open(ch);
		printf("ipf_open(%ld) = %ld errno %ld\n", (long)ch, (long)fd, (long)(fd < 0 ? err() : 0));
		for (t = 0; t < 100; t++) {
			LONG fionread = -2, fr;
			fr = ISocket->ipf_ioctl(fd, 0x4004667fUL, &fionread);	/* FIONREAD, as ipmon polls */
			n = ISocket->ipf_log_data_waiting(fd);
			if (n > 0 || fionread > 0)
				printf("FIONREAD = %ld (result %ld errno %ld), data_waiting = %ld\n", (long)fionread, (long)fr,
					(long)(fr < 0 ? err() : 0), (long)n);
			if (n > 0 || fionread > 0) {
				LONG got = ISocket->ipf_log_read(fd, buf, sizeof(buf));
				printf("ipf_log_data_waiting = %ld; ipf_log_read = %ld errno %ld\n", (long)n, (long)got,
					(long)(got < 0 ? err() : 0));
				if (got > 0) {
					dump("log", buf, got);
					total += got;
				}
			}
			IDOS->Delay(5);
		}
		printf("ipfprobe: %ld log bytes\n", (long)total);
		ISocket->ipf_close(fd);
		return 0;
	}

	for (ch = -1; ch <= 5; ch++) {
		fd = ISocket->ipf_open(ch);
		printf("ipf_open(%ld) = %ld errno %ld\n", (long)ch, (long)fd, (long)(fd < 0 ? err() : 0));
		if (fd >= 0) {
			r = ISocket->ipf_log_data_waiting(fd);
			printf("  ipf_log_data_waiting = %ld errno %ld\n", (long)r, (long)(r < 0 ? err() : 0));
			r = ISocket->ipf_close(fd);
			printf("  ipf_close = %ld errno %ld\n", (long)r, (long)(r < 0 ? err() : 0));
			r = ISocket->ipf_close(fd);
			printf("  ipf_close again = %ld errno %ld\n", (long)r, (long)(r < 0 ? err() : 0));
		}
	}
	r = ISocket->ipf_ioctl(0, SIOCGETFF, &ff);
	printf("ipf_ioctl(0 not open, SIOCGETFF) = %ld errno %ld\n", (long)r, (long)(r < 0 ? err() : 0));

	fd = ISocket->ipf_open(IPL_LOGIPF);
	printf("ipf_open(IPL_LOGIPF) = %ld; again: %ld errno %ld\n", (long)fd, (long)(r = ISocket->ipf_open(IPL_LOGIPF)),
		(long)(r < 0 ? err() : 0));
	if (r >= 0)
		ISocket->ipf_close(r);
	r = ISocket->ipf_ioctl(fd, 0x12345678, buf);
	printf("ipf_ioctl(bad command) = %ld errno %ld\n", (long)r, (long)(r < 0 ? err() : 0));
	ff = 0xdeadbeef;
	r = ISocket->ipf_ioctl(fd, SIOCGETFF, &ff);
	printf("ipf_ioctl(SIOCGETFF) = %ld errno %ld, flags 0x%lx\n", (long)r, (long)(r < 0 ? err() : 0), (unsigned long)ff);
	if (ioctl_ptr(fd, SIOCGETFS, &fio, sizeof(fio), "SIOCGETFS") == 0) {
		printf("  version '%.32s' defpass 0x%lx active %d running %d logging %d\n", fio.f_version,
			(unsigned long)fio.f_defpass, fio.f_active, fio.f_running, fio.f_logging);
		printf("  fin %p %p fout %p %p acctin %p %p acctout %p %p auth %p\n", (void *)fio.f_fin[0],
			(void *)fio.f_fin[1], (void *)fio.f_fout[0], (void *)fio.f_fout[1], (void *)fio.f_acctin[0],
			(void *)fio.f_acctin[1], (void *)fio.f_acctout[0], (void *)fio.f_acctout[1], (void *)fio.f_auth);
		printf("  groups %p %p %p %p %p %p froute %lu %lu locks %ld %ld %ld %ld\n",
			(void *)fio.f_groups[0][0], (void *)fio.f_groups[0][1], (void *)fio.f_groups[1][0],
			(void *)fio.f_groups[1][1], (void *)fio.f_groups[2][0], (void *)fio.f_groups[2][1],
			(unsigned long)fio.f_froute[0], (unsigned long)fio.f_froute[1], (long)fio.f_locks[0],
			(long)fio.f_locks[1], (long)fio.f_locks[2], (long)fio.f_locks[3]);
		dump("  friostat", (unsigned char *)&fio, sizeof(fio));
		if (list) {
			int a = fio.f_active;
			walk("fin[active]", fio.f_fin[a]);
			walk("fout[active]", fio.f_fout[a]);
			walk("acctin[active]", fio.f_acctin[a]);
			walk("acctout[active]", fio.f_acctout[a]);
			walk("fin[inactive]", fio.f_fin[1 - a]);
			walk("fout[inactive]", fio.f_fout[1 - a]);
		}
	}
	ioctl_ptr(fd, SIOCGFRST, buf, 256, "SIOCGFRST");
	dump("  ipfrstat", buf, 256);
	r = ISocket->ipf_log_read(fd, buf, 0);
	printf("ipf_log_read(len 0) = %ld errno %ld\n", (long)r, (long)(r < 0 ? err() : 0));
	r = ISocket->ipf_set_notify_mask(fd, 0);
	printf("ipf_set_notify_mask(0) = %ld errno %ld\n", (long)r, (long)(r < 0 ? err() : 0));
	r = ISocket->ipf_set_interrupt_mask(fd, 0);
	printf("ipf_set_interrupt_mask(0) = %ld errno %ld\n", (long)r, (long)(r < 0 ? err() : 0));
	ISocket->ipf_close(fd);

	fd = ISocket->ipf_open(IPL_LOGSTATE);
	ioctl_ptr(fd, SIOCGETFS, buf, 512, "state SIOCGETFS");
	dump("  ips_stat", buf, 512);
	ISocket->ipf_close(fd);
	fd = ISocket->ipf_open(IPL_LOGNAT);
	ioctl_ptr(fd, SIOCGNATS_, buf, 512, "nat SIOCGNATS");
	dump("  natstat", buf, 512);
	ISocket->ipf_close(fd);
	fd = ISocket->ipf_open(IPL_LOGAUTH);
	ioctl_ptr(fd, SIOCATHST_, buf, 512, "auth SIOCATHST");
	dump("  fr_authstat", buf, 512);
	ISocket->ipf_close(fd);

	IExec->DropInterface((struct Interface *)ISocket);
	IExec->CloseLibrary(SocketBase);
	return 0;
}
