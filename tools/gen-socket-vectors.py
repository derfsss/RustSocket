#!/usr/bin/env python3
"""Write rustsocket/src/vectors.c: rustsocket.library's "main" vector
table in the slot order of Roadshow's SocketIFace.

The slots come from the crate's generated binding
(amigaos4/src/sys/interfaces/bsdsocket.rs), whose order tests/sdk_audit.rs
checks against the SDK's netinclude/interfaces/bsdsocket.h, so the table
cannot drift from the header the drop-in must match.

- slots 0-3: the interface's Obtain, Release, Expunge (library_glue.c),
  Clone NULL;
- a slot named in IMPLEMENTED: the Rust function rs_<name>;
- a variadic slot "<X>Tags" whose sibling "<X>TagList" exists: a
  VARARGS68K wrapper that collects the tags (va_startlinear) and calls the
  sibling's vector;
- any other slot: a stub that calls rs_stub (logs the name once, sets the
  opener's errno to ENOSYS) and returns what its type calls failure: -1
  for a number, NULL for a pointer, nothing for void.

Run from the VirtioRust root after IMPLEMENTED changes:
    python3 tools/gen-socket-vectors.py
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BINDING = os.path.join(ROOT, "amigaos4", "src", "sys", "interfaces", "bsdsocket.rs")
OUT = os.path.join(ROOT, "rustsocket", "src", "vectors.c")

# The slots rustsocket.library implements in Rust (rs_<name>), by group.
IMPLEMENTED = [
    # openers and errors
    "Errno", "SetErrnoPtr", "SocketBaseTagList",
    # TCP client
    "socket", "connect", "send", "recv", "CloseSocket",
    # non-blocking sockets and WaitSelect
    "shutdown", "getsockname", "getpeername", "IoctlSocket", "setsockopt",
    "getsockopt", "WaitSelect",
    # servers, UDP, names
    "bind", "listen", "accept", "sendto", "recvfrom", "gethostbyname",
    # interfaces and statistics
    "ObtainInterfaceList", "ReleaseInterfaceList", "QueryInterfaceTagList",
    "GetNetworkStatistics",
    # descriptor passing and address helpers
    "ObtainSocket", "ReleaseSocket", "gethostname",
    "Inet_NtoA", "inet_addr", "inet_aton", "inet_network", "Inet_LnaOf",
    "Inet_NetOf", "Inet_MakeAddr", "inet_ntop", "inet_pton",
    # options, descriptors, syslog, netdb, getaddrinfo
    "SetSocketSignals", "getdtablesize", "ReleaseCopyOfSocket", "Dup2Socket",
    "GetSocketEvents", "vsyslog", "gethostid", "In_LocalAddr", "In_CanForward",
    "GetDefaultDomainName", "SetDefaultDomainName", "sendmsg", "recvmsg",
    "getservbyname", "getservbyport", "getprotobyname", "getprotobynumber",
    "getnetbyname", "getnetbyaddr", "setservent", "endservent", "getservent",
    "setprotoent", "endprotoent", "getprotoent", "setnetent", "endnetent",
    "getnetent", "gethostbyaddr", "gethostbyname_r", "gethostbyaddr_r",
    "getaddrinfo", "freeaddrinfo", "gai_strerror", "getnameinfo",
    # the interface API
    "AddInterfaceTagList", "ConfigureInterfaceTagList", "RemoveInterface",
    "CreateAddrAllocMessageA", "DeleteAddrAllocMessage", "BeginInterfaceConfig",
    "AbortInterfaceConfig",
    # the routing API
    "AddRouteTagList", "DeleteRouteTagList", "ChangeRouteTagList", "GetRouteInfo",
    "FreeRouteInfo",
    # the DNS API
    "AddDomainNameServer", "RemoveDomainNameServer", "ObtainDomainNameServerList",
    "ReleaseDomainNameServerList",
    # RoadshowData
    "ObtainRoadshowData", "ChangeRoadshowData", "ReleaseRoadshowData",
    # monitoring
    "AddNetMonitorHookTagList", "RemoveNetMonitorHook",
    # server API (server.rs)
    "ProcessIsServer", "ObtainServerSocket",
    # packet filter (bpf.rs)
    "bpf_open", "bpf_close", "bpf_read", "bpf_write", "bpf_set_notify_mask",
    "bpf_set_interrupt_mask", "bpf_ioctl", "bpf_data_waiting",
    # kernel memory (mbuf.rs)
    "mbuf_copym", "mbuf_copyback", "mbuf_copydata", "mbuf_free", "mbuf_freem",
    "mbuf_get", "mbuf_gethdr", "mbuf_prepend", "mbuf_cat", "mbuf_adj", "mbuf_pullup",
    # IP Filter (ipfil.rs)
    "ipf_open", "ipf_close", "ipf_ioctl", "ipf_log_read", "ipf_log_data_waiting",
    "ipf_set_notify_mask", "ipf_set_interrupt_mask",
]

# Slots whose result the autodoc gives as BOOL (TRUE on success): a stub
# returns FALSE, not -1 (which a caller reads as TRUE). The header and the
# binding type some of them LONG.
BOOL_SLOTS = {"RemoveInterface", "ProcessIsServer", "ChangeRoadshowData", "GetDefaultDomainName"}

text = open(BINDING, encoding="utf-8").read()
body = text[text.index("pub struct SocketIFace"):]
body = body[:body.index("\n}")]
slots = []
for m in re.finditer(r"pub (\w+): (.*?), // (\d+): (\d+)", body):
    name, ty, idx = m.group(1), m.group(2), int(m.group(3))
    slots.append((idx, name, ty))
slots.sort()
assert [s[0] for s in slots] == list(range(len(slots))), "slot numbers have a gap"
assert slots[0][1] == "Obtain" and slots[4][1] == "socket", "unexpected first slots"

names = {s[1] for s in slots}
for n in IMPLEMENTED:
    assert n in names, n

def ret_kind(ty):
    if ty == "APTR":
        return "varargs"
    m = re.search(r"\)\s*->\s*(.+)$", ty)
    if not m:
        return "void"
    r = m.group(1).strip()
    if r.startswith("*") or r in ("APTR", "STRPTR", "CONST_STRPTR"):
        return "ptr"
    return "num"

out = []
out.append("/* Generated by tools/gen-socket-vectors.py from the crate's SocketIFace")
out.append("   binding (bsdsocket.h order). Do not edit. */")
out.append("")
out.append("#define __NOLIBBASE__")
out.append("#define __NOGLOBALIFACE__")
out.append("#include <proto/exec.h>")
out.append("#include <exec/types.h>")
out.append("#include <stdarg.h>")
out.append("")
out.append("extern uint32 main_Obtain(struct Interface *self);")
out.append("extern uint32 main_Release(struct Interface *self);")
out.append("extern APTR main_Expunge(struct Interface *self);")
out.append("extern int32 rs_stub(struct Interface *self, uint32 slot, const char *name);")
for n in IMPLEMENTED:
    out.append("extern void rs_%s(void);" % n)
out.append("")

entries = []
for idx, name, ty in slots:
    if idx < 4:
        entries.append({0: "(void *)main_Obtain", 1: "(void *)main_Release", 2: "(void *)main_Expunge", 3: "(void *)0"}[idx])
        continue
    if name in IMPLEMENTED:
        entries.append("(void *)rs_%s" % name)
        continue
    kind = ret_kind(ty)
    sib = name[:-4] + "TagList" if name.endswith("Tags") else None
    if kind == "varargs" and sib in names:
        sib_idx = [s[0] for s in slots if s[1] == sib][0]
        out.append("/* %d: %s(...) -> %s(tags) */" % (idx, name, sib))
        out.append("static int32 VARARGS68K va_%s(struct Interface *self, ...)" % name)
        out.append("{")
        out.append("    va_list ap;")
        out.append("    int32 r;")
        out.append("    int32 (*f)(struct Interface *, struct TagItem *) = (int32 (*)(struct Interface *, struct TagItem *))((void **)((uint8 *)self + 60))[%d];" % sib_idx)
        out.append("    va_startlinear(ap, self);")
        out.append("    r = f(self, (struct TagItem *)va_getlinearva(ap, struct TagItem *));")
        out.append("    va_end(ap);")
        out.append("    return r;")
        out.append("}")
        entries.append("(void *)va_%s" % name)
        continue
    if kind == "varargs" and name == "CreateAddrAllocMessage" and name + "A" in names:
        # CreateAddrAllocMessage(version, protocol, name, result, tag, ...)
        # -> CreateAddrAllocMessageA(version, protocol, name, result, tags).
        sib_idx = [s[0] for s in slots if s[1] == name + "A"][0]
        out.append("/* %d: %s(version, protocol, name, result, ...) -> %sA */" % (idx, name, name))
        out.append("static int32 VARARGS68K va_%s(struct Interface *self, int32 version, int32 protocol, STRPTR iname, APTR *result, ...)" % name)
        out.append("{")
        out.append("    va_list ap;")
        out.append("    int32 r;")
        out.append("    int32 (*f)(struct Interface *, int32, int32, STRPTR, APTR *, struct TagItem *) = (int32 (*)(struct Interface *, int32, int32, STRPTR, APTR *, struct TagItem *))((void **)((uint8 *)self + 60))[%d];" % sib_idx)
        out.append("    va_startlinear(ap, result);")
        out.append("    r = f(self, version, protocol, iname, result, (struct TagItem *)va_getlinearva(ap, struct TagItem *));")
        out.append("    va_end(ap);")
        out.append("    return r;")
        out.append("}")
        entries.append("(void *)va_%s" % name)
        continue
    vsib = "v" + name
    if kind == "varargs" and vsib in IMPLEMENTED and name == "syslog":
        # syslog(level, format, ...) -> vsyslog(level, format, args).
        out.append("/* %d: %s(level, format, ...) -> rs_%s */" % (idx, name, vsib))
        out.append("static void VARARGS68K va_%s(struct Interface *self, int32 level, const char *format, ...)" % name)
        out.append("{")
        out.append("    va_list ap;")
        # Through a typed pointer (as the TagList wrappers do): a call
        # through a cast of rs_<name>'s own declaration draws a warning.
        out.append("    void (*f)(struct Interface *, int32, const char *, APTR) = (void (*)(struct Interface *, int32, const char *, APTR))(void *)rs_%s;" % vsib)
        out.append("    va_startlinear(ap, format);")
        out.append("    f(self, level, format, va_getlinearva(ap, APTR));")
        out.append("    va_end(ap);")
        out.append("}")
        entries.append("(void *)va_%s" % name)
        continue
    out.append("static %s st_%s(struct Interface *self)" % ({"num": "int32", "ptr": "APTR", "void": "void", "varargs": "int32"}[kind], name))
    out.append("{")
    if kind == "ptr":
        out.append("    rs_stub(self, %d, \"%s\");" % (idx, name))
        out.append("    return NULL;")
    elif kind == "void":
        out.append("    rs_stub(self, %d, \"%s\");" % (idx, name))
    elif name in BOOL_SLOTS:
        out.append("    rs_stub(self, %d, \"%s\");" % (idx, name))
        out.append("    return 0; /* FALSE */")
    else:
        out.append("    return rs_stub(self, %d, \"%s\");" % (idx, name))
    out.append("}")
    entries.append("(void *)st_%s" % name)

out.append("")
out.append("/* The \"main\" interface's vectors, %d slots. */" % len(entries))
out.append("void *mainVectors[] = {")
for idx, e in enumerate(entries):
    out.append("    %s, /* %d %s */" % (e, idx, slots[idx][1]))
out.append("    (void *)(APTR)-1,")
out.append("};")
out.append("")
open(OUT, "w", encoding="utf-8", newline="\n").write("\n".join(out))
print("wrote %s: %d slots, %d in Rust, %d variadic wrappers" % (OUT, len(entries), len(IMPLEMENTED), sum(1 for e in entries if e.startswith("(void *)va_"))))
