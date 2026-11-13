/*
 * companion-browse: list Apple Rapport ("_companion-link._tcp") devices on the LAN.
 *
 * Rapport is the control channel Continuity Camera uses before any video flows.
 * This tool only discovers and prints what each device advertises; it does not pair.
 *
 * Usage: companion-browse [seconds]   (default 5)
 *
 * TXT keys seen so far (meanings partly inferred, not confirmed):
 *   rpMac  unknown (a MacBook Air on macOS 26.2 shows 0)    rpVr  Rapport version
 *   rpFl   feature flags (hex)       rpBA  rotating Bluetooth address
 *   rpHI rpHA rpAD rpHN  rotating 6-byte hashes, tied to the Apple ID; they cannot
 *                        be checked without that account's identity keys
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/select.h>
#include <dns_sd.h>

#define SERVICE "_companion-link._tcp"
#define MAX_REFS 64

static DNSServiceRef refs[MAX_REFS];
static int nrefs = 0;

static void add_ref(DNSServiceRef ref) {
    if (nrefs < MAX_REFS) refs[nrefs++] = ref;
    else DNSServiceRefDeallocate(ref);  /* shortcut: fixed table, raise MAX_REFS for big networks */
}

static void DNSSD_API on_resolve(DNSServiceRef ref, DNSServiceFlags flags, uint32_t ifindex,
                                 DNSServiceErrorType err, const char *fullname, const char *host,
                                 uint16_t port_be, uint16_t txt_len, const unsigned char *txt,
                                 void *ctx) {
    (void) ref; (void) flags; (void) ctx;
    if (err != kDNSServiceErr_NoError) {
        fprintf(stderr, "resolve failed for %s: %d\n", fullname, err);
        return;
    }
    printf("\n%s\n  host %s:%u  (interface %u)\n", fullname, host, ntohs(port_be), ifindex);
    uint16_t count = TXTRecordGetCount(txt_len, txt);
    for (uint16_t i = 0; i < count; i++) {
        char key[256];
        uint8_t vlen;
        const void *val;
        if (TXTRecordGetItemAtIndex(txt_len, txt, i, sizeof key, key, &vlen, &val)) continue;
        printf("  %-6s %.*s\n", key, (int) vlen, val ? (const char *) val : "");
    }
    fflush(stdout);
}

static void DNSSD_API on_browse(DNSServiceRef ref, DNSServiceFlags flags, uint32_t ifindex,
                                DNSServiceErrorType err, const char *name, const char *type,
                                const char *domain, void *ctx) {
    (void) ref; (void) ctx;
    if (err != kDNSServiceErr_NoError) {
        fprintf(stderr, "browse error: %d\n", err);
        return;
    }
    if (!(flags & kDNSServiceFlagsAdd)) {
        printf("\n[gone] %s\n", name);
        return;
    }
    DNSServiceRef rref;
    if (DNSServiceResolve(&rref, 0, ifindex, name, type, domain, on_resolve, NULL) == kDNSServiceErr_NoError)
        add_ref(rref);
    else
        fprintf(stderr, "could not start resolve for %s\n", name);
}

int main(int argc, char **argv) {
    int seconds = argc > 1 ? atoi(argv[1]) : 5;
    if (seconds <= 0) {
        fprintf(stderr, "usage: %s [seconds]\n", argv[0]);
        return 2;
    }

    DNSServiceRef browse;
    DNSServiceErrorType err = DNSServiceBrowse(&browse, 0, 0, SERVICE, NULL, on_browse, NULL);
    if (err != kDNSServiceErr_NoError) {
        fprintf(stderr, "DNSServiceBrowse failed: %d (is mDNSResponder/avahi-daemon running?)\n", err);
        return 1;
    }
    add_ref(browse);
    printf("Looking for %s devices for %d s...\n", SERVICE, seconds);

    time_t end = time(NULL) + seconds;
    while (time(NULL) < end) {
        fd_set fds;
        FD_ZERO(&fds);
        int maxfd = -1;
        for (int i = 0; i < nrefs; i++) {
            int fd = DNSServiceRefSockFD(refs[i]);
            if (fd < 0) continue;
            FD_SET(fd, &fds);
            if (fd > maxfd) maxfd = fd;
        }
        struct timeval tv = { 1, 0 };
        if (select(maxfd + 1, &fds, NULL, NULL, &tv) <= 0) continue;
        for (int i = 0; i < nrefs; i++) {
            int fd = DNSServiceRefSockFD(refs[i]);
            if (fd >= 0 && FD_ISSET(fd, &fds)) DNSServiceProcessResult(refs[i]);
        }
    }

    for (int i = 0; i < nrefs; i++) DNSServiceRefDeallocate(refs[i]);
    return 0;
}
