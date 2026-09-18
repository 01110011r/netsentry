#include "capture.h"
#include "netsentry.h"

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <arpa/inet.h>

/*
 * Step 1: capture module only.
 *
 * This prints every parsed IPv4 packet to stdout so we can verify the
 * capture/parse path works before flowtrack.c and detect.c exist.
 * on_packet() is the seam where the flow tracker will plug in next.
 */

static const char *proto_name(l4_proto_t p) {
    switch (p) {
        case PROTO_TCP:  return "TCP";
        case PROTO_UDP:  return "UDP";
        case PROTO_ICMP: return "ICMP";
        default:         return "OTHER";
    }
}

static void on_packet(void *ctx, const packet_info_t *pkt) {
    (void)ctx;
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &pkt->src_ip, src, sizeof(src));
    inet_ntop(AF_INET, &pkt->dst_ip, dst, sizeof(dst));

    printf("%ld.%06ld  %-4s  %15s:%-5u -> %15s:%-5u  len=%u",
           (long)pkt->ts.tv_sec, (long)pkt->ts.tv_usec,
           proto_name(pkt->proto),
           src, pkt->src_port, dst, pkt->dst_port,
           pkt->length);

    if (pkt->proto == PROTO_TCP && pkt->tcp_syn && !pkt->tcp_ack)
        printf("  [SYN]");

    printf("\n");
}

static void handle_sigint(int signum) {
    (void)signum;
    /* pcap_breakloop is documented as safe to call from a signal handler */
    capture_stop();
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <interface>\n", argv[0]);
        fprintf(stderr, "       try: %s any    (capture on all interfaces)\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *iface = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    if (capture_init(iface, errbuf) != 0) {
        fprintf(stderr, "capture_init failed: %s\n", errbuf);
        fprintf(stderr, "(live capture needs root, or: sudo setcap "
                         "cap_net_raw,cap_net_admin+eip ./netsentry)\n");
        return EXIT_FAILURE;
    }

    signal(SIGINT, handle_sigint);

    printf("NetSentry capture running on '%s' — press Ctrl+C to stop\n", iface);
    int rc = capture_run(on_packet, NULL);

    capture_close();
    printf("\ncapture stopped.\n");
    return rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
