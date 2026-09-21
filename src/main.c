#include "capture.h"
#include "flowtrack.h"
#include "netsentry.h"

#include <arpa/inet.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#define WINDOW_SECS 60

/*
 * Step 1: capture module only.
 *
 * This prints every parsed IPv4 packet to stdout so we can verify the
 * capture/parse path works before flowtrack.c and detect.c exist.
 * on_packet() is the seam where the flow tracker will plug in next.
 */

static const char *proto_name(l4_proto_t p) {
  switch (p) {
  case PROTO_TCP:
    return "TCP";
  case PROTO_UDP:
    return "UDP";
  case PROTO_ICMP:
    return "ICMP";
  default:
    return "OTHER";
  }
}

static void on_packet(void *ctx, const packet_info_t *pkt) {
  // (void)ctx;
  // char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
  // inet_ntop(AF_INET, &pkt->src_ip, src, sizeof(src));
  // inet_ntop(AF_INET, &pkt->dst_ip, dst, sizeof(dst));
  //
  // printf("%ld.%06ld  %-4s  %15s:%-5u -> %15s:%-5u  len=%u",
  //        (long)pkt->ts.tv_sec, (long)pkt->ts.tv_usec, proto_name(pkt->proto),
  //        src, pkt->src_port, dst, pkt->dst_port, pkt->length);
  //
  // if (pkt->proto == PROTO_TCP && pkt->tcp_syn && !pkt->tcp_ack)
  //   printf("  [SYN]");
  //
  // printf("\n");

  flow_table_t *ft = (flow_table_t *)ctx;

  flowtrack_update(ft, pkt);

  flow_stats_t stats;
  flowtrack_get(ft, pkt->src_ip,
                &stats); /* just updated it, so this can't fail */

  char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &pkt->src_ip, src, sizeof(src));
  inet_ntop(AF_INET, &pkt->dst_ip, dst, sizeof(dst));

  printf("%-4s %15s:%-5u -> %15s:%-5u len=%-5u", proto_name(pkt->proto), src,
         pkt->src_port, dst, pkt->dst_port, pkt->length);

  if (pkt->proto == PROTO_TCP && pkt->tcp_syn && !pkt->tcp_ack)
    printf("  [SYN]");

  printf("  | %s last %ds: pkts=%llu bytes=%llu syn=%llu\n", src, WINDOW_SECS,
         (unsigned long long)stats.packets, (unsigned long long)stats.bytes,
         (unsigned long long)stats.syn_count);
}

static void on_tick(void *ctx) { flowtrack_tick((flow_table_t *)ctx); }

static void handle_sigint(int signum) {
  (void)signum;
  /* pcap_breakloop is documented as safe to call from a signal handler */
  capture_stop();
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s <interface>\n", argv[0]);
    fprintf(stderr, "       try: %s any    (capture on all interfaces)\n",
            argv[0]);
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

  flow_table_t *ft = flowtrack_create(WINDOW_SECS);
  if (!ft) {
    fprintf(stderr, "flowtrack_create failed\n");
    capture_close();
    return EXIT_FAILURE;
  }

  signal(SIGINT, handle_sigint);

  printf("NetSentry capture running on '%s' — press Ctrl+C to stop\n", iface);
  int rc = capture_run(on_packet, on_tick, NULL);

  flowtrack_destroy(ft);
  capture_close();
  printf("\ncapture stopped.\n");
  return rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
