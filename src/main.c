#include "capture.h"
#include "detect.h"
#include "flowtrack.h"
#include "netsentry.h"

#include <arpa/inet.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#define WINDOW_SECS 60

/* Everything the packet and tick callbacks need to share, bundled so
 * it can travel through capture_run's single void* user_ctx. */
typedef struct {
  flow_table_t *ft;
  detector_t *detector;
  int secs_until_detect; /* counts down; 0 means "run detect_run now" */
} app_ctx_t;

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

static void on_packet(void *ctx_v, const packet_info_t *pkt) {
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

  app_ctx_t *ctx = (app_ctx_t *)ctx_v;

  flowtrack_update(ctx->ft, pkt);

  flow_stats_t stats;
  flowtrack_get(ctx->ft, pkt->src_ip,
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

/* Called by detect_run whenever a host crosses the sensitivity
 * threshold. For now this just prints - control. will hook in here
 * later to actually block the offending host via nftables. */
static void on_anomaly(void *ctx_v, const anomaly_t *a) {
  (void)ctx_v;
  char ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &a->ip, ip, sizeof(ip));

  printf(
      "\n*** NOMALY %-15s rate=%.1f pkt/s baseline=%.1f+-%.1f z=%.2f ***\n\n",
      ip, a->packets_per_sec, a->baseline_mean, a->baseline_stddev, a->z_score);
}

static void on_tick(void *ctx_v) {
  app_ctx_t *ctx = (app_ctx_t *)ctx_v;

  flowtrack_tick(ctx->ft); /* age idle hosts even if nobody queried them */

  ctx->secs_until_detect--;
  if (ctx->secs_until_detect <= 0) {
    detect_run(ctx->detector, ctx->ft, on_anomaly, ctx);
    ctx->secs_until_detect = WINDOW_SECS;
  }
}

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

  app_ctx_t ctx = {0};
  ctx.ft = flowtrack_create(WINDOW_SECS);
  ctx.detector = detect_create(SENS_MEDIUM, WINDOW_SECS);
  ctx.secs_until_detect = WINDOW_SECS;

  if (!ctx.ft || !ctx.detector) {
    fprintf(stderr, "failed to initialize flow table / detector\n");
    capture_close();
    return EXIT_FAILURE;
  }

  signal(SIGINT, handle_sigint);

  printf("NetSentry capture running on '%s' - press Ctrl+C to stop\n", iface);
  printf("(baseline detection runs every %ds; the first pass just learns, "
         "nothing is flagged yet)\n",
         WINDOW_SECS);

  int rc = capture_run(on_packet, on_tick, &ctx);

  detect_destroy(ctx.detector);
  flowtrack_destroy(ctx.ft);
  capture_close();
  printf("\ncapture stopped.\n");
  return rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
