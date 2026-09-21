#include "capture.h"

#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static pcap_t *g_pcap = NULL;

/* Bundled together so the single libpcap callback can reach both the
 * caller's handler and their context without a global for user_ctx. */
struct dispatch_ctx {
  packet_handler_fn handler;
  void *user_ctx;
};

int capture_init(const char *iface, char *errbuf_out) {
  char errbuf[PCAP_ERRBUF_SIZE] = {0};

  /* snaplen 262144: enough for any packet incl. jumbo frames.
   * promisc = 1: see traffic not addressed to this host directly,
   *              which is required to observe other devices on the
   *              segment from a single vantage point.
   * timeout = 1000ms: batches deliveries; fine for a single-threaded
   *              loop where we don't need microsecond latency yet. */
  g_pcap = pcap_open_live(iface, 262144, 1, 1000, errbuf);
  if (!g_pcap) {
    if (errbuf_out)
      snprintf(errbuf_out, PCAP_ERRBUF_SIZE, "%s", errbuf);
    return -1;
  }

  if (pcap_datalink(g_pcap) != DLT_EN10MB) {
    if (errbuf_out) {
      snprintf(errbuf_out, PCAP_ERRBUF_SIZE,
               "interface %s is not Ethernet (DLT %d) - only "
               "Ethernet capture is supported right now",
               iface, pcap_datalink(g_pcap));
    }
    pcap_close(g_pcap);
    g_pcap = NULL;
    return -1;
  }

  return 0;
}

/* Parses one raw frame into packet_info_t. Returns 0 if it was an
 * IPv4 packet we understood, -1 if it should be skipped (non-IPv4,
 * truncated, etc.) — IDS logic only needs IPv4 for now. */
static int parse_packet(const struct pcap_pkthdr *hdr, const u_char *bytes,
                        packet_info_t *out) {
  if (hdr->caplen < sizeof(struct ether_header))
    return -1;

  const struct ether_header *eth = (const struct ether_header *)bytes;
  if (ntohs(eth->ether_type) != ETHERTYPE_IP)
    return -1; /* skip ARP, IPv6, etc. for now */

  size_t offset = sizeof(struct ether_header);
  if (hdr->caplen < offset + sizeof(struct ip))
    return -1;

  const struct ip *iph = (const struct ip *)(bytes + offset);
  size_t ip_hlen = iph->ip_hl * 4u;
  if (ip_hlen < sizeof(struct ip) || hdr->caplen < offset + ip_hlen)
    return -1;

  memset(out, 0, sizeof(*out));
  out->ts = hdr->ts;
  out->src_ip = iph->ip_src;
  out->dst_ip = iph->ip_dst;
  out->length = hdr->len;

  size_t l4_offset = offset + ip_hlen;

  switch (iph->ip_p) {
  case IPPROTO_TCP: {
    if (hdr->caplen < l4_offset + sizeof(struct tcphdr))
      break;
    const struct tcphdr *tcph = (const struct tcphdr *)(bytes + l4_offset);
    out->proto = PROTO_TCP;
    out->src_port = ntohs(tcph->th_sport);
    out->dst_port = ntohs(tcph->th_dport);
    out->tcp_syn = (tcph->th_flags & TH_SYN) ? 1 : 0;
    out->tcp_ack = (tcph->th_flags & TH_ACK) ? 1 : 0;
    break;
  }
  case IPPROTO_UDP: {
    if (hdr->caplen < l4_offset + sizeof(struct udphdr))
      break;
    const struct udphdr *udph = (const struct udphdr *)(bytes + l4_offset);
    out->proto = PROTO_UDP;
    out->src_port = ntohs(udph->uh_sport);
    out->dst_port = ntohs(udph->uh_dport);
    break;
  }
  case IPPROTO_ICMP:
    out->proto = PROTO_ICMP;
    break;
  default:
    out->proto = PROTO_OTHER;
    break;
  }

  return 0;
}

/* libpcap's required callback signature; we adapt it to packet_handler_fn. */
static void pcap_callback(u_char *user, const struct pcap_pkthdr *hdr,
                          const u_char *bytes) {
  struct dispatch_ctx *ctx = (struct dispatch_ctx *)user;
  packet_info_t pkt;

  if (parse_packet(hdr, bytes, &pkt) != 0)
    return; /* not IPv4, skip */
  ctx->handler(ctx->user_ctx, &pkt);
}

int capture_run(packet_handler_fn on_packet, tick_handler_fn on_tick,
                void *user_ctx) {
  if (!g_pcap) {
    fprintf(stderr, "capture_run: capture_init() was not called\n");
    return -1;
  }

  struct dispatch_ctx ctx = {.handler = on_packet, .user_ctx = user_ctx};
  time_t last_tick = time(NULL);

  for (;;) {
    /* Processes whatever packets are ready, then returns - either
     * because it read the timeout we set in pcap_open_live() with
     * nothing arriving, or because it drained what was available. */
    int rc = pcap_dispatch(g_pcap, -1, pcap_callback, (u_char *)&ctx);

    if (rc == -2)
      break; /* capture_stop() -> pcap_breakloop() was called */
    if (rc == -1) {
      fprintf(stderr, "pcap_dispatch error: %s\n", pcap_geterr(g_pcap));
      return -1;
    }

    time_t now = time(NULL);
    if (on_tick && now != last_tick) {
      on_tick(user_ctx);
      last_tick = now;
    }
  }
  return 0;

  /* pcap_loop(..., -1, ...) loops until an error or pcap_breakloop()
   * (called from capture_stop()) — this is the "block here forever"
   * step in our single-threaded pipeline. */
  // int rc = pcap_loop(g_pcap, -1, pcap_callback, (u_char *)&ctx);
  // if (rc == -1) {
  //   fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(g_pcap));
  //   return -1;
  // }
  // return 0; /* rc == -2 means capture_stop() was called; treat as clean exit
  // */
}

void capture_stop(void) {
  if (g_pcap)
    pcap_breakloop(g_pcap);
}

void capture_close(void) {
  if (g_pcap) {
    pcap_close(g_pcap);
    g_pcap = NULL;
  }
}
