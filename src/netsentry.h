#ifndef NETSENTRY_H
#define NETSENTRY_H

#include <stdint.h>
#include <netinet/in.h>
#include <time.h>

/*
 * Shared types for the NetSentry engine.
 *
 * Pipeline (single-threaded):
 *   capture_run() calls pcap_loop(), which invokes on_packet() per packet.
 *   on_packet() fills a `packet_info` and passes it straight to the
 *   flow tracker (added in the next step) — no queue, no worker thread.
 *   Everything happens synchronously inside the pcap callback.
 */

typedef enum {
    PROTO_OTHER = 0,
    PROTO_TCP,
    PROTO_UDP,
    PROTO_ICMP
} l4_proto_t;

/* One parsed packet, filled in by capture.c and consumed by flowtrack.c */
typedef struct {
    struct timeval ts;      /* capture timestamp */
    struct in_addr src_ip;
    struct in_addr dst_ip;
    uint16_t       src_port;   /* 0 if not TCP/UDP */
    uint16_t       dst_port;   /* 0 if not TCP/UDP */
    l4_proto_t     proto;
    uint32_t       length;     /* on-wire length, incl. headers */
    uint8_t        tcp_syn;    /* 1 if TCP SYN flag set (no ACK) */
    uint8_t        tcp_ack;    /* 1 if TCP ACK flag set */
} packet_info_t;

#endif /* NETSENTRY_H */
