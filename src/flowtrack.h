#ifndef FLOWTRACK_H
#define FLOWTRACK_H

#include "netsentry.h"

/*
 * Pre-source-IP traffic tracking using a sliding window of 1-second
 * buckets (a small ring buffer per host). This lets us answer "how
 * many packets/butes/SYNs has this IP sent in this last N seconds?"
 * cheaply, without storing every packet.
 *
 * The frow_table struct itself is NOT defined here on purpose (this
 * is called an "opeque pointer" / opaque type) - code outside
 * flowtrack.c only ever touches a `flow_table_t *`, never its
 * fields. That keeps the hash table + ring buffer implementation
 * free to change later without breaking anything that includes this
 * header.
 */

typedef struct flow_table flow_table_t;

/* Aggregated stats for one source IP, summed across its window. */
typedef struct {
  struct in_addr ip;
  uint64_t packets;
  uint64_t bytes;
  uint64_t syn_count;
} flow_stats_t;

/* Create a tracker that keeps `window_secs` worth of 1-second buckets
 * per host (e.g. 60 -> a rolling 60-second window). */
flow_table_t *flowtrack_create(int window_secs);

/* Feed one packet in. Creates a new entry for pkt -> src_ip it this is
 * the first time we've seen that host.*/
void flowtrack_update(flow_table_t *ft, const packet_info_t *pkt);

/* Write this host's current window totals into *out.
 * Returns 0 on success, -1 if we have no entry for that IP. */
int flowtrack_get(flow_table_t *ft, struct in_addr ip, flow_stats_t *out);

/* Call one per second from main's loop. Ages every entry's buckets
 * forward even if that host hasn't sent a packet recently, so a
 * burst from 90 seconds ago doesn't linger in the window forever. */
void flowtrack_tick(flow_table_t *ft);

void flowtrack_destroy(flow_table_t *ft);

#endif /* FLOWTRACK_H */
