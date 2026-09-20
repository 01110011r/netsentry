#include "flowtrack.h"
#include "netsentry.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#define HASH_BUCKETS 1024

/* One second's worth of counters for one host. */
typedef struct {
  uint64_t packets;
  uint64_t bytes;
  uint64_t syn_count;
} time_bucket_t;

/* One tracked host. `next` makes this a singly linked list, because
 * we're using separate chaining to handle hash collisions: mutiple
 * IPs that hash to the same bucket index just get linked together. */
typedef struct flow_entry {
  struct in_addr ip;
  time_bucket_t *buckets;  /* array of window_secs buckets */
  int bucket_count;        /* == ft->window_secs, kept here for convenience */
  int current_index;       /* which bucket represents "this second" */
  time_t last_bucket_time; /* wall-clock second current_index belongs to */
  struct flow_entry *next;
} flow_entry_t;

/* This is the real definition of the type flowtrack.h only forward-
 * declared. Nothing outside ths file can see these fields - caller
 * only ever hold a flow_table_t*, never touch -> slots directly.*/
struct flow_table {
  flow_entry_t *slots[HASH_BUCKETS];
  int window_secs;
};

/* Knuth's mutiplicative hash: spreads sequential/similar IPs (very
 * common on a LAN, e.g. 192.168.1.1, .2, .3...) across buckets much
 * better than `ip % HASH_BUCKETS` would, since consecutive integers
 * mod a table size tend to cluster instead of spreading out. */
static unsigned hash_ip(struct in_addr ip) {
  uint32_t h = ip.s_addr * 2654435761u;
  return h % HASH_BUCKETS;
}

flow_table_t *flowtrack_create(int window_secs) {
  flow_table_t *ft = calloc(1, sizeof(*ft));
  if (!ft)
    return NULL;
  ft->window_secs = window_secs;
  return ft;
  /* calloc zero-initializes -> every ft->slots[i] starts NULL,
   * which is exactly "empty chain" for out linked lists.*/
}

/* Look up the entry for `ip`. If create_if_missing is true and none
 * exists yet, allocate one (with a freshly zeroed bucket array) and
 * link it into its hash slot. Returns NULL only on allocation failure
 * or (when create_if_missing is false) if the IP is simpy unknown.*/
static flow_entry_t *lookup_entry(flow_table_t *ft, struct in_addr ip,
                                  int create_if_missing) {
  unsigned idx = hash_ip(ip);

  for (flow_entry_t *e = ft->slots[idx]; e != NULL; e = e->next) {
    if (e->ip.s_addr == ip.s_addr)
      return e; /* found existing host */
  }

  if (!create_if_missing)
    return NULL;

  flow_entry_t *e = calloc(1, sizeof(*e));
  if (!e)
    return NULL;

  e->buckets = calloc((size_t)ft->window_secs, sizeof(time_bucket_t));
  if (!e->buckets) {
    free(e);
    return NULL;
  }

  e->ip = ip;
  e->bucket_count = ft->window_secs;
  e->current_index = 0;
  e->last_bucket_time = time(NULL); /* "now", refind properly on first update */

  /* insert at head of this slot's chain */
  e->next = ft->slots[idx];
  ft->slots[idx] = e;
  return e;
}

/* Move a host's ring buffer forward to  `now`, zeroing out any
 * buckets that now represent a new second we haven't counted yet.
 *
 * This is what makes it a *sliding* window: instead of storing every
 * packet with a timestamp and filtering old ones out an every query,
 * we let time itself overwrite stale data as it "rotates back around"
 * to a bucket index that's about to be reused.
 */
static void advance_buckets(flow_entry_t *e, time_t now) {
  time_t elapsed = now - e->last_bucket_time;

  if (elapsed <= 0) {
    /* same second as last time (or the clock went backwards,
     * which we just ignore) - nothing to advance. */
    return;
  }

  if (elapsed >= e->bucket_count) {
    /* More time has passed than the whole window covers, so
     * EVERY bucket is stale. Clearing them all in one memset is
     * both correct and for cheaper than looping bucket_count
     * times to reach that same all-zero result.*/
    memset(e->buckets, 0, sizeof(time_bucket_t) * (size_t)e->bucket_count);
    e->current_index = 0;
    e->last_bucket_time = now;
    return;
  }

  /* common case: somewhere between 1 and (bucket_count - 1)
   * seconds passed. Step forward one bucket per elapsed second,
   * zeroing each one as we arrive at it - it now represents a
   * second with no packets counted yet.
   */
  for (time_t i = 1; i < elapsed; i++) {
    e->current_index = (e->current_index + 1) % e->bucket_count;
    e->buckets[e->current_index] = (time_bucket_t){0};
  }

  e->last_bucket_time = now;
}

void flowtrack_update(flow_table_t *ft, const packet_info_t *pkt) {
  flow_entry_t *e = lookup_entry(ft, pkt->src_ip, /*create_if_missing=*/1);
  if (!e)
    return; /* allocation failed - drop the update rather than crash */

  advance_buckets(e, pkt->ts.tv_sec);

  time_bucket_t *cur = &e->buckets[e->current_index];
  cur->packets++;
  cur->bytes += pkt->length;

  if (pkt->proto == PROTO_TCP && pkt->tcp_syn && !pkt->tcp_ack) {
    cur->syn_count++;
  }
}

int flowtrack_get(flow_table_t *ft, struct in_addr ip, flow_stats_t *out) {
  flow_entry_t *e = lookup_entry(ft, ip, /*create_if_missing=*/0);
  if (!e)
    return -1; /*never seen this host */

  /* Bring it up to date first - without this, a host that sent a
   * burst 90 seconds ago and then went silent would still report
   * that old burst's totals as if they happened "just now". */
  advance_buckets(e, time(NULL));

  memset(out, 0, sizeof(*out));
  out->ip = ip;
  for (int i = 0; i < e->bucket_count; i++) {
    out->packets += e->buckets[i].packets;
    out->bytes += e->buckets[i].bytes;
    out->syn_count += e->buckets[i].syn_count;
  }
  return 0;
}

void flowtract_tick(flow_table_t *ft) {
  time_t now = time(NULL);
  for (int i = 0; i < HASH_BUCKETS; i++) {
    for (flow_entry_t *e = ft->slots[i]; e != NULL; e = e->next) {
      advance_buckets(e, now);
    }
  }
}

void flowtrack_destroy(flow_table_t *ft) {
  if (!ft)
    return;
  for (int i = 0; i < HASH_BUCKETS; i++) {
    flow_entry_t *e = ft->slots[i];
    while (e) {
      flow_entry_t *next = e->next;
      free(e->buckets);
      free(e);
      e = next;
    }
  }
  free(ft);
}
