#include "detect.h"
#include "flowtrack.h"

#include <arpa/inet.h>
#include <math.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define HASH_BUCKETS 1024
#define ALPHA 0.2 /* EWMA smoothing factor: how ast the baseline adapts */
#define MIN_SAMPLES_BEFORE_ALERTING 5

/* One host's learned "normal" behavior, updated a little on every
 * sample (EWMA = exponentially weighted moving average) rather than
 * recomputed from scratch - so it adapts to slow, legitimate changes
 * in traffic without needing to store history. */
typedef struct baseline_entry {
  struct in_addr ip;
  int initialized;  /* have we seen a first sample? */
  int sample_count; /* how many samples we've folded in */
  double mean;      /* running average packets/sec */
  double var;       /* running variance estimate */
  struct baseline_entry *next;
} baseline_entry_t;

struct detector {
  baseline_entry_t *slots[HASH_BUCKETS];
  sensitivity_t sensitivity;
  int window_secs;
};

/* Same hash function as flowtrack.c Duplicated on purpose for now -
 * two small independent modules - but worth fatoring into a shared
 * hash_ip() in its own file later if a third module needs it too. */
static unsigned hash_ip(struct in_addr ip) {
  uint32_t h = ip.s_addr * 2654435761u;
  return h % HASH_BUCKETS;
}

static baseline_entry_t *lookup_baseline(detector_t *d, struct in_addr ip) {
  unsigned idx = hash_ip(ip);
  for (baseline_entry_t *e = d->slots[idx]; e != NULL; e = e->next) {
    if (e->ip.s_addr == ip.s_addr)
      return e;
  }

  baseline_entry_t *e = calloc(1, sizeof(*e));
  if (!e)
    return NULL;
  e->ip = ip;
  e->next = d->slots[idx];
  d->slots[idx] = e;
  return e;
}

/* Higher sensitivity -> lower threshold -> flags smaller deviations. */
static double threshold_for(sensitivity_t s) {
  switch (s) {
  case SENS_HIGH:
    return 2.0;
  case SENS_MEDIUM:
    return 3.0;
  case SENS_LOW:
    return 4.0;
  default:
    return 3.0;
  }
};

/* Bundles what visit_host needs, since flowtrack_foreach only passes
 * a single void* through to its callback. */
typedef struct {
  detector_t *d;
  anomaly_handler_fn on_anomaly;
  void *user_ctx;
} run_ctx_t;

static void visit_host(void *ctx_v, struct in_addr ip,
                       const flow_stats_t *stats) {
  printf("[detect] visit_host: ip=%s packets=%llu bytes=%llu syn=%llu\n",
         inet_ntoa(ip), (unsigned long long)stats->packets,
         (unsigned long long)stats->bytes,
         (unsigned long long)stats->syn_count);
  run_ctx_t *ctx = (run_ctx_t *)ctx_v;
  detector_t *d = ctx->d;

  double rate = (double)stats->packets / (double)d->window_secs;

  baseline_entry_t *e = lookup_baseline(d, ip);
  if (!e)
    return; /* allocation failure - skip this host this round */

  if (!e->initialized) {
    /* First time seeing this host: nothing to compare agaisnt
     * yet. so just record ti as the starting baseline.*/
    e->mean = rate;
    e->var = 0.0;
    e->initialized = 1;
    e->sample_count = 1;
    return;
  }

  double stddev = sqrt(e->var);
  /* A host with perfectly steady traffic has stddev == 0, which
   * would make any tiny wobble divide-by-zero into "infinite"
   * deviation. Flooring it keeps the math sane without needing a
   * special case in the comparison below.*/
  double safe_stddev = (stddev < 1e-6) ? 1e-6 : stddev;
  double z = (rate - e->mean) / safe_stddev;

  // debugging
  char dbg_ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &ip, dbg_ip, sizeof(dbg_ip));
  printf("[detect] %-15s rate=%.1f mean=%.1f stddev=%.1f z=%.2f\n", dbg_ip,
         rate, e->mean, stddev, z);

  if (e->sample_count >= MIN_SAMPLES_BEFORE_ALERTING &&
      z > threshold_for(d->sensitivity)) {
    anomaly_t a = {.ip = ip,
                   .packets_per_sec = rate,
                   .baseline_mean = e->mean,
                   .baseline_stddev = stddev,
                   .z_score = z};
    ctx->on_anomaly(ctx->user_ctx, &a);
  }

  /* Update the baseline AFTER comparing this sample agaisnt it -
   * otherwise a spike would immediately drag its own mean/stddev
   * upward and could mask itself before on_anomaly ever fires. */
  double delta = rate - e->mean;
  e->mean += ALPHA * delta;
  e->var = (1.0 - ALPHA) * (e->var + ALPHA * delta * delta);
  if (e->sample_count < MIN_SAMPLES_BEFORE_ALERTING)
    e->sample_count++;
}

detector_t *detect_create(sensitivity_t sensitivity, int window_secs) {
  detector_t *d = calloc(1, sizeof(*d));
  if (!d)
    return NULL;
  d->sensitivity = sensitivity;
  d->window_secs = window_secs;
  return d;
}

void detect_run(detector_t *d, flow_table_t *ft, anomaly_handler_fn on_anomaly,
                void *user_ctx) {
  run_ctx_t ctx = {.d = d, .on_anomaly = on_anomaly, .user_ctx = user_ctx};
  printf("[detect_run] run: sensitivity=%d window_secs=%d\n", d->sensitivity,
         d->window_secs);
  flowtrack_foreach(ft, visit_host, &ctx);
}

void detect_set_sensitivity(detector_t *d, sensitivity_t sensitivity) {
  d->sensitivity = sensitivity;
}

void detect_destroy(detector_t *d) {
  if (!d)
    return;
  for (int i = 0; i < HASH_BUCKETS; i++) {
    baseline_entry_t *e = d->slots[i];
    while (e) {
      baseline_entry_t *next = e->next;
      free(e);
      e = next;
    }
  }
  free(d);
}
