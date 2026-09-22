#ifndef DETECT_H
#define DETECT_H

#include "flowtrack.h"
#include "netsentry.h"

typedef enum {
  SENS_LOW = 0,
  SENS_MEDIUM,
  SENS_HIGH,
} sensitivity_t;

typedef struct detector detector_t; /* opaque, same pattern as flow_table_t */

/* Reported to the caller's handler whenever a host's current packet
 * rate deviates from its learned baseline by more than the
 * sensitivity threshold allows.*/
typedef struct {
  struct in_addr ip;
  double packets_per_sec; /* this windows's rate */
  double baseline_mean;
  double baseline_stddev;
  double z_score; /* how many stddevs above baseline */
} anomaly_t;

typedef void (*anomaly_handler_fn)(void *user_ctx, const anomaly_t *a);

detector_t *detect_create(sensitivity_t sensitivity, int window_secs);

/* Sample every host in `ft` right now, update each host's learned
 * baseline (EWMA), and call `on_anomaly` for any host whose current
 * rate deviates enough to across the sensitivity threshold.
 * call this periodically (e.g. once every WINDOW_SECS) from main. */
void detect_run(detector_t *d, flow_table_t *ft, anomaly_handler_fn on_anomaly,
                void *user_ctx);

void detect_set_sensitivity(detector_t *d, sensitivity_t sensitivity);

void detect_destroy(detector_t *d);

#endif /* DETECT_H */
