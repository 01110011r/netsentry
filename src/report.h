#ifndef REPORT_H
#define REPORT_H

#include "detect.h"
#include <netinet/in.h>

/* Opens (creating if needed, appending if it exists) a JSON-lines log
 * file at `log_path`. Other tools can tail/pars it independently
 * while NetSentry keeps running. Returns 0 on success, -1 on failure.*/
int report_init(const char *log_path);

void report_alert(const anomaly_t *a);
void report_block(struct in_addr ip, int timeout_secs);
void report_unblock(struct in_addr ip);

void report_close(void);

#endif /* REPORT_H */
