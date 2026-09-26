#include "report.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <time.h>

static FILE *g_log = NULL;

int report_init(const char *log_path) {
  g_log = fopen(log_path, "a");
  if (!g_log) {
    perror("report_init: fopen");
    return -1;
  }

  /* Line-buffered, not the full-buffering fopen() would otherwise
   * pick for a regular file. Without this, a tool tailing the log
   * (or a future dashboard backend) could see nothing for a long
   * time after a real alert, because stdio would be holding
   * finished lines in its own buffer instead of handing them to
   * the OS as soon as each line completes.*/
  setvbuf(g_log, NULL, _IOLBF, 0);
  return 0;
}

/* Every record starts the same way: epoch seconds (easy for other
 * programs to parse/sort) plush a huma-readable string (easy for a
 * person tailing the file to read without doing math in their head).*/
static void write_timestamp_fields(void) {
  time_t now = time(NULL);
  struct tm tm_buf;
  char human[32];
  localtime_r(&now, &tm_buf);
  strftime(human, sizeof(human), "%Y-%m-%d %H:%M:%S", &tm_buf);

  fprintf(g_log, "\"ts\":%ld,\"time\":\"%s\",", (long)now, human);
}

void report_alert(const anomaly_t *a) {
  if (!g_log)
    return;

  char ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &a->ip, ip, sizeof(ip));

  fprintf(g_log, "{");
  write_timestamp_fields();
  fprintf(g_log,
          "\"event\":\"anomaly\",\"ip\":\"%s\","
          "\"rate\":%.2f,\"baseline_mean\":%.2f,"
          "\"baseline_stddev\":%.2f,\"z_score\":%.2f}\n",
          ip, a->packets_per_sec, a->baseline_mean, a->baseline_stddev,
          a->z_score);
}

void report_block(struct in_addr ip_addr, int timeout_secs) {
  if (!g_log)
    return;

  char ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &ip_addr, ip, sizeof(ip));

  fprintf(g_log, "{");
  write_timestamp_fields();
  fprintf(g_log, "\"event\":\"block\",\"ip\":\"%s\",\"timeout_secs\":%d}\n", ip,
          timeout_secs);
}

void report_unblock(struct in_addr ip_addr) {
  if (!g_log)
    return;

  char ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &ip_addr, ip, sizeof(ip));

  fprintf(g_log, "{");
  write_timestamp_fields();
  fprintf(g_log, "\"event\":\"unblock\",\"ip\":\"%s\"}\n", ip);
}

void report_close(void) {
  if (g_log) {
    fclose(g_log);
    g_log = NULL;
  }
}
