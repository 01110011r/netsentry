#ifndef CAPTURE_H
#define CAPTURE_H

#include "netsentry.h"

/*
 * capture_init: open `iface` in promiscuous mode with pcap.
 * Returns 0 on success, -1 on failure (message left in errbuf_out,
 * which must be at least PCAP_ERRBUF_SIZE bytes).
 */
int capture_init(const char *iface, char *errbuf_out);

/*
 * capture_run: block in pcap_loop(), calling `on_packet` for every
 * captured packet until capture_stop() is invoked (e.g. from a
 * SIGINT handler) or an error occurs. Single-threaded: this function
 * does not return until capture stops.
 *
 * `user_ctx` is passed through untouched to `on_packet`.
 */
typedef void (*packet_handler_fn)(void *user_ctx, const packet_info_t *pkt);

/* Called once per second (roughly) even if no packets arrived,
 * so periodic bookkeeping (like aging a sliding window) can run. */
typedef void (*tick_handler_fn)(void *user_ctx);

int capture_run(packet_handler_fn on_packet, tick_handler_fn on_tick,
                void *user_ctx);

/* capture_stop: ask the running pcap_loop() to return. Signal-safe. */
void capture_stop(void);

/* capture_close: release pcap resources. */
void capture_close(void);

#endif /* CAPTURE_H */
