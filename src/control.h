#ifndef CONTROL_H
#define CONTROL_H

#include <netinet/in.h>

/* Creates a dedicated nftables table/chain/set for NetSentry's
 * dynamic blocking rules. Requirs root (or CAP_NET_ADMIN).
 * Returns 0 on success, -1 on failure.*/
int control_init(void);

/* Adds `ip` to the blocked set for `timeout_secs` seconds. nftables
 * expires the entry itself once the timeout elapses - no polling
 * needed on our side. Returns 0 on success, -1 on failure.*/
int control_block(struct in_addr ip, int timeout_secs);

/* Removes `ip` from the blocked set immediately (manual unblock).
 * Returns 0 on success, -1 on failure.*/
int control_unblock(struct in_addr ip);

/* Deletes the entire dedicated table (every rule/set NetSentry
 * created), so a future control_init() starts from a clean state.*/
void control_teardown(void);

#endif // CONTROL_H
