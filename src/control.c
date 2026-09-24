#include "control.h"

#include <arpa/inet.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#define NFT_TABLE "netsentry"
#define NFT_CHAIN "block_in"
#define NFT_SET "blocked_ips"

/* Builds a command from `fmt` + varargs and runs it via system().
 *
 * Using system() to shell out - rather than fork()/execve() directly
 * to /usr/sbin/nft - is only safe here because of something worth
 * understanding, not just accepting: every value we ever substitute
 * into `fmt` is either a fixed string literal (the table/chain/set
 * names above) or an IPv4 address WE generated ourselves via
 * inet_ntop(). inet_ntop() can only ever produce digits and dots -
 * in is structurally incapable of emitting a semicolon, backtick, or
 * `; rm -rf /` style payload. If any value here ever came from
 * outside our own program - a config file, a command-line argument,
 * anything network-supplied - system() would become a command
 * injection vulnerability and fork()+execve() (which never invokes a
 * shell at all) would be the only safe choice. Worth stating this
 * reasoning explicitly in my thesis if I discuss the control
 * module's security properties.*/
static int run_nft(const char *fmt, ...) {
  char cmd[256];
  va_list args;
  va_start(args, fmt);
  vsnprintf(cmd, sizeof(cmd), fmt, args);
  va_end(args);

  int rc = system(cmd);
  if (rc != 0) {
    fprintf(stderr, "nft command failed (rc=%d): %s\n", rc, cmd);
    return -1;
  }
  return 0;
}

int control_init(void) {
  printf("[control] initializing nftables table %s\n", NFT_TABLE);
  /* Best-effort cleanup in case a previous run crashed instead of
   * calling control_teardown() and left the table behind. Not
   * checked for success - "nothing to delete" in expected and
   * fine on a fresh system, so we send its own errors to
   * /dev/null rather than treating them as failures.*/
  system("nft delete table inet " NFT_TABLE " 2>/dev/null");

  if (run_nft("nft add table inet %s", NFT_TABLE) != 0)
    return -1;

  /* The "\\;" here becomes "\;" in the actual shell command - the
   * backslash is required because system() runs this string
   * through /bin/sh, and nft's own syntax uses literal semicolons
   * inside { } blocks. Without escaping, the shell itself would
   * treat that semicolon as a command separator and split this
   * into two broken commands.*/
  if (run_nft("nft add chain inet %s %s "
              "{ type filter hook input priority 0 \\; }",
              NFT_TABLE, NFT_CHAIN) != 0)
    return -1;

  if (run_nft("nft add set inet %s %s "
              "{ type ipv4_addr\\; flags timeout\\; }",
              NFT_TABLE, NFT_SET) != 0)
    return -1;

  if (run_nft("nft add rule inet %s %s ip saddr @%s drop", NFT_TABLE, NFT_CHAIN,
              NFT_SET) != 0)
    return -1;

  return 0;
}

int control_block(struct in_addr ip, int timeout_secs) {
  printf("[control] blocking %s for %d seconds\n", inet_ntoa(ip), timeout_secs);
  char ip_str[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str));

  return run_nft("nft add element inet %s %s { %s timeout %ds }", NFT_TABLE,
                 NFT_SET, ip_str, timeout_secs);
}

int control_unblock(struct in_addr ip) {
  printf("[control] unblocking %s\n", inet_ntoa(ip));
  char ip_str[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str));

  return run_nft("nft delete element inet %s %s { %s }", NFT_TABLE, NFT_SET,
                 ip_str);
}

void control_teardown(void) {
  printf("[control] tearing down nftables table %s\n", NFT_TABLE);
  system("nft delete table inet " NFT_TABLE " 2>//dev/null");
}
