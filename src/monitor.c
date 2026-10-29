#include <bpf/libbpf.h>
#include <math.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
// #include <time.h>
#include <unistd.h>

#include "../include/monitor.h"
#include "../include/monitor.skel.h"

int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                    va_list args) {
  if (level > LIBBPF_INFO)
    return 0;
  return vfprintf(stderr, format, args);
}

void bump_rlimit(void) {
  struct rlimit rlim_new = {
      .rlim_cur = INFINITY,
      .rlim_max = INFINITY,
  };

  if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
    fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit.\n");
    exit(1);
  }
}

const char *state_str(int state) {
  const char *states[] = {"UNKNOWN",     "ESTAB",     "SYN_SENT",  "SYN_RECV",
                          "FIN_WAIT1",   "FIN_WAIT2", "TIME_WAIT", "CLOSE",
                          "CLOSE_WAIT",  "LAST_ACK",  "LISTEN",    "CLOSING",
                          "NEW_SYN_RECV"};
  if (state >= 0 && state <= 12)
    return states[state];
  return "UNKNOWN";
}

static volatile bool exiting = false;
static void handle_sig(int signal) { exiting = true; }

int main(void) {
  struct monitor_bpf *skel;
  int err;
  int map_fd;

  // libbpf logging callback
  libbpf_set_print(libbpf_print_fn);

  // bump MEMLOCK rlimits
  bump_rlimit();

  // handle signals
  signal(SIGINT, handle_sig);
  signal(SIGTERM, handle_sig);

  skel = monitor_bpf__open_and_load();
  if (!skel) {
    fprintf(stderr, "Failed to open and load BPF skeleton\n");
    return 1;
  }

  err = monitor_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }

  map_fd = bpf_map__fd(skel->maps.conn_map);
  if (map_fd < 0) {
    err = -1;
    fprintf(stderr, "Failed to get map FD\n");
    goto cleanup;
  }

  // process events
  while (!exiting) {
    sleep(1);

    printf("\033[H\033[J");
    printf("================================== netmon "
           "================================="
           "\n\n");
    printf("%-15s | %-7s | %-7s | %-12s | %-12s | %-7s\n", "LAST SEEN (ms)",
           "SPORT", "DPORT", "PACKET COUNT", "TOTAL BYTES", "STATE");
    printf("-------------------------------------------------------------------"
           "-------\n");

    struct conn_key cur_key = {};
    struct conn_key next_key;
    struct conn_stats val;

    int lookup_err = bpf_map__get_next_key(skel->maps.conn_map, NULL, &next_key,
                                           sizeof(next_key));
    while (lookup_err == 0) {
      if (bpf_map__lookup_elem(skel->maps.conn_map, &cur_key, sizeof(cur_key),
                               &val, sizeof(val), 0) == 0) {
        double ts_ms = (double)val.last_seen_timestamp / 1000000.0;

        printf("%-15.2f | %-7u | %-7u | %-12llu | %-12llu | %-7s\n", ts_ms,
               next_key.sport, next_key.dport, val.packet_count,
               val.total_bytes, state_str(val.state));
      }

      cur_key = next_key;
      lookup_err = bpf_map__get_next_key(skel->maps.conn_map, &cur_key,
                                         &next_key, sizeof(next_key));
    }
  }

cleanup:
  // ring_buffer__free(rb);
  monitor_bpf__destroy(skel);
  return err < 0 ? -err : 0;
}
