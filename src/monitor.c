#include <bpf/libbpf.h>
#include <math.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <time.h>

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

static volatile bool exiting = false;
static void handle_sig(int signal) { exiting = true; }

int handle_event(void *ctx, void *data, size_t data_size) {
  const struct event *e = data;
  struct tm *tm;
  char ts[32];
  time_t t;

  time(&t);
  tm = localtime(&t);
  strftime(ts, sizeof(ts), "%H:%M:%S", tm);

  printf("%-8s PID:%-7d COMM:%-16s SPORT:%-5u DPORT:%-5u\n", ts, e->pid,
         e->comm, e->sport, e->dport);
  return 0;
}

// int main(void) {
//   struct ring_buffer *rb = NULL;
//   struct monitor_bpf *skel;
//   int err;
//
//   // libbpf logging callback
//   libbpf_set_print(libbpf_print_fn);
//
//   // bump MEMLOCK rlimits
//   bump_rlimit();
//
//   // handle signals
//   signal(SIGINT, handle_sig);
//   signal(SIGTERM, handle_sig);
//
//   skel = monitor_bpf__open_and_load();
//   if (!skel) {
//     fprintf(stderr, "Failed to open and load BPF skeleton\n");
//     return 1;
//   }
//
//   err = monitor_bpf__attach(skel);
//   if (err) {
//     fprintf(stderr, "Failed to attach BPF skeleton\n");
//     goto cleanup;
//   }
//
//   rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL,
//   NULL); if (!rb) {
//     err = -1;
//     fprintf(stderr, "Failed to create ring buffer\n");
//     goto cleanup;
//   }
//
//   // process events
//   printf("%-8s %-7s %-16s %-5s %-5s\n", "TIME", "PID", "COMM", "SPORT",
//          "DPORT");
//   while (!exiting) {
//     err = ring_buffer__poll(rb, 100);
//     if (err == -EINTR) {
//       err = 0;
//       break;
//     }
//     if (err < 0) {
//       printf("Error polling ring buffer: %d\n", err);
//       break;
//     }
//   }
//
// cleanup:
//   ring_buffer__free(rb);
//   monitor_bpf__destroy(skel);
//   return err < 0 ? -err : 0;
// }

int main(void) {
  struct ring_buffer *rb = NULL;
  struct bpf_object *skel;
  int err;

  // libbpf logging callback
  libbpf_set_print(libbpf_print_fn);

  // bump MEMLOCK rlimits
  bump_rlimit();

  // handle signals
  signal(SIGINT, handle_sig);
  signal(SIGTERM, handle_sig);

  skel = bpf_object__open_file("src/monitor.bpf.o", NULL);
  if (!skel) {
    fprintf(stderr, "Failed to open BPF object\n");
    return 1;
  }
  if (bpf_object__load(skel) < 0) {
    fprintf(stderr, "Failed to load BPF object\n");
    return 1;
  }

  struct bpf_program *prog =
      bpf_object__find_program_by_name(skel, "handle_tcp_probe");
  struct bpf_link *link = bpf_program__attach(prog);
  // err = monitor_bpf__attach(skel);
  if (!link) {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }

  struct bpf_map *map = bpf_object__find_map_by_name(skel, "rb");
  rb = ring_buffer__new(bpf_map__fd(map), handle_event, NULL, NULL);
  if (!rb) {
    err = -1;
    fprintf(stderr, "Failed to create ring buffer\n");
    goto cleanup;
  }

  // process events
  printf("%-8s %-7s %-16s %-5s %-5s\n", "TIME", "PID", "COMM", "SPORT",
         "DPORT");
  while (!exiting) {
    err = ring_buffer__poll(rb, 100);
    if (err == -EINTR) {
      err = 0;
      break;
    }
    if (err < 0) {
      printf("Error polling ring buffer: %d\n", err);
      break;
    }
  }

cleanup:
  ring_buffer__free(rb);
  // monitor_bpf__destroy(skel);
  bpf_object__close(skel);
  return err < 0 ? -err : 0;
}
