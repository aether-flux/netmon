#include "../include/monitor.h"
#include "../include/vmlinux.h"

#include <bpf/bpf_helpers.h>
// #include <linux/bpf.h>

char LICENSE[] SEC("license") = "GPL";

// Ring buffer
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 4096); // 1MB
} rb SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, int);
  __type(value, struct event);
} heap SEC(".maps");

// Attach code
SEC("tp/tcp/tcp_probe")
int handle_tcp_probe(struct trace_event_raw_tcp_probe *ctx) {
  unsigned char *saddr = ctx->saddr;
  struct event *e;
  int zero = 0;

  e = bpf_map_lookup_elem(&heap, &zero);
  if (!e) // can't happen
    return 0;

  e->pid = bpf_get_current_pid_tgid() >> 32;
  bpf_get_current_comm(&e->comm, sizeof(e->comm));
  e->sport = ctx->sport;
  e->dport = ctx->dport;

  bpf_probe_read_kernel(e->saddr, sizeof(e->saddr), ctx->saddr);
  bpf_probe_read_kernel(e->daddr, sizeof(e->daddr), ctx->daddr);

  bpf_ringbuf_output(&rb, e, sizeof(*e), 0);
  return 0;
}
