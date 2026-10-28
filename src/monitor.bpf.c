// clang-format off
#include "../include/vmlinux.h"
#include "../include/monitor.h"

#include <bpf/bpf_helpers.h>
// #include <bpf/bpf_tracing.h>
// #include <linux/bpf.h>
// clang-format on

char LICENSE[] SEC("license") = "GPL";

// Ring buffer
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 4096); // 1MB
} rb SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, struct conn_key);
  __type(value, struct conn_stats);
} conn_map SEC(".maps");

// Attach code
SEC("tp/tcp/tcp_probe")
int handle_tcp_probe(struct trace_event_raw_tcp_probe *ctx) {
  struct conn_key key;
  struct conn_stats *val;

  __builtin_memset(&key, 0, sizeof(key));

  key.pid = bpf_get_current_pid_tgid() >> 32;
  key.sport = ctx->sport;
  key.dport = ctx->dport;
  bpf_probe_read_kernel(key.saddr, sizeof(key.saddr), ctx->saddr);
  bpf_probe_read_kernel(key.daddr, sizeof(key.daddr), ctx->daddr);

  val = bpf_map_lookup_elem(&conn_map, &key);
  if (!val) {
    struct conn_stats initial_stats = {
        .packet_count = 1,
        .total_bytes = ctx->data_len,
        .last_seen_timestamp = bpf_ktime_get_ns(),
    };
    bpf_map_update_elem(&conn_map, &key, &initial_stats, BPF_ANY);
  } else {
    val->packet_count++;
    val->total_bytes += ctx->data_len;
    val->last_seen_timestamp = bpf_ktime_get_ns();
  }

  // bpf_ringbuf_output(&rb, val, sizeof(*val), 0);
  return 0;
}
