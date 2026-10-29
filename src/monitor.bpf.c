/*
 * SPDX-License-Identifier: GPL-3.0
 * netmon - High-performance eBPF network monitor
 * Copyright (C) 2026 Amartya Chowdhury
 */

// clang-format off
#include "../include/vmlinux.h"
#include "../include/monitor.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
// clang-format on

#define AF_INET 2
#define IPPROTO_TCP 6
#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT 2
#define TCP_SYN_RECV 3

char LICENSE[] SEC("license") = "GPL";

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, struct conn_key);
  __type(value, struct conn_stats);
} conn_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, struct conn_key);
  __type(value, __u64);
} start_times SEC(".maps");

// Attach code
SEC("tp/tcp/tcp_probe")
int handle_tcp_probe(struct trace_event_raw_tcp_probe *ctx) {
  struct conn_key key;
  struct conn_stats *val;

  __builtin_memset(&key, 0, sizeof(key));

  key.sport = ctx->sport;
  key.dport = ctx->dport;
  bpf_probe_read_kernel(key.saddr, 16, ctx->saddr);
  bpf_probe_read_kernel(key.daddr, 16, ctx->daddr);

  struct sock *sk = (struct sock *)ctx->skaddr;
  __u8 kernel_state = 0;
  if (sk)
    kernel_state = BPF_CORE_READ(sk, __sk_common.skc_state);

  val = bpf_map_lookup_elem(&conn_map, &key);
  if (!val) {
    struct conn_stats initial_stats = {
        .packet_count = 1,
        .total_bytes = ctx->data_len,
        .last_seen_timestamp = bpf_ktime_get_ns(),
        .handshake_latency_ns = 0,
        .state = kernel_state,
    };
    bpf_map_update_elem(&conn_map, &key, &initial_stats, BPF_ANY);
  } else {
    val->packet_count++;
    val->total_bytes += ctx->data_len;
    val->last_seen_timestamp = bpf_ktime_get_ns();
  }

  return 0;
}

/* Track socket state */
SEC("tp/sock/inet_sock_set_state")
int handle_set_state(struct trace_event_raw_inet_sock_set_state *ctx) {
  // Track only IPv4 TCP sockets
  if (ctx->family != AF_INET || ctx->protocol != IPPROTO_TCP)
    return 0;

  struct conn_key key;
  __builtin_memset(&key, 0, sizeof(key));

  // key.pid = bpf_get_current_pid_tgid() >> 32;
  key.sport = ctx->sport;
  key.dport = ctx->dport;
  bpf_probe_read_kernel(key.saddr, 4, ctx->saddr);
  bpf_probe_read_kernel(key.daddr, 4, ctx->daddr);
  // __builtin_memcpy(key.saddr, ctx->saddr, 4);
  // __builtin_memcpy(key.daddr, ctx->daddr, 4);

  __u64 now = bpf_ktime_get_ns();

  if (ctx->newstate == TCP_SYN_RECV || ctx->newstate == TCP_SYN_SENT) {
    bpf_map_update_elem(&start_times, &key, &now, BPF_ANY);
  } else if (ctx->newstate == TCP_ESTABLISHED) {
    __u64 *start_time = bpf_map_lookup_elem(&start_times, &key);
    __u64 latency = 0;

    if (start_time) {
      latency = now - (*start_time);
      bpf_map_delete_elem(&start_times, &key);
    }

    struct conn_stats *val = bpf_map_lookup_elem(&conn_map, &key);
    if (val) {
      val->state = ctx->newstate;
      if (latency > 0)
        val->handshake_latency_ns = latency;
    } else {
      struct conn_stats val = {
          .packet_count = 0,
          .total_bytes = 0,
          .last_seen_timestamp = now,
          .handshake_latency_ns = latency,
          .state = ctx->newstate,
      };
      bpf_map_update_elem(&conn_map, &key, &val, BPF_ANY);
    }
  } else {
    struct conn_stats *val = bpf_map_lookup_elem(&conn_map, &key);
    if (val)
      val->state = ctx->newstate;
  }

  return 0;
}
