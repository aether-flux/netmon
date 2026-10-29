#ifndef MONITOR_H
#define MONITOR_H

// #include "vmlinux.h"

struct conn_key {
  // socket_state state;
  unsigned short sport;
  unsigned short dport;
  unsigned short saddr[16];
  unsigned short daddr[16];
} __attribute__((packed));

struct conn_stats {
  unsigned long long packet_count;
  unsigned long long total_bytes;
  unsigned long long last_seen_timestamp;
  unsigned long long handshake_latency_ns;
  unsigned int state;
};

#endif // MONITOR_H
