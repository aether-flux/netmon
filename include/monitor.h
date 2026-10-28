#ifndef MONITOR_H
#define MONITOR_H

// #include <linux/types.h>

struct conn_key {
  unsigned int pid;
  unsigned short sport;
  unsigned short dport;
  unsigned short saddr[16];
  unsigned short daddr[16];
} __attribute__((packed));

struct conn_stats {
  unsigned long long packet_count;
  unsigned long long total_bytes;
  unsigned long long last_seen_timestamp;
};

#endif // MONITOR_H
