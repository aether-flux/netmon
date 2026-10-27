#ifndef MONITOR_H
#define MONITOR_H

// #include "vmlinux.h"

struct event {
  unsigned int pid;
  char comm[16];
  unsigned short sport;
  unsigned short dport;
  unsigned char saddr[28];
  unsigned char daddr[28];
};

#endif // !MONITOR_H
