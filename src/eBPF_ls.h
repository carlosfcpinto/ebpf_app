#include <linux/limits.h>
// #include <vmlinux.h>

struct data_t {
  int pid;
  int uid;
  char command[16];
  // char message[12];
  char path[100];
};

struct pairing {
  int uid;
  // char path[PATH_MAX];
  unsigned char path[100];
};

struct msg_t {
  char message[12];
};
