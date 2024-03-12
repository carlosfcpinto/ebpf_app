// SPDX-License-Identifier: BSD-3-Clause
// clang-format-off
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "file_open.h"
#include <asm-generic/errno-base.h>
#include <linux/limits.h>
// clang-format-on

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define EFAULT 14 /* Bad address */

#define MAX_PATH_SIZE 4096 // PATH_MAX from <linux/limits.h>
#define LIMIT_PATH_SIZE(x) ((x) & (MAX_PATH_SIZE - 1))
#define MAX_PATH_COMPONENTS 20

#define MAX_PERCPU_ARRAY_SIZE (1 << 15)
#define HALF_PERCPU_ARRAY_SIZE (MAX_PERCPU_ARRAY_SIZE >> 1)
#define LIMIT_PERCPU_ARRAY_SIZE(x) ((x) & (MAX_PERCPU_ARRAY_SIZE - 1))
#define LIMIT_HALF_PERCPU_ARRAY_SIZE(x) ((x) & (HALF_PERCPU_ARRAY_SIZE - 1))
#define statfunc static __always_inline

struct buffer {
  u8 data[MAX_PERCPU_ARRAY_SIZE];
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, struct buffer);
  __uint(max_entries, 1);
} heaps_map SEC(".maps");

statfunc struct buffer *get_buffer() {
  u32 zero = 0;
  return (struct buffer *)bpf_map_lookup_elem(&heaps_map, &zero);
}

// based in
// https://github.com/aquasecurity/tracee/blob/a6118678c6908c74d6ee26ca9183e99932d098c9/pkg/ebpf/c/common/filesystem.h#L160

statfunc long get_path_str_from_path(u_char **path_str, const struct path *path,
                                     struct buffer *out_buf) {
  long ret;
  struct dentry *dentry, *dentry_parent, *dentry_mnt;
  struct vfsmount *vfsmnt;
  struct mount *mnt, *mnt_parent;
  const u_char *name;
  size_t name_len;

  dentry = BPF_CORE_READ(path, dentry);
  vfsmnt = BPF_CORE_READ(path, mnt);
  mnt = container_of(vfsmnt, struct mount, mnt);
  mnt_parent = BPF_CORE_READ(mnt, mnt_parent);

  size_t buf_off = HALF_PERCPU_ARRAY_SIZE;

#pragma unroll
  for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {

    dentry_mnt = BPF_CORE_READ(vfsmnt, mnt_root);
    dentry_parent = BPF_CORE_READ(dentry, d_parent);

    if (dentry == dentry_mnt || dentry == dentry_parent) {
      if (dentry != dentry_mnt) {
        // We reached root, but not mount root - escaped?
        break;
      }
      if (mnt != mnt_parent) {
        // We reached root, but not global root - continue with mount point path
        dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
        mnt_parent = BPF_CORE_READ(mnt, mnt_parent);
        vfsmnt = __builtin_preserve_access_index(&mnt->mnt);
        continue;
      }
      // Global root - path fully parsed
      break;
    }

    // Add this dentry name to path
    name_len = LIMIT_PATH_SIZE(BPF_CORE_READ(dentry, d_name.len));
    name = BPF_CORE_READ(dentry, d_name.name);

    name_len = name_len + 1; // add slash
    // Is string buffer big enough for dentry name?
    if (name_len > buf_off) {
      break;
    }
    volatile size_t new_buff_offset = buf_off - name_len; // satisfy verifier
    ret =
        bpf_probe_read_kernel_str(&(out_buf->data[LIMIT_HALF_PERCPU_ARRAY_SIZE(
                                      new_buff_offset) // satisfy verifier
    ]),
                                  name_len, name);
    if (ret < 0) {
      return ret;
    }

    if (ret > 1) {
      buf_off -= 1; // remove null byte termination with slash sign
      buf_off = LIMIT_HALF_PERCPU_ARRAY_SIZE(buf_off); // satisfy verifier
      out_buf->data[buf_off] = '/';
      buf_off -= ret - 1;
      buf_off = LIMIT_HALF_PERCPU_ARRAY_SIZE(buf_off); // satisfy verifier
    } else {
      // If sz is 0 or 1 we have an error (path can't be null nor an empty
      // string)
      break;
    }
    dentry = dentry_parent;
  }

  // Is string buffer big enough for slash?
  if (buf_off != 0) {
    // Add leading slash
    buf_off -= 1;
    buf_off = LIMIT_HALF_PERCPU_ARRAY_SIZE(buf_off); // satisfy verifier
    out_buf->data[buf_off] = '/';
  }

  // Null terminate the path string
  out_buf->data[HALF_PERCPU_ARRAY_SIZE - 1] = 0;
  *path_str = &out_buf->data[buf_off];
  return HALF_PERCPU_ARRAY_SIZE - buf_off - 1;
}

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(u32));
  __uint(value_size, sizeof(u32));
} output SEC(".maps");
// Ringbuffer Map to pass messages from kernel to user
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// Map to fold the dents buffer addresses
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, size_t);
  __type(value, long unsigned int);
} map_buffs SEC(".maps");

// map to store directories to not be allowed access, max size of 100 chars
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, u8[100]);
  __type(value, u32);
} directories SEC(".maps");

// map to store users to be allowed access to the directories stored in
// directories map
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, u32);
  __type(value, struct msg_t);
} my_config SEC(".maps");

SEC("lsm/file_open")
int BPF_PROG(file_open, struct file *file) {
  struct msg_t *p;
  u32 *directory_flag;
  struct pairing x;
  int uid;

  uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

  struct buffer *string_buf = get_buffer();
  if (string_buf == NULL) {
    bpf_printk("string_buf is null");
    return 0;
  }

  u8 *file_path;
  get_path_str_from_path(&file_path, &file->f_path, string_buf);

  x.uid = uid;

  bpf_core_read(x.path, sizeof(x.path), file_path);
  bpf_printk("x.uid? %d", x.uid);
  bpf_printk("buffer? %s", string_buf->data);
  bpf_printk("x.path? \"%s\"", x.path);
  bpf_printk("size of dir: %d ", sizeof(file_path));

  p = bpf_map_lookup_elem(&my_config, &x.uid);
  directory_flag = bpf_map_lookup_elem(&directories, &x.path);
  if (p != 0) {
    /* bpf_printk("This user %d", uid);
    bpf_printk("File_open allowed to %s", file_path); */
    return 0;
  } else {
    if (directory_flag != 0) {
      if (*directory_flag == uid) {
        bpf_printk("user %d does not have access to file", uid);
        return -EPERM;
      }
      bpf_printk("Aux not empty %d -> %d\n ", uid, *directory_flag);
      bpf_printk("File_open allowed to %s %d", file_path, uid);
      return 0;
    } else {
      /* bpf_printk("aux is empty");
      bpf_printk("file_open allowed to %s %d", file_path, uid); */
      return 0;
    }
  }

  bpf_printk("what is going on?");
  return 0;
}
