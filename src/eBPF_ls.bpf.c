#include "eBPF_ls.h"
#include "vmlinux.h"
#include <asm-generic/errno-base.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <string.h>

char message[12] = "Hello World";

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

// map uid to a struct with filenames that user cannot change
struct user_msg_t {
  char message[12];
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, u32);
  __type(value, struct msg_t);
} my_config SEC(".maps");

// path_chmod or file_permission
SEC("lsm/path_chmod")
int BPF_PROG(path_chmod, const struct path *path, umode_t mode) {
  struct data_t data = {};
  struct msg_t *p;
  u64 uid;

  data.pid = bpf_get_current_pid_tgid() >> 32;
  uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
  data.uid = uid;

  // ring buffer should be initialized in user side to contain the name of files
  // to be denied access to
  // file is present in path -> dentry -> d_iname

  /* bpf_get_current_comm(&data.command, sizeof(data.command)); */
  /* bpf_probe_read_user_str(&data.path, sizeof(data.path), path->dentry); */

  struct buffer *string_buf = get_buffer();
  if (string_buf == NULL) {
    return 0;
  }
  // struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  // struct file *file = BPF_CORE_READ(task, mm, exe_file);
  // struct path *path_aux = __builtin_preserve_access_index(&file->f_path);
  u_char *file_path = NULL;
  get_path_str_from_path(&file_path, path, string_buf);
  // if (path->dentry->d_op && path->dentry->d_op->d_dname &&
  //     (path->dentry != path->mnt->mnt_root))
  //   buf = path->dentry->d_op->d_dname(path->dentry, buf, 100);
  //
  // read config from map, see if user has restrictions
  p = bpf_map_lookup_elem(&my_config, &data.uid);
  if (p != 0) {
    bpf_printk("This user %d\n", data.uid);
    bpf_printk("Chmod allowed to %s", path->dentry->d_iname);
    return 0;
  } else {
    bpf_printk("This user %d\n", data.uid);
    bpf_printk("Access denied to %s", file_path);

    return -EPERM;
  }

  /*   bpf_perf_event_output(ctx, &output, BPF_F_CURRENT_CPU, &data,
   * sizeof(data)); */
  return 0;
}

SEC("lsm/task_fix_setuid")
int BPF_PROG(setuid, struct cred *new, struct cred *old, int flags) {

  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  struct file *file = BPF_CORE_READ(task, mm, exe_file);
  struct path *path = __builtin_preserve_access_index(&file->f_path);

  struct buffer *string_buf = get_buffer();
  if (string_buf == NULL) {
    return 0;
  }
  u_char *file_path = NULL;
  get_path_str_from_path(&file_path, path, string_buf);
  bpf_printk("sudo access in %s ", file_path);
  bpf_printk("flags: %d ", flags);

  char comm[16];
  bpf_get_current_comm(&comm, sizeof(comm));
  bpf_printk("/n/n/n This command %s ", comm);
  // char new_string[15];
  // bpf_probe_read_str(&new_string, sizeof(new_string), file_path);
  // if (/* (new->uid.val == 1000 && old->suid.val == 1006) ||*/
  //   (new->uid.val == 1000 && old->euid.val == 0 && old->suid.val != 1000)/*
  //   &&
  //     __builtin_memcmp("su\0", comm, 2 * sizeof(char)) == 0 */)
  if (new->uid.val == 1000 && old->euid.val == 0 && old->uid.val != 1000)
    return -EPERM;
  return 0;
}

// SEC("ksyscall/execve")
// int BPF_PROG(exec, const char *pathname, char *const _Nullable argv[],
//              char *const _Nullable envp[]) {
//   char comm[16];
//
//   struct data_t data = {};
//   u64 uid;
//
//   data.pid = bpf_get_current_pid_tgid() >> 32;
//   uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
//   data.uid = uid;
//   bpf_get_current_comm(&comm, sizeof(comm));
//   if (__builtin_memcmp(comm, "su", 2) == 0 && uid == 0) {
//     // Deny the execution of "su" command
//     bpf_printk("sudo access detected in probe ");
//     return -EPERM; // This will cause the "su" command to fail
//   }
//   return 0;
// }
char LICENSE[] SEC("license") = "Dual BSD/GPL";
