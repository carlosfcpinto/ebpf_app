#include "eBPF_ls.h"
// #include "eBPF_ls.skel.h"
#include ".output/eBPF_ls.skel.h"

// #include "vmlinux.h"
#include <cyaml/cyaml.h>
// #include "../libcyaml-main/include/cyaml/cyaml.h"
#include <bpf/libbpf.h>
#include <dirent.h>
#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <yaml.h>

// Convert UID from into to string with username
char *getUser(int uid) {
  struct passwd *pws;
  pws = getpwuid(uid);
  return pws->pw_name;
}

// struct for storing users to be whitelisted for all calls to chmod
struct uid_struct {
  int uid;
  char **directory;
  unsigned directory_count;
};

// // struct for storing directories to be monitored, being that they are
// // blacklisted by default
// struct directories {
//   const char *name;
//   unsigned char path[100];
//   struct uid_struct *uids;
// };
//
/******************************************************************************
 * CYAML schema to tell libcyaml about both expected YAML and data structure.
 *
 * (Our CYAML schema is just a bunch of static const data.)
 ******************************************************************************/

/* CYAML value schema for entries of the data sequence. */
static const cyaml_schema_value_t string_ptr_schema = {
    CYAML_VALUE_STRING(CYAML_FLAG_POINTER, char, 0, CYAML_UNLIMITED)};

/* CYAML mapping schema fields array for the top level mapping. */
static const cyaml_schema_field_t top_mapping_schema[] = {
    CYAML_FIELD_UINT("uid", CYAML_FLAG_DEFAULT, struct uid_struct, uid),
    CYAML_FIELD_SEQUENCE_COUNT("directory",
                               CYAML_FLAG_POINTER | CYAML_FLAG_OPTIONAL,
                               struct uid_struct, directory, directory_count,
                               &string_ptr_schema, 0, CYAML_UNLIMITED),
    CYAML_FIELD_END};

/* CYAML value schema for the top level mapping. */
static const cyaml_schema_value_t top_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, struct uid_struct,
                        top_mapping_schema),
};

/******************************************************************************
 * Actual code to load and save YAML doc using libcyaml.
 ******************************************************************************/

/* Our CYAML config.
 *
 * If you want to change it between calls, don't make it const.
 *
 * Here we have a very basic config.
 */
static const cyaml_config_t config = {
    .log_fn = cyaml_log,            /* Use the default logging function. */
    .mem_fn = cyaml_mem,            /* Use the default memory allocator. */
    .log_level = CYAML_LOG_WARNING, /* Logging errors and warnings only. */
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
  if (level >= LIBBPF_DEBUG)
    return 0;

  return vfprintf(stderr, format, args);
}

void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz) {
  /*   struct data_t *m = data; */
  struct data_t *m = data;
  char *pad = "{ ";
  if (!strcmp(m->command + strlen(m->command) - 2, "sh")) {
    const char *dir_path = m->path;
    DIR *dir = opendir(dir_path);

    // Check if the directory can be opened
    if (!dir) {
      perror("opendir");
    }

    struct dirent *entry;

    printf("%s: ", getUser(m->uid));
    // Read and print the contents of the directory
    while ((entry = readdir(dir)) != NULL) {
      printf("%s%s", pad, entry->d_name);
      pad = ", ";
    }
    printf("}\n");
    closedir(dir);
    printf("\n\n\n\n");
  }
  // printf("%-6d %-6s %-16s %-46s %s\n", m->pid, getUser(m->uid), m->command,
  //        m->path, m->message);
}

void lost_event(void *ctx, int cpu, long long unsigned int data_sz) {
  printf("lost event\n");
}

int main(int argc, char *argv[]) {
  struct eBPF_ls_bpf *skel;
  int err;
  struct perf_buffer *pb = NULL;

  libbpf_set_print(libbpf_print_fn);

  skel = eBPF_ls_bpf__open_and_load();
  if (!skel) {
    printf("Failed to open BPF object\n");
    return 1;
  }

  // uint32_t key = 1001;
  struct msg_t msg;
  const char *m = "this not allowed";
  strncpy((char *)&msg.message, m, strlen(m));
  struct uid_struct *n;
  enum {
    ARG_PROG_NAME,
    ARG_PATH_IN,
    ARG__COUNT,
  };

  /* Handle args */
  if (argc != ARG__COUNT) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s <INPUT>\n", argv[ARG_PROG_NAME]);
    return EXIT_FAILURE;
  }

  /* Load input file. */
  err = cyaml_load_file(argv[ARG_PATH_IN], &config, &top_schema,
                        (cyaml_data_t **)&n, NULL);
  if (err != CYAML_OK) {
    fprintf(stderr, "ERROR: %s\n", cyaml_strerror(err));
    return EXIT_FAILURE;
  }

  int this = 1000;
  bpf_map__update_elem(skel->maps.my_config, &this, sizeof(this), msg.message,
                       sizeof(msg.message), 0);

  // file to debug
  FILE *fptr;
  fptr = fopen("test.txt", "a");
  unsigned int i = 0;
  unsigned char aux[100];
  /* Use the data. */
  for (i = 0; i < n->directory_count; i++) {
    strncpy(aux, n->directory[i], sizeof(aux));
    // aux = (unsigned char *)n->directory[i];
    bpf_map__update_elem(skel->maps.directories, &aux, sizeof(aux), &n->uid,
                         sizeof(n->uid), 0);
    // fprintf(fptr, "\n\n%s", n->directory[i]);
    // fprintf(fptr, "wtfwtfwtfwtf\n");
  }

  // fprintf(fptr, " %d wtfwtfwtfwtf\n", i);
  // struct pairing x;
  // // unsigned char *str = "/home/test2/this");
  // unsigned char str[100] = "/home/test2/this\0";
  // // bpf_strtol to convert string into long, to facilitate accessing from the
  // // hash map char *str_aux = &str[0];
  // // strcpy(x.path, str);
  // x.uid = 1001;
  //
  // // int z = 12345;
  // bpf_map__update_elem(skel->maps.directories, &str, sizeof(str), &x.uid,
  //                      sizeof(x.uid), 0);
  //
  // struct pairing z;
  // // unsigned char *str = "/home/test2/this");
  // unsigned char str1[100] =
  //     "/home/carlosfcpinto/Documents/thesis/ebpf_app/src/testfile2\0";
  // // bpf_strtol to convert string into long, to facilitate accessing from the
  // // hash map char *str_aux = &str[0];
  // // strcpy(x.path, str);
  // z.uid = 1001;
  //
  // // int z = 12345;
  // bpf_map__update_elem(skel->maps.directories, &str1, sizeof(str1), &z.uid,
  //                      sizeof(z.uid), 0);
  //
  err = eBPF_ls_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
    eBPF_ls_bpf__destroy(skel);
    return 1;
  }

  // handle_event, lost_event and NULL NULL need to be in a struct of type
  // perf_buffer_opts
  // struct perf_buffer_opts pb_aux = {handle_event, lost_event, NULL};
  // struct perf_buffer_opts *pb_opt = &pb_aux;
  pb = perf_buffer__new(bpf_map__fd(skel->maps.output), 8, handle_event,
                        lost_event, NULL, NULL);
  if (!pb) {
    err = -1;
    fprintf(stderr, "Failed to create ring buffer\n");
    eBPF_ls_bpf__destroy(skel);
    return 1;
  }

  while (true) {
    err = perf_buffer__poll(pb, 10000000 /* timeout, ms */);
    // Ctrl-C gives -EINTR
    if (err == -EINTR) {
      err = 0;
      break;
    }
    if (err < 0) {
      printf("Error polling perf buffer: %d\n", err);
      break;
    }
  }

  perf_buffer__free(pb);
  eBPF_ls_bpf__destroy(skel);
  fclose(fptr);
  return -err;
}
