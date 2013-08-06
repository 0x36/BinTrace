#if !defined H_PROC_H
#define H_PROC_H

#include <sys/types.h>
#include <inttypes.h>
#include <string.h>

#define MAX_EXEC_SIZE	128
#define MEM_EXEC	1
#define MEM_WRITE	2
#define MEM_READ	4

/* set/get memory permissions */
struct perms
{
  u_short p_read:1;
  u_short p_write:1;
  u_short p_exec:1;
  u_short p_exist:1;
  u_char *p_full_path;
  u_char *p_symb;
};

/* all process infos */
struct procinfo
{
  pid_t pi_pid;
  u_char *pi_target;
  u_char *pi_args;
  u_long pi_address;	/* used for --address */
  u_char *pi_data;	/* full content */
  u_long pi_map[2];	/* holds start/end proc maps*/
  u_long pi_saved_offset;
  u_long pi_offset;
  struct perms *pi_perm;
};

struct btproc
{
  u_char *exec;
  struct procinfo *pi;
  char **proc_arguments;    /* used only if we want to execute a binary */
  void (*args_parser)(char*,struct btproc*);
};

struct procinfo *pinfo_init();
struct perms *get_mem_perms();
struct btproc *bt_proc_init();
u_char *check_target_path(u_char*,struct perms*);
static void get_file_permissions(u_char*,struct perms*);
void parse_target_args(char *,struct btproc *);
void bt_proc_destroy(struct btproc*);
void pinfo_destroy(struct procinfo *);
void exec_target(struct btproc *);
void attach_target(struct btproc*);
unsigned char *fetch_data(struct procinfo *);
#endif /* H_PROC_H */
