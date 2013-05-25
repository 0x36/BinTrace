#if !defined H_PROC_H
#define H_PROC_H
#include <sys/types.h>
#include <inttypes.h>

#define ALLOC_ERR(x)	\
  fprintf(stderr,"%s\n",x); \
  return NULL;

#define WRITE_BYTE(addr,bits) \
  (addr >> bits) & 0xff

#define MEM_EXEC	1
#define MEM_WRITE	2
#define MEM_READ	4

/* set/get memory permissions */
struct perms
{
  u_short p_read:1;
  u_short p_write:1;
  u_short p_exec:1;
  u_char *symb;
};

/* all process infos */
struct procinfo
{
  pid_t pi_pid;
  u_char *pi_target;
  u_long pi_address;
  u_char *pi_data;	/* full content */
  u_long pi_map[2];	/* holds start/end proc maps*/
  u_long pi_offset;
  struct perms *p_perm;
};

struct btproc
{
  u_char *exec;
  struct procinfo *pi;
  char **proc_arguments;    /* used only if we want to execute a binary */
  char** (*args_parser)(struct procinfo*);
};

struct procinfo *pinfo_init();
struct perms *get_mem_perms();
struct btproc *bt_proc_init();
int printfd(int fd,const char* fmt,...);
#endif /* H_PROC_H */
