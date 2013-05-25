#include <stdio.h>
#include <stdlib.h>
#include "proc.h"
#include "utils.h"

/* initialise process info data structure 
 * Success : return a valid pinfo pointer
 * Failure : returns NULL
 */
struct procinfo *pinfo_init()
{
  struct procinfo *pi;
  pi = xmalloc(sizeof(struct procinfo));
  pi->pi_pid=0;
  pi->pi_target = NULL ;	/* we'll reserve a space for
				 * this later ! */
  pi->pi_address = 0;
  pi->pi_data = NULL;		/* we'll figure it out later */
  pi->pi_map[0]=pi->pi_map[1]=0;
  pi->pi_offset =0;
  pi->pi_perm = (struct perms *)xmalloc(sizeof(struct perms));
  /* initialise permission with NULL values */
  pi->pi_perm->p_read = 0;
  pi->pi_perm->p_write= 0;
  pi->pi_perm->p_exec = 0;

  return pi;
}
void parse_target_args(struct btproc *bt)
{}

struct btproc *bt_proc_init()
{
  struct btproc *bt;
  bt = (struct btproc *)xmalloc(sizeof(struct btproc));
  if(!bt)
    return NULL;

  bt->exec = (char*)malloc(MAX_EXEC_SIZE);
  bt->proc_arguments = NULL;
  bt->args_parser = parse_target_args;
  
  return bt;
}


