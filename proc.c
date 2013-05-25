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
void parse_target_args(char* arg,struct btproc *bt)
{
  char *arg_wr;
  int len;
  int num_args;
  int i;
  char *dup_args = strdup(arg);
  num_args=0;
  arg_wr = strtok(dup_args,",");
  while(arg_wr)
    {
      arg_wr = strtok(NULL,",");
      num_args++;
    }
  
  
  bt->proc_arguments = (char**)malloc(num_args+2);
  if(!bt->proc_arguments)
    {
      printf("line : %d,parse_target_args() : error allocation\n",__LINE__);
    }
	
  
  
  bt->proc_arguments[0] = (char*)malloc(strlen(bt->exec)+1);
  if(!bt->proc_arguments[0])
    {
      printf("line : %d,parse_target_args() : error allocation\n",__LINE__);
    }
  bt->proc_arguments[0] = strdup(bt->exec);


  arg_wr = strtok(arg,",");
  i=1;
  while(arg_wr != NULL)
    {
      
      len = strlen(arg_wr);
      bt->proc_arguments[i]=(char*)malloc(len);
      if(!bt->proc_arguments[i])
	{
	  printf("file : %s ,line : %d,parse_target_args() : error allocation\n",__FILE__,__LINE__);	  
	}
      bt->proc_arguments[i]=strdup(arg_wr);
      
      arg_wr = strtok(NULL,",");
      
      i++;
    }
  
  

#if 0
  for(i=0;bt->proc_arguments[i];i++)
    printf("%s\n",bt->proc_arguments[i]);
#endif

}

struct btproc *bt_proc_init()
{
  struct btproc *bt;
  bt = (struct btproc *)xmalloc(sizeof(struct btproc));
  if(!bt)
    return NULL;
  bt->pi = (struct procinfo *)xmalloc(sizeof(struct procinfo));
  //bt->exec = (char*)malloc(MAX_EXEC_SIZE);
  bt->proc_arguments = NULL;
  bt->args_parser = parse_target_args;
  
  return bt;
}

u_char *check_target_path(u_char *target){
  u_char *vtarget=(u_char*)malloc(strlen(target)+1);
  char *env_path;
  int npath; /* number of path*/
  char *arg_wr;
if(!vtarget){
    printf("line %d,check_target_path():malloc\n",__LINE__);
    return NULL;
  }
  int i,j=0;

  memset(vtarget,0,strlen(target)+1);
  
  while(i <= strlen(target)){
    if(target[i]=='.')
      i++;
    else
      *(vtarget+j++)=*(target+i++);
  }
  
  env_path = getenv("PATH");
  
  
  
#if 1
  printf("exec :%s\n",vtarget);
  printf("path :%s\n",env_path);
#endif
}


