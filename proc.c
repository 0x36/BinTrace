#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
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
  
  
  bt->proc_arguments = (char**)xmalloc(num_args+2);
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
  /* we don't use i=0 because it's already reserved for the target*/ 
  i=1;
  while(arg_wr != NULL)
    {
      
      len = strlen(arg_wr);
      bt->proc_arguments[i]=(char*)xmalloc(len);
      if(!bt->proc_arguments[i])
	{
	  printf("file : %s ,line : %d,parse_target_args() : error allocation\n",__FILE__,__LINE__);	  
	}
      bt->proc_arguments[i]=strdup(arg_wr);
      
      arg_wr = strtok(NULL,",");
      
      i++;
    }
  
  

#if 1
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

u_char *check_target_path(u_char *target,struct perms *perms){
  char **dirs;
  u_char *vtarget;
  char *env_path,*path;
  int npath; /* number of path*/
  char *arg_wr,*full_path;
  int found=0; /* check if we found the pathfull_path or not */
  int len; /* len of dir */
  int i,j,k=0;

  vtarget=strdup(target);

  if(!access(target,F_OK)){
    get_file_permissions(target , perms);
    perms->p_full_path = strdup(target);

  }
  else
    {
      while(i <= strlen(target)){
	if(target[i]=='.')
	  i++;
	else
	  *(vtarget+j++)=*(target+i++);
      }
      
      env_path = getenv("PATH");
      path = strdup(env_path);

      /*check number og directories used in path env*/
      npath = 0;
      arg_wr = strtok(env_path,":");
      
      while(arg_wr)
	{
	  full_path = (char*)xmalloc(strlen(arg_wr)+strlen(vtarget)+2);
	  memset(full_path,0,strlen(arg_wr)+strlen(vtarget)+2);
	  strcpy(full_path,arg_wr);
	  strcat(full_path,"/");
	  strcat(full_path,vtarget);

	  if(!access(full_path,F_OK))
	    {
	      found = 1; /* found */
	      //printf("full path : %s\n",full_path);
	      get_file_permissions(full_path , perms);
	      perms->p_full_path = strdup(full_path);
	      
	      break;
	    }
	  arg_wr = strtok(NULL,":");
	  npath++;
	  free(full_path);
	}
      if(!found){
	printf("%s not found !\n",vtarget);
	return NULL;
      }
	
      
    }
  
#if 0
  printf("full path %s\n",perms->p_full_path);  
  printf("exec :%s\n",vtarget);
  printf("path :%s\n",env_path);
  printf("number of dires  : %d\n",npath);
#endif

}


void get_file_permissions(u_char *path,struct perms *p)
{
  printf("path :%s\n",path);
  p->p_read=p->p_write=p->p_exec = 0;
  if(!access(path,W_OK))
    p->p_write|=1;
  
  if(!access(path,R_OK))
    p->p_read|=1;
 
  if(!access(path,X_OK))
    p->p_exec|=1;
  
  /*set symbols */
  p->p_symb = xmalloc(4);
  (p->p_read)?strcat(p->p_symb,"r"):strcat(p->p_symb,"-");
  p->p_write?strcat(p->p_symb,"w"):strcat(p->p_symb,"-");
  (p->p_exec)?strcat(p->p_symb,"x"):strcat(p->p_symb,"-");
#if 0
  
  printf("read :%d , write :%d , exec :%d\n",
	 p->p_read,p->p_write,p->p_exec);
  printf("symbols :%s\n",p->p_symb);
#endif
}
