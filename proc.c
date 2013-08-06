#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/ptrace.h>

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

u_char *check_target_path(u_char *target,struct perms *perms){
  char **dirs;
  u_char *vtarget;
  char *env_path,*path;
  int npath;		/* number of path*/
  char *arg_wr,*full_path;
  int found=0;		/* check if we found the pathfull_path or not */
  int len;		/* len of dir */
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
	      /*printf("full path : %s\n",full_path);*/

	      get_file_permissions(full_path , perms);
	      perms->p_full_path = strdup(full_path);
	      
	      break;
	    }
	  arg_wr = strtok(NULL,":");
	  npath++;
	  free(full_path);
	}
      if(!found){
	printf(FATAL""RED"%s "NORM":not found !\n",vtarget);
	return NULL;
      }
	
      
    }
  
#if 0
  printf("full path %s\n",perms->p_full_path);  
  printf("exec :%s\n",vtarget);
  printf("path :%s\n",env_path);
  printf("number of dires  : %d\n",npath);
#endif
  return perms->p_full_path;
}

static void get_file_permissions(u_char *path,struct perms *p)
{
  //printf("path :%s\n",path);
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
  printf("read :"GREEN"%d"NORM" , write :"GREEN"%d"NORM" , exec :"GREEN"%d"NORM"\n",
	 p->p_read,p->p_write,p->p_exec);
  printf("symbols :"GREEN"%s"NORM"\n",p->p_symb);
#endif
}


void bt_proc_destroy(struct btproc* bt)
{
  int i;

  if(bt->exec)
    free(bt->exec);

  if(bt->pi)
     pinfo_destroy(bt->pi);

  for(i=0;*(bt->proc_arguments+i);i++)
    free(*(bt->proc_arguments+i));
}

void pinfo_destroy(struct procinfo *pi)
{
  
  pi->pi_pid=pi->pi_address =pi->pi_offset=0;
  memset(pi->pi_map,0,2);
  
  if(pi->pi_target)
    free(pi->pi_target);
  
  if(pi->pi_data)
    free(pi->pi_data);
  /* free permission structure */
  if(pi->pi_perm){
    free(pi->pi_perm->p_full_path);
    free(pi->pi_perm->p_symb);
  }
  
}

/* main function : it handles all process execution */
void exec_target(struct btproc *bt)
{
  pid_t pid;
  struct procinfo *pi;
  long ret;
  int l;

  pi = bt->pi;
  if(!pi){
    printfd(STDERR_FILENO,FATAL"line : %d,exec_target():malloc \n",__LINE__);
    bt_proc_destroy(bt);
    exit(1);
  }

  pid = fork();
  
  /* child */
  if(pid == 0)
    {
      /* tracing the child process */
      ret = ptrace(PTRACE_TRACEME,0,NULL,NULL);
      /* execting our target process */
      execve(bt->exec,bt->proc_arguments,NULL);
      
      if(ret == -1){
	printfd(STDERR_FILENO,FATAL"line : %d,can't trace the process :"RED"%s"NORM"\n",
		__LINE__,strerror(errno));
	bt_proc_destroy(bt);
	exit(1);
      }
    }
  else if (pid == -1)
    {
      printfd(STDERR_FILENO,FATAL"line : %d,can't fork :"RED"%s"NORM"\n",
	      __LINE__,strerror(errno));
      	bt_proc_destroy(bt);
	exit(1);
    }
  else
    {
      wait(NULL);
      /* set pid in process info structure */
      pi->pi_pid = pid;
         
      printfd(STDOUT_FILENO, DO"mapping area : "RED"0x%.08x-0x%.08x\n"NORM,
	  pi->pi_map[0],pi->pi_map[1]);
      
      pi->pi_data = fetch_data(pi);
    }
 
#if 0
  int i;
  printfd(STDOUT_FILENO, "target : %s\n",bt->exec);
  printfd(STDOUT_FILENO, "[-] mapping area :"RED"0x%.08x-0x%.08x\n"NORM,
	  pi->pi_map[0],pi->pi_map[1]);
  
  
#endif  
}

unsigned char *fetch_data(struct procinfo *pi)
{
  int i,j,k,l;
  
  unsigned char *data;
  long *fetched;
  int mod;
  
  data = (unsigned char*)xmalloc(pi->pi_offset);
  /* fetching data as 4 bytes per loop */
  fetched =(long*)xmalloc((pi->pi_offset+4)/4);
  
  memset(data,0,pi->pi_offset);
  //  memset(fetch_data,0,((pi->pi_offset+4)/4));
  
  while (pi->pi_offset%4)
    pi->pi_offset++;
  
  //  printf("offset : %d \n",(int)pi->pi_offset);
  for(i=0,j=0;i<((pi->pi_offset)/4);i++,j++)
    {
      fetched[j] = ptrace(PTRACE_PEEKTEXT,pi->pi_pid,
			  (void*)pi->pi_address+4*i,NULL);
      
      if(!fetched[j] == -1){
	printfd(STDERR_FILENO,FATAL"line : %d,can't PEEK TEXT the process :"RED"%s"NORM"\n",
		__LINE__,strerror(errno));
	
	exit(1);
      }
	
    }
  /* we are in little endian */
  pi->pi_saved_offset = pi->pi_map[1] - pi->pi_map[0];
  
  for(k=0,i=0;k<pi->pi_saved_offset;k++,i+=4)
    {
      printf("%x\n",fetched[k]);
      data[i]=(fetched[k] >> 0) & 0xff;
      data[i+1]=(fetched[k] >> 8) & 0xff;
      data[i+2]=(fetched[k] >> 16) & 0xff;
      data[i+3]=(fetched[k] >> 24) & 0xff;
    }
#if 1
  
  for(k=0;k<pi->pi_saved_offset;k++)
    printf("%02x ",data[k]);
  printf("\n");
#endif
}
