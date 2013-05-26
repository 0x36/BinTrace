/* Mohammed Ghannam 0x36 25/05/2013 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <errno.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/ptrace.h>

#include "utils.h"
#include "proc.h"

#define	 __VERSION	"0.1"
#define	__AUTHOR	"Mohammed Ghannam"
#define __LICENSE	"GPL3"

const struct option lo[]=
  {
    {"force-addr" , required_argument,0,'a'},
    {"offset",required_argument,0,'o'},
    {"dump",no_argument,0,'d'},
    {"raw",no_argument,0,'r'},
    {"data",no_argument,0,'p'},
    {"target",required_argument,0,'t'},
    {"args",required_argument,0,'A'},
    {"attach",required_argument,0,'P'},
    {NULL,0,NULL,0}
  };

struct bt_opts
{
  u_int8_t force_addr_opt;
  u_int8_t off_opt;
  u_int8_t raw_opt;
  u_int8_t use_data_opt;
  u_int8_t target_opt;
  u_int8_t target_has_args;
  u_int8_t pid_opt;
};


static void bt_banner(char*);
//static void *parse_target_args(struct dmem *,char*);
static struct btproc *parse_args(int,char **,struct bt_opts*);

int main(int argc,char** argv)
{
  struct bt_opts opts;
  struct btproc *bt;
  struct perms perms;

  bt = parse_args(argc,argv,&opts);
  if(!bt){
    printf(FATAL"can't build binary data structure\n");
    exit(-1);
  }
  
  if(opts.target_opt)
    bt->exec = check_target_path(bt->exec,&perms);
}

static struct btproc *parse_args(int argc,char **argv,
			       struct bt_opts  *opts)
{
   
  int opt,long_opt_index=0;
  char *target_args;
  struct btproc *bt;
  
  int i;

  opts->force_addr_opt =0;
  opts->off_opt  =0;
  opts->target_opt=0;
  opts->target_has_args=0;
  opts->pid_opt=0;
  /* Default dump */
  opts->use_data_opt=0;

  bt = bt_proc_init();
  if(!bt){
    printf("line : %d,bt_proc_init():malloc ",__LINE__);
    return NULL;
  }
  while( (opt=getopt_long(argc,argv,"a:o:drht:A:P:",lo,&long_opt_index))!=-1)
    {
      switch(opt)
	{
	case 'a':
	  bt->pi->pi_address = strtol(optarg,NULL,16);
	  opts->force_addr_opt |= 1;
	  break;

	case 'o':
	  bt->pi->pi_offset = strtoul(optarg,NULL,10);
	  opts->off_opt|=1;
	  break;
	
	case 'd':
	  opts->use_data_opt |=1;
	  break;
	  
	case 'h':
	  bt_banner(*argv);
	  break;
	
	case 't':
	  opts->target_opt|=1;
	  bt->exec= (char*)malloc(strlen(optarg)+1);
	  if(!bt->exec)
	    {
	    printf("line : %d,bt->exec:malloc ",__LINE__);
	    return NULL;
	    }
	  bt->exec = strdup(optarg);
	  break;
	case 'A':
	  opts->target_has_args |=1;
	  target_args = (char*)malloc(strlen(optarg)+1);
	  
	  target_args =strdup(optarg);
	  target_args[strlen(target_args)+1]='\0';
	  break;

	case 'P':
	  bt->pi->pi_pid = atoi(optarg);
	  opts->pid_opt |=1;
	  break;
	default:
	  bt_banner(*argv);
	  break;
	}
    }
  
  if(opts->target_opt && opts->pid_opt)
    {
      fprintf(stderr,FATAL" You cannot use those options together, choose only one !\n");
      exit(1);
    }
  
  if(opts->target_opt )
    {
      if(!opts->force_addr_opt || !opts->off_opt)
	{
	  fprintf(stderr,"[-] memory address or offset not set\n");
	  exit(1);
	}
      if(opts->target_has_args)
	{
	  //; fprintf(stdout,"%s\n",target_args);
	  
	  bt->args_parser(target_args,bt);
	}
      else
	{
	  bt->proc_arguments = (char**)malloc(2);
	  if(!bt->proc_arguments)
	    {
	      printf("line %d ,parse_target() : error allocation\n",__LINE__);
	      exit(1);
	    }
	  bt->proc_arguments[0]=strdup(bt->exec);
	  bt->proc_arguments[1]=NULL;
	}
    }
  
  if(!opts->target_opt && !opts->pid_opt)
    {
      fprintf(stdout,WARN"You must sepcify a target or attach a running process !\n");
      bt_banner(*argv);
      exit(1);
    }
  /* just for debugging purpose */
  /* it shouldn't be here !*/
  if(opts->use_data_opt){
    dump_using_memory(bt->pi->pi_address,bt->pi->pi_data,bt->pi->pi_offset);
  }
#if 0
  fprintf(stdout,"address :0x%.08x\n",(unsigned int)bt->pi->pi_address);
  fprintf(stdout,"offset :%d\n",(int)bt->pi->pi_offset);
  fprintf(stdout,"target :%s\n",bt->exec);
  fprintf(stdout,"target arguments: { ");
  for(i=0;bt->proc_arguments[i];i++)
    printf("%s ",bt->proc_arguments[i]);
  printf(" }\n");
  fprintf(stdout,"address options : %d\n",opts->force_addr_opt);
  fprintf(stdout,"offset options : %d\n",opts->off_opt);
  fprintf(stdout,"memory dump options : %d\n",opts->use_data_opt);
  fprintf(stdout,"raw dump option : %d\n",opts->raw_opt);
#endif
  
return bt;  
}
  
static void bt_banner(char *argv)
{
  fprintf(stdout,BLUE"+---------------------------------------------------------------------+\n"NORM);
  fprintf(stdout,"bintrace tracking a runtime process in RAM   v%s \n",__VERSION);
  fprintf(stdout,"Written By %s\n",__AUTHOR);
  fprintf(stdout,
	  "-a   --force-addr  <memory_addr> \t memory address\n"
	  "-A   --args        [bianry args] \t target arguments (optional)\n"
	  "-d   --dump                      \t dump memory data\n"
	  "-o   --offset      <byte offset> \t how many byte you want to leak?\n"
	  "-P   --attach      <process id>  \t attach a running process\n"
	  "-t   --target      <binary process>\t binary process wich you want to leak from\n"
	  );
  
}
