/* Mohammed Ghannam 0x36 */

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

#define ALLOC_ERR(x)	\
  fprintf(stderr,"%s\n",x); \
  return NULL;

#define WRITE_BYTE(addr,bits) \
  (addr >> bits) & 0xff


const struct option lo[]=
  {
    {"address" , required_argument,0,'a'},
    {"offset",required_argument,0,'o'},
    {"dump",no_argument,0,'d'},
    {"raw",no_argument,0,'r'},
    {"data",no_argument,0,'p'},
    {"target",required_argument,0,'t'},
    {"args",required_argument,0,'A'},
    {NULL,0,NULL,0}
  };

struct dmem 
{
  u_long addr;
  u_long offset;
  unsigned char* data;
  char *exec;
  char **args;
};

struct dmem_options
{
  u_int8_t addr_opt;
  u_int8_t off_opt;
  u_int8_t raw_opt;
  u_int8_t use_data_opt;
  u_int8_t target_opt;
  u_int8_t target_has_args;
};

void dmem_banner(char*,int);
void *parse_target_args(struct dmem *,char*);
static struct dmem *parse_args(int,char**,struct dmem_options *);
struct dmem *dmem_init(void);
static void dump_using_memory(u_long,u_long *,u_long);
static void dump_raw(u_long *,u_long );
static long* fetch_data(long ,u_long ,pid_t );
static long trace_process(enum __ptrace_request,pid_t,void*,void *);

int main(int argc,char** argv)
{
  struct dmem *dm;
  struct dmem_options dmopt;
  u_long *data;
  pid_t pid;
  long trace_me;
  long segment;
  long val;
  int i ;

  dm = parse_args(argc,argv,&dmopt);
  
  pid = fork();
  //printf("dm->addr : %.08x\n",dm->addr);
  /* Handle the child !*/
  if(pid == 0)
    {
      /* tracking the child process */
      trace_process(PTRACE_TRACEME,0,NULL,NULL);
      /* executing the target process */
      execve(dm->args[0],dm->args,NULL);
    }
  else
    {
      wait(NULL);
      data = fetch_data(dm->addr,dm->offset,pid); 
      
      /* we can dump data from memory with etheir 
       * raw or memory map but not together
       */
      if(dmopt.raw_opt)
	dump_raw(data,dm->offset);
      else
	dump_using_memory(dm->addr,data,dm->offset);
	 
      printf("\n");
      
      ptrace(PTRACE_KILL,pid,NULL,NULL);
    }
 
  return 0;
}

static long trace_process(enum __ptrace_request req,pid_t process,
			  void* addr ,void *data)
{
  
  int trace_me;
  trace_me = ptrace(req,process,addr,data);

#if 0
  if(req == PTRACE_PEEKTEXT )
    printf("0x%.08x:0x%.08x\n",addr,trace_me);
#endif

  if(trace_me == -1)
    {
      fprintf(stdout,"ptrace line %d : %s\n",
	      __LINE__,strerror(errno));
      return (-1);
    }
  

  return trace_me;
}

static long *fetch_data(long address ,u_long offset,pid_t pid)
{
  u_long * data;
  int i,j;
  long addr = address;
  data = (u_long*)malloc((offset+4)/4);
  if(!data)
    {
      perror("fetch_data():malloc()");
      exit(1);
    }
  memset(data,0,sizeof(data));
  long l;
  for(i=0,j=0;i<offset;i++,j++)
    {
      data[j] =trace_process(PTRACE_PEEKTEXT,pid,(void*)addr+4*i,NULL);
      //addr += 4*i;
#if 0
      printf("addresse : %.08x : data %.08x\n",addr,data[j]);
      //printf("%.08x\n",data[j]);
#endif
    }
  
  return data;
}

struct dmem *dmem_init(void)
{
  struct dmem *dm;
  dm = (struct dmem*)malloc(sizeof(struct dmem));
  
  if (!dm){
    ALLOC_ERR("dmem_init():malloc()\n");
  }
  
  dm->addr=dm->offset = 0;
  /* we don't know how much data will be *
   * used for exec table 
   */
  dm->exec = (char*)malloc(20);
  
  if(!dm->exec){
    ALLOC_ERR("dmem_init() : malloc() \n");
  }
  
  /*
 alloc_err:
  printf("dmem_init(): %s \n",strerror(errno));
  return NULL;
  */
}

static struct dmem *parse_args(int argc,char **argv,
			       struct dmem_options *dopt)
{

  int opt,long_opt_index=0;
  char *target_args;
  struct dmem *dmem;
  int i;

  dopt->addr_opt =0;
  dopt->off_opt  =0;
  dopt->raw_opt  =0;
  dopt->target_opt=0;
  dopt->target_has_args=0;
  /* Default dump */
  dopt->use_data_opt=1;
  
  dmem = dmem_init();
  if(!dmem){
    ALLOC_ERR("parse_args():malloc()\n");
  }
  while( (opt=getopt_long(argc,argv,"a:o:drht:A:",lo,&long_opt_index))!=-1)
    {
      switch(opt)
	{
	case 'a':
	  dmem->addr = strtol(optarg,NULL,16);
	  dopt->addr_opt |= 1;
	  break;
	  
	case 'o':
	  dmem->offset = strtoul(optarg,NULL,10);
	  dopt->off_opt|=1;
	  break;
	case 'd':
	  dopt->use_data_opt |=1;
	  break;
	case 'r':
	  dopt->raw_opt|=1;
	  dopt->use_data_opt &=0;
	  break;
	case 'h':
	  dmem_banner(*argv,0);
	  break;
	case 't':
	  dopt->target_opt|=1;
	  dmem->exec= (char*)malloc(strlen(optarg)+1);
	  if(!dmem->exec){ 
	    ALLOC_ERR("target_exec : malloc()\n");
	  }
	  dmem->exec = strdup(optarg);
	  break;
	case 'A':
	  dopt->target_has_args |=1;
	  target_args = (char*)malloc(strlen(optarg)+1);
	  if(!target_args){ 
	    ALLOC_ERR("target_args : malloc()\n");
	  }
	  target_args =strdup(optarg);
	  target_args[strlen(target_args)+1]='\0';
	  break;
	default:
	  dmem_banner(*argv,0);
	  break;
	}
    }

  if(!dopt->addr_opt || !dopt->off_opt)
    {
      fprintf(stderr,"[-] memory address or offset not set\n");
      dmem_banner(*argv,1);
    }
  if(dopt->use_data_opt && dopt->raw_opt)
    dopt->raw_opt =0;
    
  if(!dopt->target_opt)
    {
      fprintf(stdout,"You must sepcify a target !\n");
      dmem_banner(*argv,-1);
    }

  if(dopt->target_has_args)
    {
      //; fprintf(stdout,"%s\n",target_args);
      parse_target_args(dmem,target_args);
    }
  else
    {
      dmem->args = (char**)malloc(2);
      if(!dmem->args)
	{
	  ALLOC_ERR("parse_target() : error allocation\n");
	}
      dmem->args[0]=strdup(dmem->exec);
      dmem->args[1]=NULL;
    }

#if 0
  fprintf(stdout,"address :0x%.08x\n",dmem->addr);
  fprintf(stdout,"offset :%d\n",dmem->offset);
  fprintf(stdout,"target :%s\n",dmem->exec);
  fprintf(stdout,"target arguments: { ");
  for(i=0;dmem->args[i];i++)
    printf("%s ",dmem->args[i]);
  printf(" }\n");
  fprintf(stdout,"address options : %d\n",dopt->addr_opt);
  fprintf(stdout,"offset options : %d\n",dopt->off_opt);
  fprintf(stdout,"memory dump options : %d\n",dopt->use_data_opt);
  fprintf(stdout,"raw dump option : %d\n",dopt->raw_opt);
#endif
  
  return dmem;  

}

void dmem_banner(char* prog,int status)
{
  fprintf(stdout,"+-----------------------------------------+\n");
  fprintf(stdout,"dump memory from process execution v0.1 \n");
  fprintf(stdout,"Written By Simo Ghannam\n");
  fprintf(stdout,
	  "-a --address <memory_addr> \t memory address\n"
	  "-o --offset  <byte offset> \t how many byte you want to leak?\n"
	  "-t --target  <binary process>\t binary process wich you want to leak from\n"
	  "-A --args    [bianry args] \t target arguments (optional)\n"
	  "-d --dump                  \t dump memory data\n"
	  "-r --raw                   \t dump raw data \n"
	  
	  );
  exit(status);
}
  
void *parse_target_args(struct dmem *d,char* args)
{
  char *arg_wr;
  int len;
  int num_args;
  int i;
  char *dup_args = strdup(args);
  num_args=0;
  arg_wr = strtok(dup_args,",");
  while(arg_wr)
    {
      arg_wr = strtok(NULL,",");
      num_args++;
    }
  
  d->args = (char**)malloc(num_args+2);
  if(!d->args)
    {
      ALLOC_ERR("parse_target() : error allocation\n");
    }
  
  d->args[0] = (char*)malloc(strlen(d->exec)+1);
  if(!d->args[0])
    {
      ALLOC_ERR("parse_target_args():error malloc()\n");
    }
  d->args[0] = strdup(d->exec);


  arg_wr = strtok(args,",");
  i=1;
  while(arg_wr != NULL)
    {
      
      len = strlen(arg_wr);
      d->args[i]=(char*)malloc(len);
      if(!d->args[i])
	{
	  ALLOC_ERR("parse_target() : error allocation\n");
	}
      d->args[i]=strdup(arg_wr);
      
      arg_wr = strtok(NULL,",");
      
      i++;
    }
  
  

#if 0
  for(i=0;d->args[i];i++)
    printf("%s\n",d->args[i]);
#endif
}

static void dump_raw(u_long *adds,u_long off)
{
  u_long *dup_addr;
  int i;
  
  dup_addr = adds;

  /* respecting little endian byte ordering */
  for(i=0;i<off;i++)
    {
      if(i != 0 &&  (i%4) == 0)
	;//printf("\n");
      fprintf(stdout,"%02x%02x%02x%02x",
	      WRITE_BYTE((int)adds[i],0),
	      WRITE_BYTE((int)adds[i],8),
	      WRITE_BYTE((int)adds[i],16),
	      WRITE_BYTE((int)adds[i],24));
      
    }
  //  printf("\n");
}

static void dump_using_memory(u_long add,u_long *addr,u_long off)
{
  
  int i,j=0,k=0,mv;
  u_long vaddr = add;
    
  for(i=0,k=0,mv=0;i<off;k++,mv+=0x10)
    {
      /*printf("0x%.08x\n",dup_addr);
      if(i != 0 &&  (i%4) == 0)
	{
	  printf("  ");
	  for(;j<i;j++)
	    {
	      printf("%c%c%c%c",
		     isprint(WRITE_BYTE(addr[j],0))?	WRITE_BYTE(addr[j],0) : '.',
		     isprint(WRITE_BYTE(addr[j],8))?	WRITE_BYTE(addr[j],8) : '.',
		     isprint(WRITE_BYTE(addr[j],16))?	WRITE_BYTE(addr[j],16) : '.',
		     isprint(WRITE_BYTE(addr[j],24))?	WRITE_BYTE(addr[j],24) : '.'
		     );
	    }
	  printf("\n");
	}
      */
      if(k%4==0)
	{
	  
	  printf("0x%.08x:",(int)vaddr);
	  vaddr +=0x10;
	}
      fprintf(stdout," %02x %02x %02x %02x",
	      WRITE_BYTE((int)addr[i],0),
	      WRITE_BYTE((int)addr[i],8),
	      WRITE_BYTE((int)addr[i],16),
	      WRITE_BYTE((int)addr[i],24));
      
      
      i++;
      if(i != 0 &&  (i%4) == 0)
	{
	  printf("  ");
	  for(;j<i;j++)
	    {
	      printf("%c%c%c%c",
		     isprint(WRITE_BYTE((int)addr[j],0))?	WRITE_BYTE((int)addr[j],0) : '.',
		     isprint(WRITE_BYTE((int)addr[j],8))?	WRITE_BYTE((int)addr[j],8) : '.',
		     isprint(WRITE_BYTE((int)addr[j],16))?	WRITE_BYTE((int)addr[j],16) : '.',
		     isprint(WRITE_BYTE((int)addr[j],24))?	WRITE_BYTE((int)addr[j],24) : '.'
		     );
	    }
	  printf("\n");
	}
    }
  printf("\n");
  
}
