#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

#include "utils.h"
#include "proc.h"

#define BT_MAX_DATA_LEN		512

void  *xmalloc(int bytes)
{
  void *tmp = malloc(bytes);
  if(!tmp)
    {
        fprintf(stderr,"Line : %d , malloc\n",__LINE__);	\
	return NULL;
    }
  memset(tmp,0,bytes);
  return tmp;
}
int printfd(int fd,const char* fmt,...)
{
  
  char data[BT_MAX_DATA_LEN];
  int len;
  va_list ap;
  va_start(ap,fmt);
  len = vsnprintf(data,BT_MAX_DATA_LEN,fmt,ap);
  va_end(ap);
  write(fd,data,len);
}


void dump_using_memory(struct procinfo* pi)
{
  int i,j,k,l;
  unsigned long  counter;
  unsigned char *data;
  long *fetched;
  int mod;
   
  counter =pi->pi_map[0];
  for(k=0;k<pi->pi_saved_offset;k++)
    {
      if (k == 0)
	{
	  printf(GREEN"%.08x"NORM" : ",(int)counter);
	  counter+=16;
	}
      if(k%16==0 && k!=0)
	{
	  
	  printf("%2s","|");
	  printf("\n");
	  printf(GREEN"%.08x "NORM": ",(int)counter);
	  counter+=16;
	}
      if(k%8==0 )
	printf(" ");
      
      printf("%02x ",pi->pi_data[k]);
      

      
    }
  printf("\n");

}  

void die(const char *msg)
{
  perror(msg);
  exit(errno);
}
/* 
printf("0x%.08x:",vaddr);
	  vaddr +=0x10;
	}
      fprintf(stdout," %02x %02x %02x %02x",
	      
	      WRITE_BYTE(addr[i],0),
	      WRITE_BYTE(addr[i],8),
	      WRITE_BYTE(addr[i],16),
	      WRITE_BYTE(addr[i],24));
      
      
      i++;
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
    }
  printf("\n");
*/
  

