#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include "utils.h"

void *xmalloc(int bytes)
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
int printfd(int fd,const char* fmt,...){}

void dump_using_memory(u_long add,u_char *addr,u_long off)
{

  
  int i,j,l=0,k=0,mv;
  u_long vaddr = add;
  
  for(i=0,k=0,mv=0;i<=(off/4);k++,mv+=0x10,i+=4)
    {
      if(k%4==0)
	{
	  printf("0x%.08x:",(unsigned int)vaddr);
	  vaddr +=0x10;
	}
      
      fprintf(stdout," %02x %02x %02x %02x",
	      
		addr[i],
		addr[i+1],
		addr[i+2],
		addr[i+3]);

    }
  printf("\n");
}
  /*    
  for(i=0,k=0,mv=0;i<off;k++,mv+=0x10)
    {

      if(k%4==0)
	{
	  
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
  

