#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

#include "utils.h"
#include "proc.h"

#define BT_MAX_DATA_LEN		512
#define HEX_OFFSET    1
#define ASCII_OFFSET 51
#define NUM_CHARS    16

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


char * ascii(char *position, int c)
{
  int i=0;

  if (!isprint(c)) c='.';
  sprintf(position, "%c", c);

  return(++position);
}
 
char * hex(char *position, int c)
{
  int offset=3;
 

  sprintf(position, "%02x ", (unsigned char) c);
 
  *(position+offset)=' ';    
  return (position+offset);
}
 
        
void dump_using_memory(struct procinfo* pi)
{

  int c=' ';             
  char * hex_offset;
  int i,counter;
  char * ascii_offset; 
  char line[81];      
  i=0;
  
  counter=pi->pi_map[0];
  while (i < pi->pi_offset )
    {
      memset(line,0x20, 81);
      hex_offset   = line+HEX_OFFSET;
      ascii_offset = line+ASCII_OFFSET;
      printf(GREEN"0x%.08x"NORM" : ",(int)counter);
      counter+=16;
      
      while ( ascii_offset < line+ASCII_OFFSET+NUM_CHARS
	      && i < pi->pi_offset )
        {
	  c=pi->pi_data[i++];
	  hex_offset = hex(hex_offset, c);
	  ascii_offset = ascii(ascii_offset, c);
 
        }
      printf("%s\n", line);
    }

}

/*
void dump_using_memory(struct procinfo* pi)
{
  int i,j,k,l;
  unsigned long  counter;
  unsigned char *data;
  long *fetched;
  int mod;
  char line[100];
  memset(line,' ',100);

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
  printf("%45s","|a");
  printf("\n");

}  
*/

void die(const char *msg)
{
  perror(msg);
  exit(errno);
}
