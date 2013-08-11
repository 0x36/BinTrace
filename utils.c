#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
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
  int wr;
  va_start(ap,fmt);
  len = vsnprintf(data,BT_MAX_DATA_LEN,fmt,ap);
  va_end(ap);
  wr =   write(fd,data,len);
  return wr;
}


char *ascii(char *position, int c)
{
  
  if (!isprint(c)) c='.';
    sprintf(position, "%c", c);
  return(++position);
}
 
char *hex(char *position, int c)
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
void raw_dump(struct procinfo *pi)
{
  int left,written;
  u_char *ptr;
  ptr = pi->pi_data;
  left = pi->pi_offset;
  while(left >0)
    {
      written = write(1,ptr,left);
      left -=written; 
      ptr+=written;
    }
}
void die(const char *msg)
{
  perror(msg);
  exit(errno);
}
