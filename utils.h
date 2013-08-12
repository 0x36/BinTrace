#if !defined H_UTILS_H
#define H_UTILS_H

#include "proc.h"
/* leet color codes */
#define BLUE    "\033[94m"
#define RED     "\033[91m"
#define GREEN   "\033[92m"
#define YELLOW  "\033[93m"
#define NORM    "\033[0m"

#define WARN	GREEN"[-] "NORM
#define FATAL	RED"[x] "NORM
#define DO	BLUE"[+] "NORM
#define DEBUG	RED"[~] Debug:"NORM

#define ALLOC_ERR(x)	\
  fprintf(stderr,"Line : %d , %s\n",__LINE__,x);	\
  return NULL;

#define WRITE_BYTE(addr,bits) \
  (addr >> bits) & 0xff;

/* used only in linux 32-bit systems
 * and also 64-bit , but it's not reliable 
 * TODO : making compatibilities between archs
 *	  x86/x86_64/ARMv9
 */
//typedef vaddr_t long;

char *hex(char *, int);
char *ascii(char *, int);
int printfd(int fd,const char* fmt,...);
void *xmalloc(int);
void dump_using_memory(struct procinfo *);
void raw_dump(struct procinfo *);
void die(const char *);
void reverse_ll(struct map_addr **);
void get_cmdline_by_pid(struct procinfo *);
#endif /* H_UTILS_H */
