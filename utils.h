#if !defined H_UTILS_H
#define H_UTILS_H

/* leet color codes */
#define BLUE    "\033[94m"
#define RED     "\033[91m"
#define GREEN   "\033[92m"
#define YELLOW  "\033[93m"
#define NORM    "\033[0m"

#define WARN	GREEN"[-] "NORM
#define FATAL	RED"[x] "NORM
#define DO	BLUE"[+] "NORM
#define ALLOC_ERR(x)	\
  fprintf(stderr,"Line : %d , %s\n",__LINE__,x);	\
  return NULL;

#define WRITE_BYTE(addr,bits) \
  (addr >> bits) & 0xff

int printfd(int fd,const char* fmt,...);
void *xmalloc(int);
void dump_using_memory(u_long ,u_char*,u_long);
#endif /* H_UTILS_H */
