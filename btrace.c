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

#include "utils.h"
#include "proc.h"


const struct option lo[]=
  {
    {"pid",required_argument,0,'p'},
    {"address" , required_argument,0,'a'},
    {"offset",required_argument,0,'o'},
    {"dump",no_argument,0,'d'},
    {"raw",no_argument,0,'r'},
    {"data",no_argument,0,'p'},
    {"target",required_argument,0,'t'},
    {"args",required_argument,0,'A'},
    {NULL,0,NULL,0}
  };

struct bt_opts
{
  u_int8_t  pid_opt;
  u_int8_t addr_opt;
  u_int8_t off_opt;
  u_int8_t raw_opt;
  u_int8_t use_data_opt;
  u_int8_t target_opt;
  u_int8_t target_has_args;
};

int main(int argc,char **argv)
{
}
