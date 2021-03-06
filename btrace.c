/*
 $Id: main.c $

 Copyright (C) 2012,2013,2015 Simo36 (mg.simo@0x36.org)

 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 2 of the License, or
 (at your option) any later version.
 
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 
 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

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

const struct option lo[] = {
	/* process invokers  */
	{"attach", required_argument, 0, 'p'},
	{"target", required_argument, 0, 't'},
	/* used for dump */
	{"address", required_argument, 0, 'a'},
	{"offset", required_argument, 0, 'o'},
	{"dump-elf", required_argument, 0, 'D'}, /* experimental  */
	{"dump", required_argument, 0, 'D'},
	{"stack",no_argument,0,'s'},
	{"args", required_argument, 0, 'A'},
	{"regex", required_argument,0,'r'},
	{NULL, 0, NULL, 0}
};

struct bt_opts {
	u_int8_t pid_opt;
	u_int8_t force_addr_opt;
	u_int8_t off_opt;
	u_int8_t raw_opt;
	u_int8_t debug_opt;
	u_int8_t use_data_opt;
	u_int8_t target_opt;
	u_int8_t target_has_args;
	u_int8_t elf_dump_opts;
	
};

static struct btproc *parse_args(int, char **, struct bt_opts *);
static void btrace_banner(char *, int);

int main(int argc, char **argv)
{
	struct bt_opts opts;
	struct btproc *bt_proc;

	bt_proc = parse_args(argc, argv, &opts);

	bt_proc->pi->pi_debug = opts.debug_opt;
	if (opts.target_opt && opts.pid_opt) {
		bt_proc_destroy(bt_proc);
		printfd(2,
			FATAL " You can't choose target and pid together !\n");
		btrace_banner(*argv, 1);
	} else if (!opts.target_opt && !opts.pid_opt) {
		printfd(2, FATAL "No such target or porcess\n");
		btrace_banner(*argv, 1);
	} else {
		/* using target executable */
		if (opts.target_opt) {
			bt_proc->exec =
			    check_target_path(bt_proc->pi->pi_target,
					      bt_proc->pi->pi_perm);

			if (!bt_proc->exec) {
				bt_proc_destroy(bt_proc);
				btrace_banner(*argv, 1);
			}
			if (opts.target_has_args)
				bt_proc->args_parser((char *)bt_proc->pi->
						     pi_args, bt_proc);

			else
				bt_proc->proc_arguments[0] =
				    strdup((const char *)bt_proc->exec);

			if ((!opts.force_addr_opt && opts.off_opt) ||
			    (opts.force_addr_opt && !opts.off_opt)) {
				printfd(STDERR_FILENO,
					WARN
					"You may choose both of address and offset !\n");
				bt_proc_destroy(bt_proc);
				btrace_banner(*argv, 1);
			}
			/* if address & offset are set */
			else {
				bt_proc->pi->pi_stack->ma_map[0] =
					bt_proc->pi->pi_address;
				bt_proc->pi->pi_stack->ma_map[1] =
					bt_proc->pi->pi_address +
					bt_proc->pi->pi_offset;
				
				bt_proc->pi->pi_addr->ma_map[0] =
				    bt_proc->pi->pi_address;
				bt_proc->pi->pi_addr->ma_map[1] =
				    bt_proc->pi->pi_address +
				    bt_proc->pi->pi_offset;
			}

			exec_target(bt_proc);

			/* If force address and offset are not set we read 
			 * from profs and fetch memory base address 
			 * and write new elf binary
			 */
			if (!opts.force_addr_opt && !opts.off_opt) {
				printfd(2,
					DO "Target :" GREEN " %s " NORM
					" PID : " GREEN "%d" NORM "\n",
					bt_proc->exec, bt_proc->pi->pi_pid);
				if (read_procfs_maps(bt_proc->pi) == -1)
					die("no such process");
			}

			fetch_data(bt_proc->pi);
		}

		/* pid attach */
		if (opts.pid_opt) {
			if (attach_process(bt_proc->pi) == -1)
				die(FATAL "Can't attach process");

			get_cmdline_by_pid(bt_proc->pi);
			printfd(2,
				DO "Attach PID:" GREEN " %d" NORM "  Target :"
				GREEN " %s" NORM "\n", bt_proc->pi->pi_pid,
				bt_proc->pi->pi_perm->p_full_path);

			if ((!opts.force_addr_opt && opts.off_opt) ||
			    (opts.force_addr_opt && !opts.off_opt)) {
				printfd(STDERR_FILENO,
					WARN
					"You may choose both of address and offset !\n");
				bt_proc_destroy(bt_proc);
				btrace_banner(*argv, 1);
			}
			/* if address & offset are set */
			else {
				bt_proc->pi->pi_stack->ma_map[0] =
					bt_proc->pi->pi_address;
				bt_proc->pi->pi_stack->ma_map[1] =
					bt_proc->pi->pi_address +
					bt_proc->pi->pi_offset;
				
				bt_proc->pi->pi_addr->ma_map[0] =
				    bt_proc->pi->pi_address;
				bt_proc->pi->pi_addr->ma_map[1] =
				    bt_proc->pi->pi_address +
				    bt_proc->pi->pi_offset;

			}

			if (!opts.force_addr_opt && !opts.off_opt)
				if (read_procfs_maps(bt_proc->pi) == -1)
					die(FATAL "No such process");

			/* it shouldn't return anything 
			 * BACK TO ME 
			 */
			fetch_data(bt_proc->pi);
		}

		if (opts.raw_opt)
			raw_dump(bt_proc->pi);
		else
			dump_using_memory(bt_proc->pi);

		if(opts.elf_dump_opts) {
			
		}
		
		pinfo_destroy(bt_proc->pi);
		bt_proc_destroy(bt_proc);

	}
	return 0;

}

static struct btproc *parse_args(int argc, char **argv, struct bt_opts *opts)
{
	int opt, long_opt_index = 0;
	struct procinfo *pi;
	struct btproc *bt;

	/* initialize our options structure  */
	opts->pid_opt = 0;
	opts->force_addr_opt = 0;
	opts->off_opt = 0;
	opts->raw_opt = 0;
	opts->target_opt = 0;
	opts->debug_opt = 0;
	opts->target_has_args = 0;
	opts->elf_dump_opts = 0;
	
	/* Default dump */
	opts->use_data_opt = 1;
	opts->off_opt = 0;
	bt = bt_proc_init();
	pi = bt->pi;

	while ((opt =
		getopt_long(argc, argv, "a:p:o:d:D:rst:A:h", lo,
			    &long_opt_index)) != -1) {
		switch (opt) {
		case 'a':
			pi->pi_address = strtol(optarg, NULL, 0x10);
			opts->force_addr_opt |= 1;
			break;
		case 'p':
			pi->pi_pid = atoi(optarg);	/* get pid from user */
			opts->pid_opt |= 1;
			break;
		case 't':
			pi->pi_target = (u_char *) strdup((const char *)optarg);
			opts->target_opt |= 1;
			break;
		case 'A':
			pi->pi_args = (u_char *) strdup((const char *)optarg);
			opts->target_has_args |= 1;
			break;

		case 'h':
			btrace_banner(*argv, 0);
			break;
		case 'o':
			pi->pi_offset = strtol(optarg, NULL, 10);
			opts->off_opt |= 1;
			break;
		case 'd':
			opts->use_data_opt |= 1;
			opts->debug_opt |= DEBUG_DMP;
			if(!strncmp(optarg,"raw",3))
				opts->raw_opt |= 1;
			
			break;
		case 's':
			opts->debug_opt |= DEBUG_STACK;
			break;
		case 'D':
			opts->elf_dump_opts |= BT_ELF_DUMP;
			break;
		default:
			btrace_banner(*argv, -1);
		}
	}

	return bt;
}

void btrace_banner(char *arg, int status)
{
	//printfd(1,"+-----------------------------------------+\n");
	printfd(1, "Usage : %s <options>  \n", arg);
	printfd(1, "Written By  M.Ghannam (Simo36)\n\n");
	printfd(1,
		"Process Invoker methods : \n"
		"  -p  --attach  <process id>    \tSet a process id\n"
		"  -t  --target  <binary process>\tBinary process which you want to leak from\n"
		"  -A  --args    [bianry args]   \tTarget arguments (optional)\n"
		"\n");
	printfd(1,
		"Dump facilities : \n"
		"  -d  --dump     <hex/raw>       \tDump memory data (default output)\n"
		"  -D  --dump-elf <out_file>       \tDump ELF binary\n"
		"  -a  --address  <memory_addr>    \tMemory address\n"
		"  -o  --offset   <byte offset>    \tHow many byte you want to leak?\n"
		"  -s  --stack			   \tDump the stack \n"
		"\n"
		);

		
	exit(status);
}
