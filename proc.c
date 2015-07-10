#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <elf.h>

#include "proc.h"
#include "utils.h"

/* initialise process info data structure 
 * Success : return a valid pinfo pointer
 * Failure : returns NULL
 */
struct procinfo *pinfo_init()
{
	struct procinfo *pi;
	pi = (struct procinfo *)xmalloc(sizeof(struct procinfo));
	pi->pi_pid = 0;
	pi->pi_target = NULL;	/* we'll reserve a space for
				 * this later ! */
	pi->pi_debug = 0;
	pi->pi_address = 0;
	pi->pi_stack = 0;
	pi->pi_data = NULL;	/* we'll figure it out later */
	pi->pi_map[0] = pi->pi_map[1] = 0;
	pi->pi_offset = 0;
	
	pi->pi_addr = (struct map_addr *)xmalloc(sizeof(struct map_addr));
	pi->pi_addr->ma_map[0] = pi->pi_addr->ma_map[1] = 0;
	pi->pi_addr->ma_next = NULL;

	pi->pi_stack = (struct map_addr *)xmalloc(sizeof(struct map_addr));
	pi->pi_stack->ma_map[0] = pi->pi_addr->ma_map[1] = 0;
	pi->pi_stack->ma_next = NULL;
	
	pi->pi_perm = (struct perms *)xmalloc(sizeof(struct perms));

	/* initialise permission with NULL values */
	pi->pi_perm->p_read = 0;
	pi->pi_perm->p_write = 0;
	pi->pi_perm->p_exec = 0;
	pi->pi_perm->p_symb = (u_char *) malloc(4 * sizeof(u_char));

	return pi;
}

void parse_target_args(char *arg, struct btproc *bt)
{
	char *arg_wr;
	int num_args;
	int i;
	char *dup_args = arg;
	num_args = 0;
	arg_wr = strtok(dup_args, ",");

	/* this loop is done for checking how many args are passed
	 * lazy idea but it works fine 
	 */
	while (arg_wr) {
		arg_wr = strtok(NULL, ",");
		num_args++;
	}

	for (i = 0; bt->proc_arguments[i]; i++)
		free(bt->proc_arguments[i]);
	free(bt->proc_arguments);

	bt->proc_arguments = (char **)xmalloc((num_args + 2) * sizeof(char *));

	if (!bt->proc_arguments) {
		printf("line : %d,parse_target_args() : error allocation\n",
		       __LINE__);
	}
	bt->proc_arguments[0] = strdup((const char *)bt->exec);

	arg_wr = strtok(arg, ",");

	/* we don't use i=0 because it's already reserved for the target */
	i = 1;
	while (arg_wr != NULL) {
		bt->proc_arguments[i] = strdup((const char *)arg_wr);
		arg_wr = strtok(NULL, ",");
		i++;
	}
	bt->proc_arguments[i] = NULL;

#if 0
	for (i = 0; bt->proc_arguments[i]; i++)
		printf(DEBUG "%s\n", bt->proc_arguments[i]);
#endif

}

struct btproc *bt_proc_init()
{
	struct btproc *bt;
	bt = (struct btproc *)xmalloc(sizeof(struct btproc));
	if (!bt)
		return NULL;
	//bt->pi = (struct procinfo *)xmalloc(sizeof(struct procinfo));
	//bt->exec = (char*)malloc(MAX_EXEC_SIZE);

	bt->pi = pinfo_init();
	bt->proc_arguments = (char **)xmalloc(2 * sizeof(char *));
	bt->proc_arguments[0] = NULL;

	if (!bt->proc_arguments) {
		printf(FATAL
		       "line : %d,parse_target_args() : error allocation\n",
		       __LINE__);
		die("Error");
	}

	bt->args_parser = parse_target_args;

	return bt;
}

u_char *check_target_path(u_char * target, struct perms * perms)
{
	char *vtarget;
	char *env_path;
	int npath;		/* number of path */
	char *arg_wr, *full_path;
	int found = 0;		/* check if we found the pathfull_path or not */
	char current[1025];
	char *rpath;

	vtarget = strdup((const char *)target);
	memset(current, 0, 1025);

	rpath = realpath((const char *)target, current);
	if (rpath)
		perms->p_full_path = (u_char *) strdup((const char *)rpath);

	else {
		if (!access((const char *)target, F_OK)) {
			get_file_permissions(target, perms);
			perms->p_full_path =
			    (u_char *) strdup((const char *)target);

		} else {
			env_path = getenv("PATH");

			/*check number og directories used in path env */
			npath = 0;
			arg_wr = strtok(env_path, ":");

			while (arg_wr) {
				full_path = (char *)
				    xmalloc((strlen(arg_wr) + strlen(vtarget) +
					     2) * sizeof(char));
				memset(full_path, 0,
				       strlen(arg_wr) + strlen(vtarget) + 2);
				strcpy(full_path, arg_wr);
				strcat(full_path, "/");
				strcat(full_path, vtarget);
				if (!access(full_path, F_OK)) {
					found = 1;	/* found */
					/*printf("full path : %s\n",full_path); */

					get_file_permissions((u_char *)
							     full_path, perms);
					perms->p_full_path =
					    (u_char *) strdup((const char *)
							      full_path);

					break;
				}
				arg_wr = strtok(NULL, ":");
				npath++;
				free(full_path);
			}
			if (!found) {
				printf(FATAL "" RED "%s " NORM ":not found !\n",
				       vtarget);
				return NULL;
			}
			free(full_path);

		}
	}
#if 0
	printfd(2, DEBUG "full path %s\n", perms->p_full_path);
	printfd(2, DEBUG "exec :%s\n", vtarget);
	printfd(2, DEBUG "path :%s\n", env_path);
	printfd(2, DEBUG "number of dires  : %d\n", npath);
#endif

	free(vtarget);
	return perms->p_full_path;
}

void get_file_permissions(u_char * path, struct perms *p)
{
	p->p_read = p->p_write = p->p_exec = 0;
	if (!access((const char *)path, W_OK))
		p->p_write |= 1;

	if (!access((const char *)path, R_OK))
		p->p_read |= 1;

	if (!access((const char *)path, X_OK))
		p->p_exec |= 1;

	/* set symbols */
	memset(p->p_symb, 0, 4);
	(p->p_read) ? strcat((char *)p->p_symb, "r") : strcat((char *)p->p_symb,
							      "-");
	p->p_write ? strcat((char *)p->p_symb, "w") : strcat((char *)p->p_symb,
							     "-");
	(p->p_exec) ? strcat((char *)p->p_symb, "x") : strcat((char *)p->p_symb,
							      "-");

#if 0
	printf("read :" GREEN "%d" NORM " , write :" GREEN "%d" NORM " , exec :"
	       GREEN "%d" NORM "\n", p->p_read, p->p_write, p->p_exec);
	printf("symbols :" GREEN "%s" NORM "\n", p->p_symb);
#endif
}

void bt_proc_destroy(struct btproc *bt)
{
	int i;

	for (i = 0; *(bt->proc_arguments + i); i++)
		free(*(bt->proc_arguments + i));

	bt->args_parser = NULL;
}

void pinfo_destroy(struct procinfo *pi)
{
	struct map_addr *ma, *tmp;

	pi->pi_pid = pi->pi_address = pi->pi_offset = 0;
	memset(pi->pi_map, 0, 2);

	if (pi->pi_target)
		free(pi->pi_target);

	if (pi->pi_data)
		free(pi->pi_data);
	/* free permission structure */
	if (pi->pi_perm) {
		free(pi->pi_perm->p_full_path);
		free(pi->pi_perm->p_symb);
	}

	/* Free linked list */
	for (ma = pi->pi_addr; ma; ma = tmp) {
		tmp = ma->ma_next;
		free(ma);
	}
	/* free stack object */
	if(pi->pi_stack) {
		if(pi->pi_stack->ma_data)
			free(pi->pi_stack->ma_data);
		free(pi->pi_stack);
	}
}

static void catch_child_proc(int sig)
{
	pid_t target_pid;
	int status;

	while ((target_pid = waitpid(-1, &status, WNOHANG)) > 0) ;

}

/* main function : it handles all process execution */
void exec_target(struct btproc *bt)
{
	pid_t pid;
	struct procinfo *pi;
	long ret;
	struct sigaction act;

	memset(&act, 0, sizeof(act));
	act.sa_handler = catch_child_proc;
	act.sa_flags = 0;
	sigemptyset(&act.sa_mask);

	if (sigaction(SIGCHLD, &act, NULL) == -1) {
		printfd(STDERR_FILENO, FATAL "sigaction : %s\n",
			strerror(errno));
		exit(1);
	}
	pi = bt->pi;
	pid = fork();

	/* child */
	if (pid == 0) {
		close(0);
		close(1);
		close(2);
		/* tracing the child process */
		ret = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		/* execting our target process */
		execve((const char *)bt->exec, (char **const)bt->proc_arguments,
		       NULL);

		if (ret == -1) {
			printfd(STDERR_FILENO,
				FATAL "line : %d,can't trace the process :" RED
				"%s" NORM "\n", __LINE__, strerror(errno));
			bt_proc_destroy(bt);
			exit(1);
		}
	} else if (pid == -1) {
		printfd(STDERR_FILENO,
			FATAL "line : %d,can't fork :" RED "%s" NORM "\n",
			__LINE__, strerror(errno));
		bt_proc_destroy(bt);
		exit(1);
	} else {
		wait(NULL);
		/* set pid in process info structure */
		pi->pi_pid = pid;

		//pi->pi_data = fetch_data(pi);

	}

/* FIXME */
#if 0
	int i;
	printfd(STDOUT_FILENO, DEBUG "target : %s\n", bt->exec);
	printfd(STDOUT_FILENO,
		DEBUG "[-] mapping area :" RED "0x%.08x-0x%.08x\n" NORM,
		pi->pi_map[0], pi->pi_map[1]);
#endif
}

void show_mem_debug(struct map_addr *addr)
{
	struct map_addr *ma_ptr,*ma_tmp;

	ma_tmp = addr;

	/**/ for (ma_ptr = ma_tmp; ma_ptr; ma_ptr = ma_ptr->ma_next) {
		printfd(STDERR_FILENO,
			DO "mapping area : " RED "" SHOW_ADDR "-" SHOW_ADDR "\n"
			NORM, ma_ptr->ma_map[0], ma_ptr->ma_map[1]);
	}
}
void fetch_data(struct procinfo *pi)
{
	int i;
	unsigned char *data;
	struct map_addr *ma_ptr,*ma_tmp;
	
	/* for testing purpose only */
	if((pi->pi_debug | DEBUG_MASK) & DEBUG_STACK) {
		//printfd(2,"STACK\n");
		ma_tmp = pi->pi_stack;
	}
	
	else 
		ma_tmp = pi->pi_addr;
	
	/**/ for (ma_ptr = ma_tmp; ma_ptr; ma_ptr = ma_ptr->ma_next) {
		/*
		printfd(STDERR_FILENO,
			DO "mapping area : " RED "" SHOW_ADDR "-" SHOW_ADDR "\n"
			NORM, ma_ptr->ma_map[0], ma_ptr->ma_map[1]);
		*/
		pi->pi_offset = ma_ptr->ma_map[1] - ma_ptr->ma_map[0];
		data =
		    (unsigned char *)malloc(pi->pi_offset + 4 * sizeof(char));

		pi->pi_saved_offset = pi->pi_offset;

		memset(data, 0, pi->pi_offset + 4);

		for (i = 0; i < pi->pi_offset; i++) {
			data[i] = (char)ptrace(PTRACE_PEEKDATA, pi->pi_pid,
					       ma_ptr->ma_map[0] + i, NULL);
		}

		/* more optimization  */
		ma_ptr->ma_data = 
			(unsigned char *)malloc(sizeof(unsigned char) *
						pi->pi_offset + 1);
		memset(ma_ptr->ma_data, 0, pi->pi_offset + 1);
		memcpy(ma_ptr->ma_data, data, pi->pi_offset);
		
		free(data);
		
	}
	if((pi->pi_debug | DEBUG_MASK) & DEBUG_DMP)
		show_mem_debug(ma_tmp);
}

int read_procfs_maps(struct procinfo *pi)
{
	char procfs_path[20];
	FILE *fp;
	char buf[512];
	char unwanted[256];
	char file_path[256];
	struct map_addr *ma_ptr, *head;
	u_long start, end;

	memset(procfs_path, 0, 20);
	memset(buf, 0, 512);
	memset(file_path, 512, 0);
	memset(unwanted, 0, 256);

	ma_ptr = NULL;
	head = NULL;
	sprintf(procfs_path, "/proc/%d/maps", (int)pi->pi_pid);

	fp = fopen(procfs_path, "r");
	if (!fp)
		return -1;
	printfd(2, DO "Fetch /procfs" NORM "\n");

	while (fgets(buf, 512, fp)) {
		//00400000-0040b000 r-xp 00000000 08:03 1572888                            /bin/cat
		
		sscanf(buf, "%lx-%lx %s %s %s %s %255s\n",
		       &start, &end, unwanted, unwanted, unwanted, unwanted,
		       file_path);

		if (!memcmp
		    (pi->pi_perm->p_full_path, file_path,
		     strlen((const char *)pi->pi_perm->p_full_path))) {
			ma_ptr =
			    (struct map_addr *)xmalloc(sizeof(struct map_addr));

			ma_ptr->ma_map[0] = start;
			ma_ptr->ma_map[1] = end;
			ma_ptr->ma_next = head;
			head = ma_ptr;

#if 0
			printfd(2, GREEN "%s " NORM "\n",
				pi->pi_perm->p_full_path);
			printfd(2, GREEN "line : %s" NORM "\n", buf);
			printfd(2, DEBUG " start : %lx\n", ma_ptr->ma_map[0]);
			printfd(2, DEBUG " end : %lx\n", ma_ptr->ma_map[1]);
			printfd(2, DEBUG " path : %s\n", file_path);
#endif

		}
		else if (!memcmp("[stack]", file_path,7)) {
			pi->pi_stack =
				(struct map_addr *)xmalloc(sizeof(struct map_addr));
			pi->pi_stack->ma_map[0] = start;
			pi->pi_stack->ma_map[1] = end;
			pi->pi_stack->ma_next = NULL;
		}
		/* It doesn't reach here  */
		else if (!memcmp("[heap]", file_path,6)) {
			//printfd(2,"FIXME\n");
		}
	}
#if 0
	for (ma_ptr = pi->pi_addr; ma_ptr; ma_ptr = ma_ptr->ma_next) {
		printf(BLUE "ADDR : 0x%lx" NORM "\n", ma_ptr->ma_map[0]);
	}
#endif

	pi->pi_addr = head;
	reverse_ll(&pi->pi_addr);

#if 0
	for (ma_ptr = pi->pi_addr; ma_ptr; ma_ptr = ma_ptr->ma_next) {
		printf(BLUE "ADDR : 0x%lx" NORM "\n", ma_ptr->ma_map[0]);
	}
#endif

#if 0
	addr2 = strtok(addr1, "-");
	addr2 = strtok(NULL, "-");
	pi->pi_address = pi->pi_map[0] = strtoul(addr1, NULL, 16);
	pi->pi_map[1] = strtoul(addr2, NULL, 16);

	pi->pi_offset = pi->pi_map[1] - pi->pi_map[0];

	printfd(2, DEBUG "%s", buf);
	printfd(2, DEBUG " Base address : 0x%08x\n", pi->pi_map[0]);
	printfd(2, DEBUG " End address :  0x%08x\n", pi->pi_map[1]);
	printfd(2, DEBUG " Offset :  0x%08x\n", pi->pi_offset);
#endif
	return 0;
}

void get_cmdline_by_pid(struct procinfo *pi)
{
	char cmd_path[128];
	char cmd[256];
	char resolved[256];

	FILE *fp;

	memset(cmd_path, 0, 128);
	memset(cmd, 0, 256);
	sprintf(cmd_path, "/proc/%d/cmdline", pi->pi_pid);
	fp = fopen(cmd_path, "r");
	fgets(cmd, 256, fp);

	/*resolve all symlinks */
	check_target_path((u_char *) cmd, pi->pi_perm);
	memset(cmd, 0, 256);
	memcpy(cmd, pi->pi_perm->p_full_path,
	       strlen((const char *)pi->pi_perm->p_full_path));

	strcpy((char *)pi->pi_perm->p_full_path, realpath(cmd, resolved));
#if 0
	printfd(2, DEBUG "cmdline path : %s\n", cmd_path);
	printfd(2, DEBUG "cmd is : %s\n", pi->pi_perm->p_full_path);
#endif
}


int attach_process(struct procinfo *pi)
{
	int ret;

	ret = ptrace(PTRACE_ATTACH, pi->pi_pid, 0, 0);
	if (ret == -1)
		return ret;
	waitpid(pi->pi_pid, 0, 0);
	return ret;
}
