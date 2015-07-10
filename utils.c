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

void *xmalloc(int bytes)
{
	void *tmp = malloc(bytes);
	if (!tmp) {
		fprintf(stderr, "Line : %d , malloc\n", __LINE__);
		return NULL;
	}
	memset(tmp, 0, bytes);
	return tmp;
}

int printfd(int fd, const char *fmt, ...)
{

	char data[BT_MAX_DATA_LEN];
	int len;
	va_list ap;
	int wr;
	va_start(ap, fmt);
	len = vsnprintf(data, BT_MAX_DATA_LEN, fmt, ap);
	va_end(ap);
	wr = write(fd, data, len);
	return wr;
}

char *ascii(char *position, int c)
{

	if (!isprint(c))
		c = '.';
	sprintf(position, "%c", c);
	return (++position);
}

char *hex(char *position, int c)
{
	int offset = 3;
	sprintf(position, "%02x ", (unsigned char)c);
	*(position + offset) = ' ';

	return (position + offset);
}

void dump_using_memory(struct procinfo *pi,int stack_dbg)
{
	int c = ' ';
	char *hex_offset;
	int i;
	vaddr_t counter;
	char *ascii_offset;
	char line[81];
	struct map_addr *ma_ptr,*ma_tmp;

	i = 0;

	if(stack_dbg == DEBUG_STACK)
		ma_tmp = pi->pi_stack;
	else
		ma_tmp = pi->pi_addr;
	

	for (ma_ptr = ma_tmp; ma_ptr; ma_ptr = ma_ptr->ma_next) {
		//printfd(2,DEBUG"mapping : 0x%.08x\n",ma_ptr->ma_map[0]);
		i = 0;

		counter = ma_ptr->ma_map[0];
		
		while (i < pi->pi_offset) {
			memset(line, 0x20, 81);
			hex_offset = line + HEX_OFFSET;
			ascii_offset = line + ASCII_OFFSET;
			printf(GREEN "" SHOW_ADDR "" NORM " : ", counter);
			counter += 16;
			
			while (ascii_offset < line + ASCII_OFFSET + NUM_CHARS
			       && i < pi->pi_offset) {
				//printf("DDDDDD\n");
				c = ma_ptr->ma_data[i++];
				hex_offset = hex(hex_offset, c);
				ascii_offset = ascii(ascii_offset, c);

			}

			printf("%s\n", line);
		}
	}
}

void raw_dump(struct procinfo *pi)
{
	int left, written;
	u_char *ptr;
	struct map_addr *ma_ptr;

	for (ma_ptr = pi->pi_addr; ma_ptr; ma_ptr = ma_ptr->ma_next) {
		ptr = ma_ptr->ma_data;
		left = pi->pi_offset;
		while (left > 0) {
			written = write(1, ptr, left);
			left -= written;
			ptr += written;
		}
	}
}

void die(const char *msg)
{
	perror(msg);
	exit(errno);
}

void reverse_ll(struct map_addr **maddr)
{
	struct map_addr *prev = NULL;
	struct map_addr *current = *maddr;
	struct map_addr *next;
	while (current != NULL) {
		next = current->ma_next;
		current->ma_next = prev;
		prev = current;
		current = next;
	}
	*maddr = prev;
}
