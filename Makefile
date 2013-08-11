CC=gcc
BIN=btrace

SRC=$(wildcard *.c)
OBJ=$(SRC:.c=.o)
DEP=MF.dep
CFLAGS=-ggdb -Wall
all: $(DEP) $(BIN)

$(DEP):$(SRC)
	$(CC) -MM $^ > $@

$(BIN):$(OBJ)
	$(CC)  -o $@ $^ $(CFLAGS)

%.o:%.c
	$(CC) -c $< $(CFLAGS)

clean_obj:
	rm -rf $(OBJ)

clean: clean_obj
	rm -rf *~
	rm -rf $(BIN)

ifdef ($(wildcard Makefile.dep,))
include $(DEP)
endif
