CC=gcc
BIN=btrace

SRC=$(wildcard *.c)
OBJ=$(SRC:.c=.o)
DEP=MF.dep

all: $(DEP) $(BIN)

$(DEP):$(SRC)
	$(CC) -MM $^ > $@

$(BIN):$(OBJ)
	$(CC)  -o $@ $^

%.o:%.c
	$(CC) -c $<

clean_obj:
	rm -rf $(OBJ)

clean: clean_obj
	rm -rf *~
	rm -rf $(BIN)

ifdef ($(wildcard Makefile.dep,))
include $(DEP)
endif
