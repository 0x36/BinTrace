BinTrace
==========
BinTrace is a an open source tool that helps to dump a running process or an executable.
I've found it in a dying directory and decided to make it public
Bellow some tips about how to use it 

Compilation
-----------

cd BinTrace
make
./btrace

Features
----------
	Attach to a process
	Execute a binary with its arguments
	Process sections dump (.text,.bss,.data)
	Stack dump
	Full dump of a process
	Dump a range of blocks using --address and --offset
	Hex/Raw dump

Usage
----------
	full Dump:
		./btrace -p 4016
		./btrace -t /bin/bash -A "-c ls"
	Partial Dump:
		./btrace -p  4016 -a 0x6f3670 -o 10
		
	Full dump Raw
		./btrace -p  4016 -a 0x6f3670 -o 10 -d raw
	
	Dump the stack:
		./btrace -p  4016  -s
	
